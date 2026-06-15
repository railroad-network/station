//! OR-Set (Observed-Remove Set) CRDT.
//!
//! Used for community membership and marketplace listings (Phase 1); included
//! now to validate the CRDT layer. The defining property: a remove only cancels
//! the *adds it observed*, so a remove concurrent with a fresh add leaves the
//! element present — **add wins on concurrency**.
//!
//! Each `add` tags the element with a fresh random [`UniqueTag`]; `remove`
//! records the tags currently observed for the element. An element is present if
//! it carries at least one tag that has not been removed. Merge is the union of
//! the add-tags and the union of the removed-tags — commutative, associative,
//! and idempotent.
//!
//! Tombstones (removed tags) accumulate and are never garbage-collected in
//! Phase 0; sets are small and this is a documented, deferred concern.

use std::collections::{BTreeMap, BTreeSet};

use dcbor::prelude::*;
use rand_core::{OsRng, RngCore};
use rusqlite::OptionalExtension;

use crate::db::Database;
use crate::{Error, Result};

/// A random 128-bit tag distinguishing one `add` of an element from another.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UniqueTag([u8; 16]);

impl UniqueTag {
    /// Draws a fresh tag from the OS CSPRNG.
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Constructs a tag from raw bytes — for reconstructing a tag observed on a
    /// remote replica, and for deterministic tests.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The 16 raw bytes of this tag.
    pub fn to_bytes(&self) -> [u8; 16] {
        self.0
    }
}

/// An Observed-Remove Set of `T`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrSet<T>
where
    T: Ord + Clone,
{
    /// Per-element set of add-tags ever observed.
    adds: BTreeMap<T, BTreeSet<UniqueTag>>,
    /// Tags that have been removed (tombstones).
    removes: BTreeSet<UniqueTag>,
}

impl<T: Ord + Clone> Default for OrSet<T> {
    fn default() -> Self {
        Self {
            adds: BTreeMap::new(),
            removes: BTreeSet::new(),
        }
    }
}

impl<T: Ord + Clone> OrSet<T> {
    /// Creates an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `element`, tagging this observation with a fresh unique tag. Adding
    /// an element already present simply records another tag.
    pub fn add(&mut self, element: T) {
        self.add_with_tag(element, UniqueTag::random());
    }

    /// Adds `element` with a caller-supplied tag. Used when applying a remote
    /// replica's add (which carries its own tag) and for deterministic tests;
    /// ordinary local adds use [`add`](Self::add), which generates a fresh tag.
    pub fn add_with_tag(&mut self, element: T, tag: UniqueTag) {
        self.adds.entry(element).or_default().insert(tag);
    }

    /// Removes `element` by tombstoning every tag currently observed for it. A
    /// concurrent add (a tag this replica has not seen) survives the merge.
    pub fn remove(&mut self, element: &T) {
        if let Some(tags) = self.adds.get(element) {
            self.removes.extend(tags.iter().copied());
        }
    }

    /// Whether `element` is present: it has at least one non-removed tag.
    pub fn contains(&self, element: &T) -> bool {
        self.adds
            .get(element)
            .is_some_and(|tags| tags.iter().any(|t| !self.removes.contains(t)))
    }

    /// Iterates the elements currently present, in `T`'s order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.adds.iter().filter_map(|(element, tags)| {
            tags.iter()
                .any(|t| !self.removes.contains(t))
                .then_some(element)
        })
    }

    /// Merges `other` into `self`: union the add-tags per element, union the
    /// tombstones. Idempotent, commutative, associative.
    pub fn merge(&mut self, other: &Self) {
        for (element, tags) in &other.adds {
            self.adds
                .entry(element.clone())
                .or_default()
                .extend(tags.iter().copied());
        }
        self.removes.extend(other.removes.iter().copied());
    }
}

// --- Persistence (canonical CBOR blob in the `kv` table) -------------------

impl<T> OrSet<T>
where
    T: Ord + Clone + Into<CBOR>,
{
    /// Serializes the whole set to a canonical-CBOR blob in `kv` under `name`.
    pub fn save(&self, db: &Database, name: &str) -> Result<()> {
        db.conn().execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![name, self.to_cbor().to_cbor_data()],
        )?;
        Ok(())
    }

    /// Encodes as `{ "adds": { element: [tag,...] }, "removes": [tag,...] }`.
    fn to_cbor(&self) -> CBOR {
        let mut adds = Map::new();
        for (element, tags) in &self.adds {
            adds.insert(element.clone(), tag_array(tags));
        }
        let mut top = Map::new();
        top.insert("adds", adds);
        top.insert("removes", tag_array(&self.removes));
        top.into()
    }
}

impl<T> OrSet<T>
where
    T: Ord + Clone + TryFrom<CBOR>,
{
    /// Loads the set stored under `name`, or an empty set if absent.
    pub fn load(db: &Database, name: &str) -> Result<Self> {
        let row: Option<Vec<u8>> = db
            .conn()
            .query_row("SELECT value FROM kv WHERE key = ?1", [name], |r| r.get(0))
            .optional()?;
        match row {
            Some(bytes) => {
                let cbor = CBOR::try_from_data(&bytes)
                    .map_err(|e| Error::Corrupt(format!("or-set cbor: {e}")))?;
                Self::from_cbor(cbor)
            }
            None => Ok(Self::new()),
        }
    }

    fn from_cbor(cbor: CBOR) -> Result<Self> {
        let top = expect_map(cbor)?;
        let adds_cbor = top
            .get::<_, CBOR>("adds")
            .ok_or_else(|| Error::Corrupt("or-set: missing 'adds'".into()))?;
        let removes_cbor = top
            .get::<_, CBOR>("removes")
            .ok_or_else(|| Error::Corrupt("or-set: missing 'removes'".into()))?;

        let mut adds = BTreeMap::new();
        for (key, value) in expect_map(adds_cbor)?.iter() {
            let element = T::try_from(key.clone())
                .map_err(|_| Error::Corrupt("or-set: undecodable element".into()))?;
            adds.insert(element, tag_set(value.clone())?);
        }
        Ok(Self {
            adds,
            removes: tag_set(removes_cbor)?,
        })
    }
}

/// Encodes a set of tags as a CBOR array of 16-byte byte strings.
fn tag_array(tags: &BTreeSet<UniqueTag>) -> Vec<CBOR> {
    tags.iter()
        .map(|t| ByteString::from(t.0.to_vec()).into())
        .collect()
}

/// Decodes a CBOR array of byte strings back into a tag set.
fn tag_set(cbor: CBOR) -> Result<BTreeSet<UniqueTag>> {
    let array = match cbor.into_case() {
        CBORCase::Array(items) => items,
        _ => return Err(Error::Corrupt("or-set: expected tag array".into())),
    };
    let mut set = BTreeSet::new();
    for item in array {
        let bytes: Vec<u8> = ByteString::try_from(item)
            .map_err(|e| Error::Corrupt(format!("or-set tag: {e}")))?
            .into();
        let tag: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Error::Corrupt("or-set: tag not 16 bytes".into()))?;
        set.insert(UniqueTag(tag));
    }
    Ok(set)
}

fn expect_map(cbor: CBOR) -> Result<Map> {
    match cbor.into_case() {
        CBORCase::Map(map) => Ok(map),
        _ => Err(Error::Corrupt("or-set: expected map".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Deterministic tag from a counter — keeps tests reproducible (no OsRng).
    fn tag(n: u8) -> UniqueTag {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        UniqueTag(bytes)
    }

    #[test]
    fn add_then_remove_is_absent() {
        let mut s = OrSet::new();
        s.add("x");
        s.remove(&"x");
        assert!(!s.contains(&"x"));
        assert_eq!(s.iter().count(), 0);
    }

    #[test]
    fn concurrent_add_wins_over_remove() {
        // Shared history: both replicas observed x added with tag 1.
        let mut a = OrSet::new();
        a.add_with_tag("x", tag(1));
        let mut b = a.clone();

        // Concurrently: A adds x again (tag 2, which B never sees); B removes x,
        // observing only tag 1.
        a.add_with_tag("x", tag(2));
        b.remove(&"x");

        // After merge, tag 2 survives → x is present (add wins).
        let mut merged = a.clone();
        merged.merge(&b);
        assert!(merged.contains(&"x"));
    }

    #[test]
    fn fully_observed_remove_stays_absent_after_merge() {
        // If the remover observed every add, the element is gone after merge.
        let mut a = OrSet::new();
        a.add_with_tag("x", tag(1));
        let mut b = a.clone();
        b.remove(&"x");
        a.merge(&b);
        assert!(!a.contains(&"x"));
    }

    #[test]
    fn persistence_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        crate::migrations::run(&db).unwrap();

        let mut s: OrSet<String> = OrSet::new();
        s.add_with_tag("alice".into(), tag(1));
        s.add_with_tag("bob".into(), tag(2));
        s.add_with_tag("alice".into(), tag(3));
        s.remove(&"bob".to_string());

        s.save(&db, "members").unwrap();
        let loaded = OrSet::<String>::load(&db, "members").unwrap();
        assert_eq!(loaded, s);
        assert!(loaded.contains(&"alice".to_string()));
        assert!(!loaded.contains(&"bob".to_string()));
    }

    #[test]
    fn load_absent_is_empty() {
        let db = Database::open_in_memory().unwrap();
        crate::migrations::run(&db).unwrap();
        let loaded = OrSet::<String>::load(&db, "nope").unwrap();
        assert_eq!(loaded, OrSet::new());
    }

    // --- Merge laws over arbitrary operation sequences ---------------------

    /// `(element 0..4, is_add, tag byte)`. A remove targets the element; the tag
    /// byte only matters for adds.
    type Op = (u8, bool, u8);

    fn apply(ops: &[Op]) -> OrSet<u8> {
        let mut s = OrSet::new();
        for &(element, is_add, t) in ops {
            let element = element % 5;
            if is_add {
                s.add_with_tag(element, tag(t));
            } else {
                s.remove(&element);
            }
        }
        s
    }

    fn ops_strategy() -> impl Strategy<Value = Vec<Op>> {
        prop::collection::vec((0u8..5, any::<bool>(), any::<u8>()), 0..20)
    }

    proptest! {
        #[test]
        fn merge_commutative(a in ops_strategy(), b in ops_strategy()) {
            let (sa, sb) = (apply(&a), apply(&b));
            let mut ab = sa.clone(); ab.merge(&sb);
            let mut ba = sb.clone(); ba.merge(&sa);
            prop_assert_eq!(ab, ba);
        }

        #[test]
        fn merge_associative(a in ops_strategy(), b in ops_strategy(), c in ops_strategy()) {
            let (sa, sb, sc) = (apply(&a), apply(&b), apply(&c));
            let mut left = sa.clone(); left.merge(&sb); left.merge(&sc);
            let mut bc = sb.clone(); bc.merge(&sc);
            let mut right = sa.clone(); right.merge(&bc);
            prop_assert_eq!(left, right);
        }

        #[test]
        fn merge_idempotent(a in ops_strategy()) {
            let sa = apply(&a);
            let mut merged = sa.clone(); merged.merge(&sa.clone());
            prop_assert_eq!(merged, sa);
        }
    }
}
