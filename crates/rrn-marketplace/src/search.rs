//! Search — discovery over the set of active listings.
//!
//! Two derived stores back a query, and neither is authoritative over anything
//! (ADR-0010):
//!
//! - the **`listings_index` table**, which answers the structured filters
//!   (surface, category, price, expiry) and carries each listing's bytes so a
//!   result set does not send the caller back to the log;
//! - a **tantivy index** over `title + description + category`, which answers
//!   "what is this text about".
//!
//! Both are rebuilt from a full replay by [`SearchIndex::rebuild`]. Deleting the
//! tantivy directory is always a safe repair.
//!
//! # The drift the ADR accepted
//!
//! Tantivy lives outside the SQLite transaction that writes the log, so the two
//! *can* diverge — the cost ADR-0010 took on knowingly when it chose tantivy
//! over FTS5. Nothing here pretends otherwise. What keeps it honest is that a
//! rebuild is always available and must produce identical results to the
//! incrementally-maintained index, which is pinned by a test.
//!
//! # Ranking
//!
//! Text relevance from tantivy, **multiplied** by a provider-reputation factor,
//! so standing lifts strong providers and breaks ties without letting a high
//! score surface an irrelevant listing. A query with no text scores every
//! candidate's relevance as `1.0`, which leaves reputation ordering the results.
//!
//! Reputation is read from the M1.5 snapshot cache and **never** recomputed per
//! result: scoring is O(N) in the log and anchoring made it O(V·N), so a page of
//! fifty results must not become fifty replays on the station's single writer
//! thread. A provider with no cached snapshot ranks as `0.0` rather than
//! triggering one.

use std::collections::HashMap;
use std::path::Path;

use rrn_crypto::keypair::PublicKey;
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_identity::address::Address;
use rrn_reputation::snapshot::get_cached_profile;
use rrn_storage::db::Database;
use rrn_storage::listings_index as store;
use rrn_storage::log::AppendLog;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Field, Schema, Value, STORED, STRING, TEXT};
use tantivy::{doc, Index, IndexWriter, TantivyDocument, Term};

use crate::lifecycle::{compute_all, ListingState};
use crate::listing::{Listing, ListingId, Surface};
use crate::{Error, Result};

/// How stale a cached reputation snapshot may be before ranking treats the
/// provider as unscored.
///
/// A day: the station refreshes snapshots hourly (T1.5.5), so this tolerates a
/// long outage of that sweep without ever falling back to a live replay. Ranking
/// is a presentation decision, and a slightly stale score is a far smaller
/// problem than a search that replays the log.
pub const MAX_SNAPSHOT_AGE_SECS: i64 = 86_400;

/// Tantivy's writer heap. The minimum it accepts is 15 MB; Phase 1 corpora are
/// thousands of listings, so there is nothing to gain from more.
const INDEX_WRITER_HEAP_BYTES: usize = 15_000_000;

/// How much reputation can lift a result: the multiplier is `1.0 + composite`,
/// so an unscored provider's listing keeps its plain relevance and the best
/// standing reachable in Phase 1 (composite 3.50) lifts it 4.5×. Multiplying
/// rather than adding is what keeps a strong provider from surfacing an
/// irrelevant listing — anything times a near-zero relevance stays near zero.
fn reputation_multiplier(composite: f32) -> f32 {
    1.0 + composite.max(0.0)
}

/// How many results a [`SearchQuery::default`] asks for. A derived `Default`
/// would set `limit: 0`, which silently returns nothing — a page size is a
/// thing to state, not to leave at the type's zero value.
pub const DEFAULT_LIMIT: usize = 50;

/// What a caller is looking for. Every filter is optional; `None` does not
/// narrow.
#[derive(Clone, Debug)]
pub struct SearchQuery {
    /// Free text matched against title, description, and category.
    pub text: Option<String>,
    /// Restrict to one surface.
    pub surface: Option<Surface>,
    /// Restrict to one category.
    pub category: Option<String>,
    /// Cap the price in centi-Commons.
    pub max_price_centi: Option<i64>,
    /// Require the provider's *current* composite reputation to be at least
    /// this. Current standing, not `reputation_at_creation`, because a filter
    /// asking "who is trustworthy now" must not be answered with history.
    pub min_provider_reputation: Option<f32>,
    /// Maximum results to return.
    pub limit: usize,
    /// How many leading results to skip.
    pub offset: usize,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            text: None,
            surface: None,
            category: None,
            max_price_centi: None,
            min_provider_reputation: None,
            limit: DEFAULT_LIMIT,
            offset: 0,
        }
    }
}

/// A ranked hit.
#[derive(Clone, Debug, PartialEq)]
pub struct SearchHit {
    /// The listing.
    pub listing: Listing,
    /// Its final score: text relevance times the provider's reputation factor.
    pub score: f32,
    /// The provider's current composite reputation, as ranking saw it.
    pub provider_reputation: f32,
}

/// The full-text half of the index, plus the operations that keep both halves
/// in step.
///
/// Holds the tantivy index; the SQLite half is reached through `db` on each
/// call, so this struct owns no database handle.
pub struct SearchIndex {
    index: Index,
    listing_id: Field,
    title: Field,
    description: Field,
    category: Field,
}

impl SearchIndex {
    /// Opens (or creates) the persistent index under `dir`, the
    /// `<data_dir>/marketplace_index/` of the deployment.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| Error::Index(e.to_string()))?;
        let directory = tantivy::directory::MmapDirectory::open(dir)
            .map_err(|e| Error::Index(e.to_string()))?;
        let index = Index::open_or_create(directory, Self::schema())?;
        Ok(Self::from_index(index))
    }

    /// An index held entirely in memory — for tests, and for a station that
    /// wants to rebuild into a scratch index before swapping it in.
    pub fn in_memory() -> Self {
        Self::from_index(Index::create_in_ram(Self::schema()))
    }

    /// The tantivy schema: the id is stored and indexed verbatim so a document
    /// can be replaced by term, and the three text fields are tokenized.
    /// `title`, `description`, and `category` are searched; nothing else needs
    /// to come back out of tantivy, because the listing's bytes live in SQLite.
    fn schema() -> Schema {
        let mut builder = Schema::builder();
        builder.add_text_field("listing_id", STRING | STORED);
        builder.add_text_field("title", TEXT);
        builder.add_text_field("description", TEXT);
        builder.add_text_field("category", TEXT);
        builder.build()
    }

    fn from_index(index: Index) -> Self {
        let schema = index.schema();
        let field = |name: &str| schema.get_field(name).expect("field defined in schema()");
        Self {
            listing_id: field("listing_id"),
            title: field("title"),
            description: field("description"),
            category: field("category"),
            index,
        }
    }

    /// Rebuilds both halves of the index from a full replay of the log.
    ///
    /// The repair path, and the only way a new station catches up. Every row and
    /// document is discarded first, so the result depends on the log alone and
    /// not on whatever the index happened to hold — which is what lets a rebuild
    /// be compared against incremental maintenance and be expected to match.
    ///
    /// Returns how many listings were indexed.
    pub fn rebuild(
        &self,
        db: &Database,
        log: &AppendLog,
        station: &PublicKey,
        now: i64,
    ) -> Result<usize> {
        store::clear(db)?;
        let mut writer: IndexWriter = self.index.writer(INDEX_WRITER_HEAP_BYTES)?;
        writer.delete_all_documents()?;

        let states = compute_all(log, station, now)?;
        for state in states.values() {
            if let Some(listing) = state.listing() {
                self.write_listing(db, &mut writer, listing, state)?;
            }
        }
        writer.commit()?;
        Ok(states.len())
    }

    /// Puts one listing into both halves, replacing whatever was there.
    ///
    /// The incremental path, for a station applying newly-appended records
    /// rather than replaying everything.
    pub fn upsert(&self, db: &Database, listing: &Listing, state: &ListingState) -> Result<()> {
        let mut writer: IndexWriter = self.index.writer(INDEX_WRITER_HEAP_BYTES)?;
        self.write_listing(db, &mut writer, listing, state)?;
        writer.commit()?;
        Ok(())
    }

    /// Drops one listing from both halves.
    pub fn remove(&self, db: &Database, listing_id: &ListingId) -> Result<()> {
        store::remove(db, &listing_id.to_bytes())?;
        let mut writer: IndexWriter = self.index.writer(INDEX_WRITER_HEAP_BYTES)?;
        writer.delete_term(self.id_term(listing_id));
        writer.commit()?;
        Ok(())
    }

    /// Writes one listing's row and document. The caller commits.
    fn write_listing(
        &self,
        db: &Database,
        writer: &mut IndexWriter,
        listing: &Listing,
        state: &ListingState,
    ) -> Result<()> {
        let status = match state {
            // An expired listing is not closed on the log yet, so the row keeps
            // saying `active` and the query's `expires_at` test hides it. See
            // the migration: baking expiry into a row would make the row wrong
            // as soon as the clock moved.
            ListingState::Active(_) | ListingState::Expired { .. } | ListingState::Draft => {
                store::STATUS_ACTIVE
            }
            ListingState::Closed { .. } => store::STATUS_CLOSED,
        };
        store::put(
            db,
            &store::IndexedListing {
                listing_id: listing.id.to_bytes(),
                provider: listing.provider.public_key().to_bytes(),
                surface: listing.surface.tag().to_string(),
                category: listing.category.clone(),
                status: status.to_string(),
                price_centi: listing.pricing.amount_centi,
                reputation_at_creation: reputation_at(db, &listing.provider, listing.created_at),
                created_at: listing.created_at,
                expires_at: listing.expires_at,
                listing_cbor: to_canonical_bytes(listing.clone()),
            },
        )?;

        // Replace rather than add: tantivy has no primary key, so an upsert is
        // a delete by term followed by an add, and skipping the delete would
        // leave the old document matching alongside the new one.
        writer.delete_term(self.id_term(&listing.id));
        writer.add_document(doc!(
            self.listing_id => id_text(&listing.id),
            self.title => listing.title.clone(),
            self.description => listing.description.clone(),
            self.category => listing.category.clone(),
        ))?;
        Ok(())
    }

    fn id_term(&self, listing_id: &ListingId) -> Term {
        Term::from_field_text(self.listing_id, &id_text(listing_id))
    }

    /// Runs a query and returns hits, best first.
    ///
    /// Structured filters run in SQLite first, so text relevance is only ever
    /// computed for listings that could be returned. Ties are broken by listing
    /// id — a content address — so the order is total and identical on every
    /// station, which is what makes a rebuild comparable to incremental
    /// maintenance at all.
    pub fn search(&self, db: &Database, query: &SearchQuery, now: i64) -> Result<Vec<SearchHit>> {
        let candidates = store::active_matching(
            db,
            &store::IndexFilter {
                surface: query.surface.map(|s| s.tag().to_string()),
                category: query.category.clone(),
                max_price_centi: query.max_price_centi,
            },
            now,
        )?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let relevance = self.relevance(query, candidates.len())?;
        let mut reputations: HashMap<Address, f32> = HashMap::new();
        let mut hits = Vec::new();

        for row in &candidates {
            // Both cheap rejections happen before the listing's CBOR is decoded:
            // a row the text query missed, and a provider under the reputation
            // floor, cost nothing but a map lookup.
            let id = ListingId(rrn_crypto::hash::Hash::from_bytes(row.listing_id));
            let text_score = match &relevance {
                // A text query this listing did not match at all.
                Some(scores) => match scores.get(&id) {
                    Some(&score) => score,
                    None => continue,
                },
                // No text query: every candidate is equally relevant, so
                // reputation alone orders the results.
                None => 1.0,
            };

            // One snapshot read per provider, not per listing: a page of results
            // from one prolific provider must not be a page of lookups.
            let provider = PublicKey::from_bytes(row.provider)
                .map(Address::from_public_key)
                .map_err(|e| Error::Index(format!("corrupt indexed provider key: {e}")))?;
            let composite = match reputations.get(&provider) {
                Some(&cached) => cached,
                None => {
                    let value = reputation_now(db, &provider);
                    reputations.insert(provider, value);
                    value
                }
            };
            if query
                .min_provider_reputation
                .is_some_and(|floor| composite < floor)
            {
                continue;
            }

            let listing = decode_indexed(row)?;
            hits.push(SearchHit {
                score: text_score * reputation_multiplier(composite),
                provider_reputation: composite,
                listing,
            });
        }

        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.listing.id.cmp(&b.listing.id))
        });
        Ok(hits
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect())
    }

    /// Text relevance per listing, or `None` when the query has no text and
    /// every candidate is equally relevant.
    fn relevance(
        &self,
        query: &SearchQuery,
        candidate_count: usize,
    ) -> Result<Option<HashMap<ListingId, f32>>> {
        let Some(text) = query
            .text
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        else {
            return Ok(None);
        };
        // `Manual` plus an explicit reload, not the default `OnCommitWithDelay`:
        // that policy picks up a commit "within milliseconds", which makes a
        // search immediately after an index write a race. A caller that just
        // wrote a listing must be able to find it, and the rebuild-equivalence
        // property is not testable against a reader that may or may not have
        // caught up yet.
        let reader = self
            .index
            .reader_builder()
            .reload_policy(tantivy::ReloadPolicy::Manual)
            .try_into()?;
        reader.reload()?;
        let searcher = reader.searcher();
        let parser = QueryParser::for_index(
            &self.index,
            vec![self.title, self.description, self.category],
        );
        let parsed = parser
            .parse_query(text)
            .map_err(|e| Error::Index(format!("bad query {text:?}: {e}")))?;

        // Ask for every candidate: the filters have already bounded the set, and
        // limit/offset are applied after reputation has had its say, so cutting
        // the list here would drop listings that ranking would have promoted.
        let top = searcher.search(
            &parsed,
            &TopDocs::with_limit(candidate_count.max(1)).order_by_score(),
        )?;

        let mut scores = HashMap::new();
        for (score, address) in top {
            let document: TantivyDocument = searcher.doc(address)?;
            let Some(id) = document
                .get_first(self.listing_id)
                .and_then(|value| value.as_str())
                .and_then(id_from_text)
            else {
                continue;
            };
            scores.insert(id, score);
        }
        Ok(Some(scores))
    }
}

/// Decodes an indexed row back into a listing, taking the id from the **row**
/// rather than from the decoded bytes.
///
/// This is not belt-and-braces, it is required. `Listing`'s CBOR decode
/// recomputes `id` as the hash of the content it just read, which is right for a
/// `listing.v1` record on the log. But an *updated* listing keeps the id it was
/// published under while its content moves on
/// ([`ListingPatch::apply_to`](crate::lifecycle::ListingPatch::apply_to)) — it is
/// the one `Listing` whose id is deliberately not the hash of its fields. Trust
/// the decoded id and every patched listing would come back under an id nothing
/// else knows it by, silently detaching it from its own history.
///
/// The row's primary key is the identity that was written; it wins.
fn decode_indexed(row: &store::IndexedListing) -> Result<Listing> {
    let mut listing = from_canonical_bytes::<Listing>(&row.listing_cbor)
        .map_err(|e| Error::Index(format!("corrupt indexed listing: {e}")))?;
    listing.id = ListingId(rrn_crypto::hash::Hash::from_bytes(row.listing_id));
    Ok(listing)
}

/// A listing id as the exact-match string tantivy stores.
fn id_text(listing_id: &ListingId) -> String {
    listing_id
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn id_from_text(text: &str) -> Option<ListingId> {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Some(ListingId(rrn_crypto::hash::Hash::from_bytes(bytes)))
}

/// The provider's current composite, from the snapshot cache only.
///
/// A miss reads `0.0`. Recomputing here would replay the log inside a search,
/// which is exactly what the snapshot cache exists to prevent; an unscored
/// provider is ranked as unscored, and the hourly sweep fixes it.
fn reputation_now(db: &Database, provider: &Address) -> f32 {
    match get_cached_profile(db, provider, MAX_SNAPSHOT_AGE_SECS) {
        Ok(Some(profile)) => profile.composite(),
        Ok(None) => 0.0,
        Err(e) => {
            tracing::warn!(
                provider = %provider,
                error = %e,
                "reputation snapshot unreadable; ranking as unscored"
            );
            0.0
        }
    }
}

/// The provider's composite as of `at_time` — a historical fact, recorded once
/// when the listing is indexed.
///
/// This one *does* replay, because "what was this provider worth when they
/// published" is not something a snapshot of the present can answer. It is paid
/// on indexing, never on search, and a failure records `0.0` rather than failing
/// the index write: the value is for audit and tie-stability, and no read path
/// gates on it.
fn reputation_at(db: &Database, provider: &Address, at_time: i64) -> f32 {
    match rrn_reputation::scoring::ReputationScorer::new(db).score_at(provider, at_time) {
        Ok(profile) => profile.composite(),
        Err(e) => {
            tracing::warn!(
                provider = %provider,
                error = %e,
                "could not score provider at listing creation"
            );
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{
        append_listing_closed, append_listing_created, append_listing_updated, compute_state,
        CloseReason, ListingClosed, ListingPatch, ListingUpdated,
    };
    use crate::listing::{Availability, AvailabilityStatus, Pricing, PricingModel, Requirements};
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_reputation::model::ReputationProfile;
    use rrn_storage::migrations;

    const CREATED_AT: i64 = 1_800_000_000;
    const EXPIRES_AT: i64 = 1_900_000_000;
    const NOW: i64 = 1_850_000_000;

    fn open_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    /// A listing with the text and shape a test needs; everything else is a
    /// fixed, valid default.
    #[allow(clippy::too_many_arguments)]
    fn listing(
        provider: &Keypair,
        surface: Surface,
        category: &str,
        title: &str,
        description: &str,
        price_centi: i64,
    ) -> Listing {
        Listing::new(
            Address::from_public_key(provider.public_key()),
            "blue_ridge_collective".into(),
            surface,
            category.into(),
            title.into(),
            description.into(),
            Pricing {
                amount_centi: price_centi,
                model: PricingModel::Fixed,
                negotiable: false,
            },
            Availability {
                status: AvailabilityStatus::Available,
                capacity: Some(12),
                next_slot: None,
            },
            Requirements {
                min_reputation: 0.0,
                community_member_only: false,
                federation_only: false,
            },
            1,
            false,
            CREATED_AT,
            Some(EXPIRES_AT),
        )
        .unwrap()
    }

    /// Publishes a listing and puts it into the index incrementally.
    fn publish(
        index: &SearchIndex,
        db: &Database,
        log: &mut AppendLog,
        station: &PublicKey,
        provider: &Keypair,
        listing: &Listing,
    ) {
        append_listing_created(log, SignedPayload::sign(listing.clone(), provider), NOW).unwrap();
        let state = compute_state(log, &listing.id, station, NOW)
            .unwrap()
            .unwrap();
        index.upsert(db, listing, &state).unwrap();
    }

    /// Stores a reputation snapshot with the given composite. `composite` is
    /// `0.30 * trade_reliability`, so this drives the one dimension that has a
    /// Phase-1 data source and leaves the rest dormant.
    fn give_reputation(db: &Database, provider: &Keypair, composite: f32) {
        let address = Address::from_public_key(provider.public_key());
        let mut profile = ReputationProfile::empty(address);
        profile.trade_reliability = composite / 0.30;
        profile.last_updated = NOW;
        // Freshness is judged against the wall clock, so the snapshot is stamped
        // with real time; the scored values themselves stay fixed.
        let wall_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        rrn_storage::reputation_snapshot::put(
            db,
            &address.public_key().to_bytes(),
            wall_now,
            &to_canonical_bytes(profile),
        )
        .unwrap();
    }

    fn titles(hits: &[SearchHit]) -> Vec<String> {
        hits.iter().map(|h| h.listing.title.clone()).collect()
    }

    #[test]
    fn text_search_finds_the_listings_that_mention_the_words() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let squash = listing(
            &alice,
            Surface::Goods,
            "food",
            "Winter squash by the crate",
            "Picked this week, stores until spring.",
            250,
        );
        let hammer = listing(
            &bob,
            Surface::Goods,
            "tools",
            "Claw hammer",
            "Forged head, hickory handle.",
            900,
        );
        publish(&index, &db, &mut log, &station, &alice, &squash);
        publish(&index, &db, &mut log, &station, &bob, &hammer);

        let hits = index
            .search(
                &db,
                &SearchQuery {
                    text: Some("squash".into()),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(titles(&hits), vec!["Winter squash by the crate"]);

        // The description and the category are searched too, not just the title.
        let hits = index
            .search(
                &db,
                &SearchQuery {
                    text: Some("hickory".into()),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(titles(&hits), vec!["Claw hammer"]);

        let hits = index
            .search(
                &db,
                &SearchQuery {
                    text: Some("tools".into()),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(titles(&hits), vec!["Claw hammer"]);

        // A word nobody used returns nothing rather than everything.
        let hits = index
            .search(
                &db,
                &SearchQuery {
                    text: Some("bicycle".into()),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn filters_narrow_by_surface_category_and_price() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let providers: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();

        let cheap_food = listing(
            &providers[0],
            Surface::Goods,
            "food",
            "Squash",
            "Crate.",
            100,
        );
        let dear_food = listing(&providers[1], Surface::Goods, "food", "Honey", "Jar.", 900);
        let a_service = listing(
            &providers[2],
            Surface::Services,
            "construction",
            "Roofing",
            "Half a day.",
            500,
        );
        publish(&index, &db, &mut log, &station, &providers[0], &cheap_food);
        publish(&index, &db, &mut log, &station, &providers[1], &dear_food);
        publish(&index, &db, &mut log, &station, &providers[2], &a_service);

        let all = index.search(&db, &SearchQuery::default(), NOW).unwrap();
        assert_eq!(all.len(), 3);

        let goods = index
            .search(
                &db,
                &SearchQuery {
                    surface: Some(Surface::Goods),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(goods.len(), 2);

        let construction = index
            .search(
                &db,
                &SearchQuery {
                    category: Some("construction".into()),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(titles(&construction), vec!["Roofing"]);

        let affordable = index
            .search(
                &db,
                &SearchQuery {
                    max_price_centi: Some(500),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(affordable.len(), 2);

        // Filters compose.
        let both = index
            .search(
                &db,
                &SearchQuery {
                    surface: Some(Surface::Goods),
                    max_price_centi: Some(500),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(titles(&both), vec!["Squash"]);
    }

    #[test]
    fn reputation_breaks_a_relevance_tie() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let humble = Keypair::generate();
        let esteemed = Keypair::generate();

        // Identical text, so tantivy scores them the same and only standing can
        // separate them.
        let theirs = listing(
            &humble,
            Surface::Goods,
            "food",
            "Winter squash",
            "By the crate.",
            250,
        );
        let hers = listing(
            &esteemed,
            Surface::Goods,
            "food",
            "Winter squash",
            "By the crate.",
            250,
        );
        publish(&index, &db, &mut log, &station, &humble, &theirs);
        publish(&index, &db, &mut log, &station, &esteemed, &hers);
        give_reputation(&db, &esteemed, 2.4);

        let hits = index
            .search(
                &db,
                &SearchQuery {
                    text: Some("squash".into()),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].listing.id, hers.id);
        assert!(hits[0].provider_reputation > hits[1].provider_reputation);
        // A multiplier, not a replacement: the lifted score is the relevance
        // scaled by 1 + composite, so relevance still dominates.
        assert!(hits[0].score > hits[1].score);
        assert!((hits[0].score / hits[1].score - (1.0 + 2.4)).abs() < 0.01);
    }

    #[test]
    fn reputation_cannot_surface_a_listing_the_text_missed() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let esteemed = Keypair::generate();
        let humble = Keypair::generate();

        let irrelevant = listing(
            &esteemed,
            Surface::Goods,
            "tools",
            "Claw hammer",
            "Forged head.",
            900,
        );
        let relevant = listing(
            &humble,
            Surface::Goods,
            "food",
            "Winter squash",
            "By the crate.",
            250,
        );
        publish(&index, &db, &mut log, &station, &esteemed, &irrelevant);
        publish(&index, &db, &mut log, &station, &humble, &relevant);
        give_reputation(&db, &esteemed, 3.5);

        // The best standing in Phase 1 does not put a hammer in a squash search.
        let hits = index
            .search(
                &db,
                &SearchQuery {
                    text: Some("squash".into()),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(titles(&hits), vec!["Winter squash"]);
    }

    #[test]
    fn a_reputation_floor_excludes_providers_below_it() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let humble = Keypair::generate();
        let esteemed = Keypair::generate();
        let theirs = listing(&humble, Surface::Goods, "food", "Squash", "Crate.", 250);
        let hers = listing(&esteemed, Surface::Goods, "food", "Honey", "Jar.", 250);
        publish(&index, &db, &mut log, &station, &humble, &theirs);
        publish(&index, &db, &mut log, &station, &esteemed, &hers);
        give_reputation(&db, &esteemed, 2.4);

        let hits = index
            .search(
                &db,
                &SearchQuery {
                    min_provider_reputation: Some(2.0),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(titles(&hits), vec!["Honey"]);
    }

    #[test]
    fn closed_and_expired_listings_drop_out_of_results() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station_key = Keypair::generate();
        let station = station_key.public_key();
        let index = SearchIndex::in_memory();
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let kept = listing(&alice, Surface::Goods, "food", "Squash", "Crate.", 250);
        let withdrawn = listing(&bob, Surface::Goods, "food", "Honey", "Jar.", 250);
        publish(&index, &db, &mut log, &station, &alice, &kept);
        publish(&index, &db, &mut log, &station, &bob, &withdrawn);

        append_listing_closed(
            &mut log,
            SignedPayload::sign(
                ListingClosed {
                    listing_id: withdrawn.id,
                    reason: CloseReason::ProviderClosed,
                    closed_at: NOW,
                },
                &bob,
            ),
            &station,
            NOW,
        )
        .unwrap();
        let state = compute_state(&log, &withdrawn.id, &station, NOW)
            .unwrap()
            .unwrap();
        index.upsert(&db, &withdrawn, &state).unwrap();

        assert_eq!(
            titles(&index.search(&db, &SearchQuery::default(), NOW).unwrap()),
            vec!["Squash"]
        );

        // Past the expiry the survivor drops out too, with no new record and no
        // reindex — the row is read against `now`, not frozen at write time.
        assert!(index
            .search(&db, &SearchQuery::default(), EXPIRES_AT + 1)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_rebuild_reproduces_what_incremental_indexing_built() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station_key = Keypair::generate();
        let station = station_key.public_key();
        let index = SearchIndex::in_memory();
        let providers: Vec<Keypair> = (0..4).map(|_| Keypair::generate()).collect();
        let listings = [
            listing(
                &providers[0],
                Surface::Goods,
                "food",
                "Winter squash",
                "By the crate.",
                250,
            ),
            listing(
                &providers[1],
                Surface::Goods,
                "food",
                "Wildflower honey",
                "Jar.",
                400,
            ),
            listing(
                &providers[2],
                Surface::Services,
                "construction",
                "Roofing",
                "Half a day.",
                500,
            ),
            listing(
                &providers[3],
                Surface::Goods,
                "tools",
                "Claw hammer",
                "Hickory.",
                900,
            ),
        ];
        for (provider, l) in providers.iter().zip(&listings) {
            publish(&index, &db, &mut log, &station, provider, l);
        }
        give_reputation(&db, &providers[1], 2.4);
        // One of them is withdrawn, so the rebuild has a closed listing to agree
        // about as well as open ones.
        append_listing_closed(
            &mut log,
            SignedPayload::sign(
                ListingClosed {
                    listing_id: listings[3].id,
                    reason: CloseReason::ProviderClosed,
                    closed_at: NOW,
                },
                &providers[3],
            ),
            &station,
            NOW,
        )
        .unwrap();
        let state = compute_state(&log, &listings[3].id, &station, NOW)
            .unwrap()
            .unwrap();
        index.upsert(&db, &listings[3], &state).unwrap();

        let queries = [
            SearchQuery::default(),
            SearchQuery {
                text: Some("squash".into()),
                ..SearchQuery::default()
            },
            SearchQuery {
                text: Some("jar".into()),
                ..SearchQuery::default()
            },
            SearchQuery {
                surface: Some(Surface::Goods),
                ..SearchQuery::default()
            },
            SearchQuery {
                max_price_centi: Some(400),
                ..SearchQuery::default()
            },
        ];
        let before: Vec<Vec<SearchHit>> = queries
            .iter()
            .map(|q| index.search(&db, q, NOW).unwrap())
            .collect();

        // Throw both halves away and derive them again from the log alone.
        let rebuilt = SearchIndex::in_memory();
        assert_eq!(rebuilt.rebuild(&db, &log, &station, NOW).unwrap(), 4);

        let after: Vec<Vec<SearchHit>> = queries
            .iter()
            .map(|q| rebuilt.search(&db, q, NOW).unwrap())
            .collect();
        assert_eq!(before, after);
        assert!(!before[0].is_empty());
    }

    #[test]
    fn a_rebuild_is_the_same_twice() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let providers: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
        for provider in &providers {
            let l = listing(
                provider,
                Surface::Goods,
                "food",
                "Winter squash",
                "By the crate.",
                250,
            );
            publish(&index, &db, &mut log, &station, provider, &l);
        }

        let once = {
            let i = SearchIndex::in_memory();
            i.rebuild(&db, &log, &station, NOW).unwrap();
            i.search(&db, &SearchQuery::default(), NOW).unwrap()
        };
        let twice = {
            let i = SearchIndex::in_memory();
            i.rebuild(&db, &log, &station, NOW).unwrap();
            i.search(&db, &SearchQuery::default(), NOW).unwrap()
        };
        assert_eq!(once, twice);
        // Identical text and no reputation anywhere: every score ties, so the
        // content-address tiebreak is the only thing making the order total.
        let ids: Vec<ListingId> = once.iter().map(|h| h.listing.id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn an_update_replaces_rather_than_duplicates_the_document() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let alice = Keypair::generate();
        let original = listing(
            &alice,
            Surface::Goods,
            "food",
            "Winter squash",
            "By the crate.",
            250,
        );
        publish(&index, &db, &mut log, &station, &alice, &original);

        // The real update path: a signed patch on the log, replayed back. The
        // patched listing keeps its published id while its content moves, so
        // this also pins that the index keys on the id it was written under and
        // not on the hash of the bytes it stored.
        append_listing_updated(
            &mut log,
            SignedPayload::sign(
                ListingUpdated {
                    listing_id: original.id,
                    patch: ListingPatch {
                        description: Some("Now by the half-crate too.".into()),
                        ..ListingPatch::empty()
                    },
                    signed_by: Address::from_public_key(alice.public_key()),
                },
                &alice,
            ),
            &station,
            NOW,
        )
        .unwrap();
        let state = compute_state(&log, &original.id, &station, NOW)
            .unwrap()
            .unwrap();
        let revised = state.listing().unwrap().clone();
        assert_eq!(revised.id, original.id);
        index.upsert(&db, &revised, &state).unwrap();

        let hits = index
            .search(
                &db,
                &SearchQuery {
                    text: Some("squash".into()),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(
            hits.len(),
            1,
            "the old document should be gone, not merely outranked"
        );

        let hits = index
            .search(
                &db,
                &SearchQuery {
                    text: Some("half-crate".into()),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn removing_a_listing_takes_it_out_of_both_halves() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let alice = Keypair::generate();
        let l = listing(
            &alice,
            Surface::Goods,
            "food",
            "Winter squash",
            "By the crate.",
            250,
        );
        publish(&index, &db, &mut log, &station, &alice, &l);

        index.remove(&db, &l.id).unwrap();

        assert!(index
            .search(&db, &SearchQuery::default(), NOW)
            .unwrap()
            .is_empty());
        assert!(index
            .search(
                &db,
                &SearchQuery {
                    text: Some("squash".into()),
                    ..SearchQuery::default()
                },
                NOW
            )
            .unwrap()
            .is_empty());
        assert_eq!(store::count(&db).unwrap(), 0);
    }

    #[test]
    fn paging_walks_the_ranked_order_without_gaps_or_repeats() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let providers: Vec<Keypair> = (0..5).map(|_| Keypair::generate()).collect();
        for provider in &providers {
            let l = listing(
                provider,
                Surface::Goods,
                "food",
                "Winter squash",
                "By the crate.",
                250,
            );
            publish(&index, &db, &mut log, &station, provider, &l);
        }

        let page = |offset| {
            index
                .search(
                    &db,
                    &SearchQuery {
                        limit: 2,
                        offset,
                        ..SearchQuery::default()
                    },
                    NOW,
                )
                .unwrap()
        };
        let walked: Vec<ListingId> = [0, 2, 4]
            .iter()
            .flat_map(|&o| page(o).into_iter().map(|h| h.listing.id))
            .collect();

        let whole: Vec<ListingId> = index
            .search(&db, &SearchQuery::default(), NOW)
            .unwrap()
            .iter()
            .map(|h| h.listing.id)
            .collect();
        assert_eq!(walked, whole);
        assert_eq!(walked.len(), 5);
    }

    #[test]
    fn an_empty_or_blank_text_query_is_not_a_text_query() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let alice = Keypair::generate();
        let l = listing(
            &alice,
            Surface::Goods,
            "food",
            "Winter squash",
            "By the crate.",
            250,
        );
        publish(&index, &db, &mut log, &station, &alice, &l);

        // Whitespace is not a search for whitespace; it is no text filter at all,
        // which matters because the browse screen sends an empty box.
        for text in ["", "   "] {
            let hits = index
                .search(
                    &db,
                    &SearchQuery {
                        text: Some(text.into()),
                        ..SearchQuery::default()
                    },
                    NOW,
                )
                .unwrap();
            assert_eq!(hits.len(), 1, "blank text {text:?} should not filter");
        }
    }

    #[test]
    fn the_stored_row_records_standing_at_creation_not_now() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let alice = Keypair::generate();
        let l = listing(
            &alice,
            Surface::Goods,
            "food",
            "Winter squash",
            "By the crate.",
            250,
        );
        publish(&index, &db, &mut log, &station, &alice, &l);

        // Standing arrives *after* the listing was indexed.
        give_reputation(&db, &alice, 2.4);

        let row = store::get(&db, &l.id.to_bytes()).unwrap().unwrap();
        assert_eq!(row.reputation_at_creation, 0.0);
        // Ranking, though, reads the present.
        let hits = index.search(&db, &SearchQuery::default(), NOW).unwrap();
        assert!((hits[0].provider_reputation - 2.4).abs() < 0.01);
    }

    #[test]
    fn a_listing_with_no_cached_snapshot_ranks_as_unscored() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let alice = Keypair::generate();
        let l = listing(
            &alice,
            Surface::Goods,
            "food",
            "Winter squash",
            "By the crate.",
            250,
        );
        publish(&index, &db, &mut log, &station, &alice, &l);

        // No snapshot written, and searching must not go and compute one.
        let hits = index.search(&db, &SearchQuery::default(), NOW).unwrap();
        assert_eq!(hits[0].provider_reputation, 0.0);
        assert_eq!(hits[0].score, 1.0);
    }

    #[test]
    fn the_index_survives_being_closed_and_reopened_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marketplace_index");
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let alice = Keypair::generate();
        let l = listing(
            &alice,
            Surface::Goods,
            "food",
            "Winter squash",
            "By the crate.",
            250,
        );

        {
            let index = SearchIndex::open(&path).unwrap();
            publish(&index, &db, &mut log, &station, &alice, &l);
        }

        let reopened = SearchIndex::open(&path).unwrap();
        let hits = reopened
            .search(
                &db,
                &SearchQuery {
                    text: Some("squash".into()),
                    ..SearchQuery::default()
                },
                NOW,
            )
            .unwrap();
        assert_eq!(titles(&hits), vec!["Winter squash"]);
    }

    #[test]
    fn compute_all_and_the_index_agree_on_what_is_active() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let providers: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
        for provider in &providers {
            let l = listing(provider, Surface::Goods, "food", "Squash", "Crate.", 250);
            publish(&index, &db, &mut log, &station, provider, &l);
        }

        let from_log = crate::lifecycle::compute_all_active(&log, &station, NOW).unwrap();
        let from_index: Vec<Listing> = {
            let mut hits = index.search(&db, &SearchQuery::default(), NOW).unwrap();
            hits.sort_by_key(|h| h.listing.id);
            hits.into_iter().map(|h| h.listing).collect()
        };
        assert_eq!(from_log, from_index);
    }
}
