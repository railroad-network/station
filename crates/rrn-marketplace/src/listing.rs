//! Listings — a member's signed offer of a good or service, priced in the
//! Common.
//!
//! One schema serves all three surfaces (Goods, Services, Commons) behind a
//! discriminant, and a `ListingId` is the Blake3 hash of the listing's own
//! canonical bytes, so a listing names itself. Validation runs at construction:
//! an invalid listing is one that cannot exist, not one that exists and is
//! ignored.
//!
//! Implemented in T1.6.3 (the record type) and T1.6.4 (its log entries); this
//! is a Phase 1 skeleton placeholder.
