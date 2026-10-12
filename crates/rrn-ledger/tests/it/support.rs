//! Shared setup for the integration tests.

use rrn_crypto::keypair::Keypair;
use rrn_identity::address::Address;
use rrn_ledger::enrollment::{append_enrollment, EnrollmentAction, EnrollmentBasis};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

/// Enrolls `member` under `station` (ADR-0038), as pairing would, so a member
/// who spends from zero runs the configured debt floor rather than the
/// unenrolled floor of zero.
pub fn enroll(db: &Database, station: &Keypair, member: &Keypair) {
    append_enrollment(
        &mut AppendLog::new(db),
        station,
        Address::from_public_key(member.public_key()),
        EnrollmentAction::Enroll,
        EnrollmentBasis::Pairing,
        0,
    )
    .unwrap();
}
