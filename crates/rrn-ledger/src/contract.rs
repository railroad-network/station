//! The direct-debit charge that a recurring service contract executes each
//! period (T1.7.7).
//!
//! A one-off payment is a sender-signed [`TransactionProposal`](crate::transaction::TransactionProposal)
//! the receiver confirms and the settlement window closes. A subscription cannot
//! work that way — the buyer is not present to sign each period's charge. Instead
//! the buyer signs *one* `ServiceContract` (in `rrn-marketplace`) that
//! pre-authorizes every identical period, and the
//! **station** executes each period as a direct debit: it appends a
//! station-signed [`ContractCharge`] to the log, which moves the balance directly
//! — no per-period proposal, confirmation, or settlement window.
//!
//! # A second balance source, so it mirrors settlement exactly
//!
//! [`ContractCharge`] is the sibling of
//! [`SettlementRecord`](crate::settlement::SettlementRecord): a station-signed
//! record that *is* a balance change, restating the parties and amount so
//! balances stay fully re-derivable from the log alone (ADR-0005 — the station
//! attests to a move no transacting party is present to sign). Whoever derives
//! balances from the log folds a charge as **buyer `-amount`, provider
//! `+amount`**, and — the load-bearing rule — applies each
//! `(contract_ref, period_index)` **exactly once**, so a boot-time re-sweep, a
//! replayed entry, or a gossiped duplicate can never double-charge a period.
//!
//! # The ledger does not know what a contract is
//!
//! As with [`ListingRef`](crate::transaction::ListingRef), the contract is held
//! as an **opaque 32 bytes** ([`ContractRef`]) — a marketplace `ContractId` in raw
//! form — so `rrn-ledger` stays free of a dependency on `rrn-marketplace`, which
//! already depends on it (the reverse would cycle). The ledger cannot check that a
//! charge is backed by a real, active, not-yet-charged contract period; the
//! station does, at append time (T1.7.7 Part D). The ledger's job is only to make
//! the charge a balance change that re-derives identically everywhere.

use dcbor::prelude::*;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use serde::{Deserialize, Serialize};

/// Discriminant string for a contract-charge record's canonical CBOR.
pub(crate) const CONTRACT_CHARGE_KIND: &str = "rrn.tx.contract_charge";

/// A reference to the marketplace service contract a charge is executing.
///
/// Held as **opaque 32 bytes** — a marketplace `ContractId` in raw form — so the
/// ledger need not depend on `rrn-marketplace`. Marketplace and mobile code
/// convert via `ContractId::to_bytes()`. Encoded as a CBOR byte string, exactly
/// as a [`ListingRef`](crate::transaction::ListingRef) or transaction id is.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContractRef(pub [u8; 32]);

impl From<ContractRef> for CBOR {
    fn from(r: ContractRef) -> Self {
        CBOR::to_byte_string(r.0)
    }
}

impl TryFrom<CBOR> for ContractRef {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let bytes: [u8; 32] = cbor
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(ContractRef(bytes))
    }
}

/// One period's direct-debit charge under a service contract. Signed by the
/// station.
///
/// It restates the parties and amount so that balances are fully re-derivable
/// from the log alone (the materialized balance is just a cache). The idempotency
/// key is `(contract_ref, period_index)`: a balance fold applies each period once,
/// no matter how many charge records reference it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractCharge {
    /// The service contract this charge is executing.
    pub contract_ref: ContractRef,
    /// The subscriber, debited `amount_centi`.
    pub buyer: Address,
    /// The service provider, credited `amount_centi`.
    pub provider: Address,
    /// The per-period charge in centicommons (the agreed price). Positive =
    /// buyer pays provider, the only direction a contract charges.
    pub amount_centi: i64,
    /// Which period this charge is for (0-based). With `contract_ref`, the
    /// idempotency key.
    pub period_index: u32,
    /// Unix seconds the station executed the charge, from its own clock.
    pub charged_at: i64,
}

impl From<ContractCharge> for CBOR {
    fn from(c: ContractCharge) -> Self {
        let mut m = Map::new();
        m.insert("kind", CONTRACT_CHARGE_KIND);
        m.insert("contract_ref", c.contract_ref);
        m.insert("buyer", c.buyer);
        m.insert("provider", c.provider);
        m.insert("amount_centi", c.amount_centi);
        m.insert("period_index", c.period_index);
        m.insert("charged_at", c.charged_at);
        m.into()
    }
}

impl TryFrom<CBOR> for ContractCharge {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != CONTRACT_CHARGE_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(ContractCharge {
            contract_ref: map.extract::<&str, ContractRef>("contract_ref")?,
            buyer: map.extract::<&str, Address>("buyer")?,
            provider: map.extract::<&str, Address>("provider")?,
            amount_centi: map.extract::<&str, i64>("amount_centi")?,
            period_index: map.extract::<&str, u32>("period_index")?,
            charged_at: map.extract::<&str, i64>("charged_at")?,
        })
    }
}

/// A [`ContractCharge`] signed by the station (the only party entitled to it).
pub type SignedContractCharge = SignedPayload<ContractCharge>;

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    #[test]
    fn charge_roundtrips_through_canonical_cbor() {
        let buyer = Keypair::generate();
        let provider = Keypair::generate();
        let charge = ContractCharge {
            contract_ref: ContractRef([7u8; 32]),
            buyer: addr(&buyer),
            provider: addr(&provider),
            amount_centi: 500,
            period_index: 3,
            charged_at: 1_753_000_000,
        };
        let decoded: ContractCharge = from_canonical_bytes(&to_canonical_bytes(charge)).unwrap();
        assert_eq!(decoded, charge);
    }

    #[test]
    fn contract_ref_roundtrips_as_a_byte_string() {
        let r = ContractRef([9u8; 32]);
        let cbor: CBOR = r.into();
        assert_eq!(ContractRef::try_from(cbor).unwrap(), r);
    }

    #[test]
    fn a_settlement_record_does_not_decode_as_a_charge() {
        // Distinct `kind`s keep the two station-signed balance records apart, so a
        // balance fold never mistakes one for the other.
        let buyer = Keypair::generate();
        let provider = Keypair::generate();
        let settlement = crate::settlement::SettlementRecord {
            proposal_id: crate::transaction::TransactionId(rrn_crypto::hash::Hash::of(b"x")),
            sender: addr(&buyer),
            receiver: addr(&provider),
            amount_centi: 500,
            settled_at: 1_000,
        };
        let bytes = to_canonical_bytes(settlement);
        assert!(from_canonical_bytes::<ContractCharge>(&bytes).is_err());
    }
}
