//! Lineage proof: authenticating that a coin belongs to a DID's identity (SPEC §5).
//!
//! [`prove_lineage`] answers ONE question — "is this coin a coin the DID identity owns / is rooted
//! in?" — and answers it soundly, via exactly two accepted models, both reduced to DID-singleton
//! lineage membership:
//!
//! - **[`LineageModel::Direct`]** — the coin authenticates as a state of the DID singleton ITSELF
//!   (its authenticated launcher id equals the DID's launcher id).
//! - **[`LineageModel::LaunchedFrom`]** — the coin is a DISTINCT singleton whose launcher coin's parent
//!   is a MEMBER of the DID singleton's lineage (the DID coin created that launcher). Membership, NOT
//!   tip-equality: launching from a DID recreates the DID coin in the same spend, so the launcher's
//!   parent is a PAST DID coin `Cn` while the DID tip is already `Cn+1`.
//!
//! Everything else fails closed. In particular an ordinary payment/change coin whose `parent_coin_info`
//! merely happens to be a DID coin is REJECTED — a DID spend can pay anyone, so a pay-to coin is not
//! owned by the DID. The discriminator is SINGLETON STRUCTURE (authenticated by the walk in
//! [`crate::resolve`]): a non-singleton coin has no launcher and fails with [`DidError::NotASingleton`].

use chia_protocol::Bytes32;
use chia_wallet_sdk::driver::{Did, SingletonInfo};

use crate::error::{DidError, DidResult};
use crate::resolve::{authenticate_singleton, ChainSource};

/// How a coin is rooted in a DID's identity — the two (and only two) accepted models.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageModel {
    /// The coin is a state of the DID singleton itself (authenticated launcher id == the DID's).
    Direct,

    /// The coin is a distinct singleton launched from the DID: its launcher's parent is a member of the
    /// DID singleton's lineage.
    LaunchedFrom {
        /// The authenticated launcher id of the distinct (launched) singleton.
        launcher: Bytes32,
        /// The DID coin (a member of the DID lineage) that created the distinct singleton's launcher.
        did_parent: Bytes32,
    },
}

/// A chain-authenticated proof that a coin is rooted in a DID's identity.
///
/// Its fields are PRIVATE and exposed only through accessors: an `AncestryProof` cannot be forged by a
/// struct literal — the only way to obtain one is [`prove_lineage`], which authenticates every field
/// against the chain. Treat a value of this type as evidence the proof genuinely holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestryProof {
    coin_id: Bytes32,
    did_launcher_id: Bytes32,
    model: LineageModel,
    did_lineage_tip: Bytes32,
    authenticated_launcher: Bytes32,
    chain: Vec<Bytes32>,
}

impl AncestryProof {
    /// The coin this proof authenticates.
    pub fn coin_id(&self) -> Bytes32 {
        self.coin_id
    }

    /// The launcher id of the DID the coin is rooted in.
    pub fn did_launcher_id(&self) -> Bytes32 {
        self.did_launcher_id
    }

    /// Which of the two accepted models roots the coin in the DID.
    pub fn model(&self) -> LineageModel {
        self.model
    }

    /// The DID singleton's current unspent tip at proof time.
    pub fn did_lineage_tip(&self) -> Bytes32 {
        self.did_lineage_tip
    }

    /// The launcher id the coin itself authenticated to (equal to the DID's launcher id for
    /// [`LineageModel::Direct`]; the distinct singleton's launcher for [`LineageModel::LaunchedFrom`]).
    pub fn authenticated_launcher(&self) -> Bytes32 {
        self.authenticated_launcher
    }

    /// The audit trail of coin ids walked, from the proven coin up to (and including) its launcher.
    pub fn chain(&self) -> &[Bytes32] {
        &self.chain
    }
}

/// Proves that `coin_id` is rooted in `did`'s identity, reading chain state through `chain`.
///
/// This is the crate's lineage trust anchor. It authenticates `coin_id` as a genuine singleton (walking
/// its parent-spend chain to a launcher — see [`crate::resolve`]) and then roots it in the DID by one of
/// the two [`LineageModel`]s. Pure over the injected reads: NO keys, NO signing, NO network (INV-1/2).
///
/// # Errors
///
/// Fails closed on every gap or mismatch (SPEC §5):
///
/// - [`DidError::NoIdentitySingleton`] — the DID has no current on-chain coin (unlaunched or melted).
/// - [`DidError::NotASingleton`] — `coin_id` is not a genuine singleton (a payment/change coin, or a
///   pay-to coin wearing a singleton puzzle hash with no genuine recreation parent spend).
/// - [`DidError::NotDidRooted`] — `coin_id` authenticates as a singleton but is neither the DID nor
///   launched from a coin in the DID's lineage.
/// - [`DidError::LineageTooDeep`] — the walk exceeded [`crate::resolve::MAX_LINEAGE_DEPTH`].
/// - [`DidError::Chain`] — a `chain` read failed (never degraded to "assume owned").
pub fn prove_lineage<S: ChainSource>(
    coin_id: Bytes32,
    did: &Did,
    chain: &S,
) -> DidResult<AncestryProof> {
    let did_launcher_id = did.info.launcher_id();

    // The DID's own authentic lineage — its existence anchors the proof, and its membership set decides
    // the LaunchedFrom model. A missing lineage is fail-closed, never "assume owned".
    let did_lineage = chain
        .resolve_singleton_lineage(did_launcher_id)
        .map_err(|error| DidError::Chain(error.to_string()))?
        .ok_or(DidError::NoIdentitySingleton)?;

    // Authenticate the coin as a genuine singleton and derive the launcher it descends from.
    let authenticated = authenticate_singleton(coin_id, chain)?;

    // Model (a) Direct: the coin IS a state of the DID singleton.
    let model = if authenticated.launcher_id == did_launcher_id {
        LineageModel::Direct
    } else {
        // Model (b) LaunchedFrom: the distinct singleton's launcher must have been created by a coin in
        // the DID's lineage (membership, not tip-equality).
        let did_parent = authenticated.launcher_coin.parent_coin_info;
        if !did_lineage.contains(did_parent) {
            return Err(DidError::NotDidRooted);
        }
        LineageModel::LaunchedFrom {
            launcher: authenticated.launcher_id,
            did_parent,
        }
    };

    Ok(AncestryProof {
        coin_id,
        did_launcher_id,
        model,
        did_lineage_tip: did_lineage.tip(),
        authenticated_launcher: authenticated.launcher_id,
        chain: authenticated.trail,
    })
}
