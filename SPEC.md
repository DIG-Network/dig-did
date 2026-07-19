# dig-did — Normative Specification

`dig-did` is the DIG Network canonical **Chia DID expert crate**: a pure, key-free, network-free
library that builds the exact `CoinSpend`s for every Chia Decentralized Identifier (DID) lifecycle
operation and reports the exact signatures a caller must produce. This document is the authoritative
contract an independent reimplementation could be built against. It describes the COMPLETE designed
surface; the crate ships incrementally by unit (U1 = foundation), but the contract below is final.

Key words MUST, MUST NOT, SHOULD, MAY are used per RFC 2119.

---

## §1 Scope & invariants

dig-did is a **spend-builder**. It transforms caller-supplied on-chain state (coins, puzzles,
lineage) into unsigned `CoinSpend`s and tells the caller what to sign. It is not a wallet, not a
node, and not a signer.

Four invariants hold across the entire crate:

- **INV-1 — No network.** dig-did performs NO network or chain I/O. Every public function is a pure
  transform of its inputs. The caller is responsible for fetching coins/puzzle reveals and for
  broadcasting the assembled `SpendBundle`.
- **INV-2 — No keys.** dig-did MUST NOT accept, hold, derive, persist, or log a secret key. It
  computes the messages that must be signed (§4); the caller's signer produces the signatures. No
  function in this crate takes a `SecretKey`.
- **INV-3 — Unsigned output.** Every operation returns an unsigned `DidSpend` — the coin spends plus
  the recreated child DID. Assembling and signing the `SpendBundle` is always the caller's
  responsibility.
- **INV-4 — SDK byte-source-of-truth.** Every puzzle, layer, and coin-spend byte is produced by
  `chia-wallet-sdk` (pinned to the **0.30 / chia-protocol 0.26** family — the version the whole DIG
  on-chain line rides). dig-did MUST NOT re-implement a DID puzzle or hand-roll a spend bundle; it
  adds DID-workflow ergonomics over the SDK primitives.

---

## §2 DID model

A Chia DID is a **singleton** whose inner puzzle is the DID layer, whose inner puzzle is in turn the
owner's p2 ("standard") puzzle:

```
SingletonLayer( DidLayer( p2_puzzle ) )
```

### 2.1 `DidInfo`

The information needed to construct a DID's outer puzzle (re-exported verbatim from
`chia-wallet-sdk`, INV-4):

| Field | Type | Meaning |
|---|---|---|
| `launcher_id` | `Bytes32` | Coin id of the launcher coin that created this DID's singleton. Stable identity of the DID for life. |
| `recovery_list_hash` | `Option<Bytes32>` | Hash of the recovery list (§3 recovery). `None` where the wallet allows it. |
| `num_verifications_required` | `u64` | Number of recoverer attestations required to recover. |
| `metadata` | `HashedPtr` | The DID layer metadata. Freely updatable, but must be confirmed by a settle spend (§3). |
| `p2_puzzle_hash` | `Bytes32` | Hash of the inner (owner) puzzle. Bech32m-encoded, this is the current owner's address. |

`DidInfo::inner_puzzle_hash()` derives the DID layer puzzle hash from these fields via
`DidArgs::curry_tree_hash(p2_puzzle_hash, recovery_list_hash, num_verifications_required,
SingletonStruct::new(launcher_id), metadata_tree_hash)`. This derivation is the SDK's; dig-did MUST
use it rather than recomputing.

### 2.2 `Did`

`Did = Singleton<DidInfo>` = `{ coin: Coin, proof: Proof, info: DidInfo }`. The `Proof` (an
`EveProof` for a freshly launched DID, a `LineageProof` thereafter) is required in the singleton
solution to spend the coin. A `Did` carries everything needed to spend the DID EXCEPT the inner
puzzle+solution, which the `Owner` (§2.4) supplies.

### 2.3 `did:chia:1…` string (codec)

A DID's canonical string form is `did:chia:` followed by the **bech32m** encoding of its
`launcher_id`, using the same address codec as `chia-sdk-utils` `Address` (hrp `did:chia:`). The
codec MUST byte-agree with that SDK codec (§9); dig-did MUST NOT hand-roll bech32m. Malformed input
yields `DidError::InvalidDidString`.

### 2.4 `Owner`

`Owner` names the p2 puzzle that authorizes a DID spend:

- `Owner::Standard(PublicKey)` — the standard single-key p2 puzzle. dig-did curries the
  `StandardLayer` over the (synthetic) key; the resulting spend requires one `AGG_SIG_ME` over that
  key (§4).
- `Owner::Custom(Spend)` — a caller-supplied, already-built inner `Spend` for any p2 puzzle (custom
  vault, multisig, delegated puzzle). dig-did passes it through unchanged; the caller owns its
  signature requirements.

---

## §3 Operations

Every operation returns `Result<DidSpend, DidError>` where `DidSpend = { coin_spends:
Vec<CoinSpend>, child: Option<Did> }`. `child` is the DID as it will exist after the spends confirm
(`None` only for a terminal operation). Unless stated otherwise, a standard-owner operation requires
exactly one `AGG_SIG_ME` over the owner key (§4); a custom-owner operation requires whatever the
caller's inner spend requires.

| Operation | Unit | Inputs | CoinSpends produced | Recreated child | Signature |
|---|---|---|---|---|---|
| **Create** | U2 | funding coin, owner, `recovery_list_hash`, `num_verifications_required`, metadata | launcher spend (from funding coin) + eve DID spend + owner settle spend | the new `Did` | 2× `AGG_SIG_ME` (owner: one over the funding-coin spend, one over the settle spend) |
| **Update-metadata** | U3 | `Did`, owner, new metadata | DID update spend recreating the DID with new metadata | `Did` with new `metadata` | 1× `AGG_SIG_ME` (owner) |
| **Settle** | U3 | `Did`, owner | DID update spend with unchanged metadata/p2 (confirms metadata for wallets) | `Did` unchanged in shape | 1× `AGG_SIG_ME` (owner) |
| **Set-recovery** | U4 | `Did`, owner, new `recovery_list_hash`, `num_verifications_required` | DID update spend recreating the DID with new recovery config | `Did` with new recovery fields | 1× `AGG_SIG_ME` (owner) |
| **Recover** | U4 | `Did`, recoverer attestations, new p2 puzzle hash | DID recovery spend rotating owner to the new p2 | `Did` with new `p2_puzzle_hash` | attestations per `num_verifications_required` |
| **Transfer** | U5 | `Did`, owner, new p2 puzzle hash | DID update spend creating the DID under the new owner (hinted) | `Did` with new `p2_puzzle_hash` | 1× `AGG_SIG_ME` (CURRENT owner) |
| **Launch-from-DID** (child DID / NFT / datastore) | U6 | `Did`, owner, launch parameters | DID update spend emitting the launch conditions + the dependent singleton's launch spend(s) | `Did` (unchanged) + the launched primitive | 1× `AGG_SIG_ME` (owner) |
| **Melt** | U7 | `Did`, owner | DID spend with no odd-amount successor (terminal) | `None` | 1× `AGG_SIG_ME` (owner) |
| **Announce-as-DID** (attest) | U8 | `Did`, owner, announcement message/target | DID update spend emitting the announcement condition | `Did` (unchanged) | 1× `AGG_SIG_ME` (owner) |
| **Hydrate** | U9 | parent coin, parent puzzle reveal, parent solution, child coin | — (parse only) | the spendable `Did` | — |
| **Resolve** | U10 | `Did` (or hydrated state) | — (projection only) | resolved view / DID document | — |

Notes:
- **Create** builds the eve DID via `Launcher::create_eve_did`, then performs the settle spend
  itself (via `Did::spend` with an `Owner`-derived inner [`Spend`], SPEC §2.4) rather than the SDK's
  typed `Launcher::create_did`/`Did::update`, because those require a concrete `SpendWithConditions +
  ToTreeHash` inner layer and so cannot accept an `Owner::Custom` pre-built spend. Building on the raw
  `Did::spend` primitive keeps every create/update/settle operation generic over `Owner`. All three
  resulting spends (funding, launcher, settle) are returned together as one `DidSpend`.
  `create_eve_did_only` is the lower-level primitive that stops after the launcher spend, for a
  caller that wants to fold its own follow-up spend into the same bundle.
- **Update/Settle/Transfer/Launch/Melt/Attest** all build on the SDK `Did::update*` / `Did::spend` /
  `Did::transfer` methods with the inner spend from the `Owner` (§2.4).
- dig-did MUST NOT sign or broadcast any of these; it returns the `CoinSpend`s only (INV-3).

---

## §4 Signing boundary

`required_signatures(coin_spends: &[CoinSpend], constants: &AggSigConstants) ->
Result<Vec<RequiredSignature>, DidError>` is the sole bridge between dig-did's unsigned output and a
caller's signer.

- It runs each coin spend's puzzle against its solution in a private `Allocator`, collects every
  `AGG_SIG_*` condition, and returns the precise `RequiredSignature` set (public key + raw message +
  appended coin/domain info) — the exact bytes the caller must sign.
- It is **pure and key-free** (INV-2): it takes no secret key and computes only what must be signed.
- `AggSigConstants` is derived from the network's `AGG_SIG_ME` additional data, e.g.
  `AggSigConstants::from(&*MAINNET_CONSTANTS)`.
- **Owner operations use `AGG_SIG_ME`** (bound to the specific coin id). dig-did MUST NOT produce a
  spend that requires `AGG_SIG_UNSAFE` over caller-supplied bytes — an `AGG_SIG_UNSAFE` requirement
  would let a signature be replayed against an unrelated message.
- Errors: `DidError::Signer` if a puzzle fails to evaluate or an `AGG_SIG` condition carries an
  infinity public key.

The delegation to `chia_sdk_signer::RequiredSignature::from_coin_spends` guarantees byte-agreement
with the SDK's signature-message construction (INV-4, §9).

---

## §5 Hydration & lineage (fail-closed)

Reconstructing a spendable `Did` from chain data is **fail-closed**: dig-did returns an
error rather than a degraded or guessed DID.

- A DID child is parsed from its parent coin spend (SDK `Did::parse_child`), which relies on the
  child being **hinted** and carrying the **same metadata** as the parent.
- If the parent spend does not establish a lineage proof for the child, hydration MUST return
  `DidError::MissingLineage`.
- If the owner **hint memo** required to recreate the child is absent, hydration MUST return
  `DidError::MissingHint`.
- A puzzle that parses but is not a DID singleton MUST yield `DidError::NotDid`; a puzzle that should
  have been a DID but fails to parse MUST yield `DidError::Parse`.
- Hydration MUST NOT fabricate a lineage proof or a hint. A DID that cannot be proven spendable is an
  error, never a partially-populated success.

### 5.1 Lineage proof (`prove_lineage` → `AncestryProof`)

`prove_lineage(coin_id, did, chain)` answers one question — *is `coin_id` a coin the DID identity owns
/ is rooted in?* — over a caller-supplied `ChainSource` (§10). It returns an unforgeable `AncestryProof`
(private fields, accessor-only) via **exactly two accepted models**, both reduced to DID-singleton
**lineage membership**:

- **`Direct`** — `coin_id` authenticates as a state of the DID singleton itself: its authenticated
  launcher id equals `did.launcher_id`.
- **`LaunchedFrom { launcher, did_parent }`** — `coin_id` is a *distinct* singleton whose launcher
  coin's `parent_coin_info` (`did_parent`) is a **member** of the DID singleton's lineage. Membership,
  NOT tip-equality: launching from a DID recreates the DID coin in the same spend, so the launcher's
  parent is a past DID coin `Cn` while the tip is already `Cn+1`.

**The curry-commitment authentication rule (the soundness crux).** A coin is authenticated as a genuine
singleton ONLY by walking its parent-spend chain (`ChainSource::parent_spend`): at each hop the parent
puzzle MUST parse as the SDK `SingletonLayer` (proving the parent is itself a singleton and yielding its
*curried* `launcher_id`); the parent's inner puzzle is run and its odd-amount successor re-wrapped in the
singleton curry (`SingletonArgs::curry_tree_hash(launcher_id, inner)`), and that computed successor MUST
equal the child under authentication. The walk terminates at the singleton **launcher** coin
(`SINGLETON_LAUNCHER_HASH`), yielding the authenticated `launcher_id`. dig-did MUST NEVER authenticate a
coin on `coin.puzzle_hash == singleton_puzzle_hash(...)` alone (a pay-to coin can wear any puzzle hash),
nor on a bare `parent_coin_info` field without the parent's spend proving the recreation.

**Out of scope — MUST fail.** An ordinary payment/change coin whose `parent_coin_info` merely happens to
be a DID coin is REJECTED (`NotASingleton`): a DID spend may pay anyone, so a non-singleton output is not
owned by the DID. The discriminator is singleton structure.

**Fail-closed.** Every gap/mismatch is an error, never a soft `true`: no DID lineage →
`NoIdentitySingleton`; not a genuine singleton → `NotASingleton`; a genuine singleton neither the DID nor
launched from it → `NotDidRooted`; a walk past `MAX_LINEAGE_DEPTH` → `LineageTooDeep`; a `ChainSource`
read failure → `Chain` (never "assume owned").

`walk_did_lineage_to_tip(chain, launcher_id)` is the forward companion: it resolves the DID singleton's
current unspent tip and reconstructs it as a `DidTip { coin, info, proof }` (SDK `Did::parse_child`), or
`None` when the DID is unlaunched/melted. It fails closed (`NotDid`) when the tip's creating spend does
not parse as a DID.

---

## §6 Error taxonomy

`DidError` (a `thiserror` enum; the crate result alias is `DidResult<T> = Result<T, DidError>`):

| Variant | Raised when |
|---|---|
| `Driver(DriverError)` | A chia-wallet-sdk driver op failed (currying, spend construction, CLVM eval). Wrapped verbatim. |
| `Signer(String)` | The signing calculator failed (invalid puzzle/solution, infinity public key). Underlying signer error as a string, so the signer's error type does not leak. |
| `Parse(String)` | A coin/puzzle/solution could not be parsed as the expected shape. |
| `NotDid` | A puzzle parsed but is not a DID singleton. |
| `InvalidDidString(String)` | A `did:chia:1…` string was malformed / failed bech32m decoding. |
| `InvalidRecovery(String)` | An inconsistent recovery configuration was supplied. |
| `MissingLineage` | Hydration could not establish the lineage proof (fail-closed, §5). |
| `MissingHint` | A parsed DID coin was missing the owner hint memo (fail-closed, §5). |
| `Chain(String)` | A chain-level precondition was violated, or a `ChainSource` read failed (§10) — surfaced verbatim, never degraded to "assume owned". |
| `NoIdentitySingleton` | The DID has no current on-chain coin — unlaunched or melted (§5.1, fail-closed). |
| `NotASingleton` | A coin under `prove_lineage` is not a genuine singleton (a payment/change coin, or a pay-to coin wearing a singleton puzzle hash with no genuine recreation parent spend) (§5.1). |
| `NotDidRooted` | A coin authenticates as a singleton but is neither the DID nor launched from a coin in the DID's lineage (§5.1). |
| `LineageTooDeep` | The singleton parent-spend walk exceeded `MAX_LINEAGE_DEPTH` — a DoS guard (§5.1/§10). |

Error messages MUST be descriptive and MUST NOT include secret material.

---

## §7 Security properties

- **No custody.** dig-did never holds a key (INV-2). A caller compromise cannot leak a key *through*
  dig-did because dig-did never possesses one.
- **Explicit signing surface.** Every signature a caller must produce is enumerated by
  `required_signatures` — there is no hidden signing requirement. What the caller signs is exactly
  and only what the returned spends require.
- **`AGG_SIG_ME` binding.** Owner operations bind their signature to the specific coin being spent
  (§4), preventing signature replay across coins. dig-did never emits an `AGG_SIG_UNSAFE` over
  caller bytes.
- **Fail-closed hydration.** Ambiguous or under-specified chain data is an error, not a guess (§5),
  so a caller never signs against a mis-reconstructed DID.
- **Deterministic byte output.** Given identical inputs, dig-did produces identical `CoinSpend`
  bytes (INV-4 delegation to the SDK), making spends auditable and reproducible.
- **Unforgeable lineage proof.** An `AncestryProof` has private fields and accessor-only reads — it
  cannot be minted by a struct literal; the only constructor, `prove_lineage`, authenticates every
  field against the chain (§5.1). A value of the type is therefore evidence the proof genuinely holds.
- **Sound singleton authentication.** A coin is proven owned ONLY by the curry-commitment walk (§5.1) —
  never by puzzle-hash equality or a bare `parent_coin_info`. A non-singleton coin (a payment routed
  through a DID spend) fails closed as `NotASingleton`, so a DID spend that pays an attacker never
  launders that coin into the DID's authority.
- **Bounded work.** The parent-spend walk is capped at `MAX_LINEAGE_DEPTH`, so a malicious
  `ChainSource` cannot force unbounded computation (`LineageTooDeep`).

---

## §8 Backwards compatibility

Per CLAUDE.md §5.1 (additive-only), a published DID is a permanent on-chain artifact and MUST stay
spendable and parseable by every later dig-did:

- **Additive only.** New operations, new optional parameters, and new fields MAY be added. Existing
  operation signatures, produced `CoinSpend` byte shapes, and parsing behavior MUST NOT be removed,
  renumbered, or repurposed.
- **Newer parses older.** A newer dig-did MUST hydrate/resolve every DID a prior version built. A
  version bump means "new builders MAY emit new shapes", never "readers reject older DIDs".
- **Golden fixtures.** Each release keeps golden `CoinSpend` fixtures of the DID operations. A change
  MUST include a test proving the new builder reproduces the prior fixtures byte-identically and the
  new parser decodes older fixtures. A byte-shape change without such a test is incomplete.
- **SDK pin discipline.** The chia-wallet-sdk version is a byte contract (INV-4). Bumping it is a
  deliberate, fixture-verified event — a resulting byte change is a breaking (major) protocol event
  with a migration path, never a silent break.

---

## §9 Conformance

An implementation conforms to this spec when:

- Every produced `CoinSpend` **byte-agrees with chia-wallet-sdk 0.30** for the equivalent operation
  (INV-4). This crate satisfies it by construction (it calls the SDK).
- The `did:chia:1…` codec **byte-agrees with `chia-sdk-utils` `Address`** (§2.3) — same hrp, same
  bech32m, round-trips every launcher id.
- `required_signatures` output **byte-agrees with `chia_sdk_signer::RequiredSignature`** for the same
  coin spends and constants (§4).
- The datastore launch authorization (§3, U6) **byte-agrees with `chip35`** for the equivalent
  DID-authorized datastore launch, so a DID launched via dig-did and one launched via chip35 are
  indistinguishable on chain.
- All fail-closed hydration rules (§5) hold: missing lineage/hint/DID-shape are errors, never
  degraded successes.
- `prove_lineage` accepts exactly the two models of §5.1 and rejects everything else with the stated
  fail-closed error; the curry-commitment authentication rule holds (no puzzle-hash-equality shortcut).

---

## §10 The `ChainSource` seam & trust model

dig-did performs **no network or chain I/O** (INV-1), yet lineage authentication needs to *read* chain
state. `ChainSource` is the seam that reconciles the two — the caller supplies an honest reader; dig-did
supplies all the trust logic. There is **no default impl** in dig-did: the consumer implements it over
its own backend (coinset.org, a local full node, `chia-query`), keeping dig-did no-network and
wasm-buildable.

```rust
pub trait ChainSource {
    type Error: core::fmt::Display;
    fn resolve_singleton_lineage(&self, launcher_id: Bytes32)
        -> Result<Option<SingletonLineage>, Self::Error>;
    fn parent_spend(&self, coin_id: Bytes32)
        -> Result<Option<CoinSpend>, Self::Error>;
}
```

- `resolve_singleton_lineage` MUST be a genuine forward walk from the DID launcher to its current
  unspent tip, returning every coin id on the walk as a `SingletonLineage` (membership set + tip), or
  `None` when the launcher never existed / the singleton is fully spent. It MUST NOT echo a
  caller-supplied coin.
- `parent_spend(coin_id)` MUST return the coin spend that CREATED `coin_id` (the spend of its parent
  coin), or `None` when no such spend is known. It performs NO authentication — dig-did's walk parses
  and verifies it.

**Trust boundary.** The `ChainSource` MUST be the caller's OWN honest view of the chain, never an
attacker-controlled channel. dig-did assumes the source reports real chain state; it cannot defend
against a source that fabricates the chain itself. Given honest chain data, dig-did guarantees no coin
can launder itself into a DID's authority (§5.1, §7). Every read failure or gap fails closed
(`DidError::Chain` / the §5.1 errors), never an "assume owned" default.

**Coherence.** `SingletonLineage` (tip + membership `contains`) is byte-coherent with dig-identity's
type of the same name, so dig-identity can later de-duplicate onto dig-did (the lower foundation) without
a behavioural change.
