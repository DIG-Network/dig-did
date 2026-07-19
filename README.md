# dig-did

**The DIG Network canonical Chia DID expert crate** — a pure, key-free, network-free
SpendBundle-builder for Chia Decentralized Identifiers (DIDs).

dig-did constructs the exact `CoinSpend`s for every DID lifecycle operation and reports the exact
signatures a caller must produce. It **never holds a secret key, never signs, and never touches the
network.** You build an unsigned spend, ask dig-did what must be signed, sign it with your own
signer, assemble the `SpendBundle`, and broadcast.

> This crate is built to a normative spec — see [`SPEC.md`](./SPEC.md) for the full contract an
> independent reimplementation could be built against.

```toml
[dependencies]
dig-did = "0.2"
```

---

## Invariants

- **INV-1 — No network.** No network or chain I/O. Every function is a pure transform; you fetch
  coins and broadcast bundles.
- **INV-2 — No keys.** dig-did never accepts, holds, derives, or logs a secret key. No function takes
  a `SecretKey`.
- **INV-3 — Unsigned output.** Every operation returns an unsigned `DidSpend`. Signing is always
  yours.
- **INV-4 — SDK byte-source-of-truth.** Every puzzle/spend byte comes from `chia-wallet-sdk` (pinned
  to the 0.30 / chia-protocol 0.26 family). dig-did adds DID-workflow ergonomics; it never
  re-implements a puzzle or hand-rolls a spend bundle.

---

## The consumer pattern

```text
build an unsigned DidSpend
   -> required_signatures(&spend.coin_spends, &constants)
   -> your signer signs each reported message
   -> assemble a SpendBundle (coin_spends + aggregated signature)
   -> broadcast
```

`DidSpend { coin_spends: Vec<CoinSpend>, child: Option<Did> }` is the output of every operation:
the unsigned coin spends plus the DID as it will exist after they confirm (`child` is `None` for a
terminal operation such as a melt).

`Owner` says who is authorized to spend a DID:

- `Owner::Standard(PublicKey)` — the standard single-key p2 puzzle; dig-did builds the layer for you.
- `Owner::Custom(Spend)` — you supply an already-built inner spend for any custom p2 puzzle.

---

## Creating a DID

```rust
use dig_did::{create_simple_did, did_string_from_launcher_id, Owner};
use chia_wallet_sdk::driver::SpendContext;

let ctx = &mut SpendContext::new();

// `funding_coin` must be owned by the same key/spend as `owner` (fetched from your own coin store).
let spend = create_simple_did(ctx, funding_coin, Owner::Standard(owner_public_key))?;

let did = spend.child.expect("create always returns a child DID");
println!("minted {}", did_string_from_launcher_id(did.info.launcher_id));

// spend.coin_spends now holds the funding + launcher + settle spends, unsigned (INV-3).
```

`Owner::Custom` works identically — pass a pre-built inner `Spend` for any p2 puzzle instead of a
`PublicKey`, and `create_did`/`create_simple_did`/`create_eve_did_only` build the same shape around it.

---

## The signing boundary

```rust
use dig_did::{required_signatures, AggSigConstants, RequiredSignature};
use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;

// `coin_spends` came from a dig-did operation (e.g. create/update/transfer).
let constants = AggSigConstants::from(&*MAINNET_CONSTANTS);
let required: Vec<RequiredSignature> = required_signatures(&coin_spends, &constants)?;

for sig in &required {
    match sig {
        RequiredSignature::Bls(bls) => {
            let message = bls.message();     // the exact bytes to sign
            let public_key = &bls.public_key; // the key to sign them under
            // your signer produces the BLS signature here — dig-did never does
        }
        RequiredSignature::Secp(_) => { /* handle secp requirements if your p2 uses them */ }
    }
}
```

`required_signatures` runs each coin spend to collect its `AGG_SIG_*` conditions and returns the
precise set — public key, raw message, appended coin/domain info. It is pure and key-free; it never
takes a secret key. Owner operations require `AGG_SIG_ME` (bound to the specific coin), never an
`AGG_SIG_UNSAFE` over caller bytes.

---

## Operation surface

The full DID lifecycle (see [`SPEC.md`](./SPEC.md) §3 for field-level detail). Each operation
returns `Result<DidSpend, DidError>`; a standard-owner operation requires one `AGG_SIG_ME` over the
owner key unless noted.

| Function (module) | Semantics | Signature |
|---|---|---|
| `create_did` | Mint a new DID from a funding coin — launcher + eve DID + owner settle spend, fully wallet-parseable. | 2× `AGG_SIG_ME` (owner: funding-coin spend + settle spend) |
| `create_simple_did` | `create_did` with the common defaults: no recovery list, 1 required verification, nil metadata. | 2× `AGG_SIG_ME` (owner) |
| `create_eve_did_only` | Lower-level: launches the eve DID and stops (no settle spend) — for folding a custom follow-up spend into the same bundle. | 1× `AGG_SIG_ME` (owner) |
| `update` (metadata) | Update DID metadata, recreating the child. | 1× `AGG_SIG_ME` (owner) |
| `update` (settle) | Confirm metadata so wallets can sync it; also emits conditions without transfer. | 1× `AGG_SIG_ME` (owner) |
| `recovery` (set) | Set recovery list hash / required verifications. | 1× `AGG_SIG_ME` (owner) |
| `recovery` (recover) | Rotate owner via recoverer attestations. | per `num_verifications_required` |
| `transfer` | Transfer the DID to a new owner (p2 puzzle hash). | 1× `AGG_SIG_ME` (current owner) |
| `launch` | DID-authorized launch of a child DID / NFT / CHIP-0035 datastore. | 1× `AGG_SIG_ME` (owner) |
| `melt` | Terminate the DID (no successor); `child` is `None`. | 1× `AGG_SIG_ME` (owner) |
| `attest` | Make a signed on-chain announcement as the DID. | 1× `AGG_SIG_ME` (owner) |
| `hydrate_did_from_parent_spend` | Reconstruct the spendable child `Did` created by a parent DID's coin spend (fail-closed). | — |
| `parse_did_coin_spend` | Parse a DID coin's own spend into the `Did` it spent + its p2 `Spend` (or `None` if not a DID). | — |
| `did_info_from_puzzle` | Parse just a puzzle reveal into its `DidInfo`, without a coin or lineage proof. | — |
| `resolve_xch_address` / `resolve_xch_address_from_did_string` | Resolve a DID's CURRENT owner XCH payment `Address` from chain (over a `ChainSource`), authenticating the genuine launcher via the parent-spend walk before returning it — money-critical, fail-closed; `None` if unlaunched/melted. | — (chain read) |
| `prove_lineage` | Prove a coin is rooted in a DID's identity (`Direct` or `LaunchedFrom`), over a `ChainSource` — returns an unforgeable `AncestryProof`; fail-closed. | — (pure verify) |
| `walk_did_lineage_to_tip` | Walk a DID singleton to its current unspent tip (`DidTip { coin, info, proof }`), or `None` if unlaunched/melted. | — |
| `did_string_from_launcher_id` / `launcher_id_from_did_string` | Encode/decode the canonical `did:chia:1…` string (bech32m, byte-agrees with `chia-sdk-utils`). | — |

**Status:** `0.4` adds the **DID→XCH address resolver** (`resolve_xch_address` +
`resolve_xch_address_from_did_string`, [`SPEC.md`](./SPEC.md) §3/§6) and migrates the `ChainSource`
seam onto the canonical **`dig-chainsource-interface`** crate (the one non-drifting trait, re-exported
so the public paths are unchanged). `0.3` added the **lineage-proof spine** — the `ChainSource` seam,
`prove_lineage` + `AncestryProof`, and `walk_did_lineage_to_tip` ([`SPEC.md`](./SPEC.md) §5.1/§10) — on
top of `0.2` (creation + hydration + `did:chia:` codec) and the `0.1` foundation (type surface, error
taxonomy, signing boundary). The remaining operation modules above are declared and specified; each
lands in its own release against this foundation. The table documents the complete designed interface.

---

## Types

- `Did`, `DidInfo` — the DID singleton and its info (re-exported from `chia-wallet-sdk`).
- `DidSpend` — `{ coin_spends, child }`, the unsigned output of every operation.
- `Owner` — `Standard(PublicKey)` | `Custom(Spend)`.
- `DidError` / `DidResult<T>` — the error taxonomy ([`SPEC.md`](./SPEC.md) §6).
- `AggSigConstants`, `RequiredSignature` — re-exported so you can call and consume
  `required_signatures` without a direct chia-wallet-sdk dependency.
- `ChainSource` / `SingletonLineage` — re-exported from the canonical `dig-chainsource-interface` crate:
  the caller-supplied honest chain reader (see [`SPEC.md`](./SPEC.md) §10) + a singleton's lineage
  (membership + tip).
- `Address` — re-exported bech32m address codec (`chia-sdk-utils`), for rendering/decoding a resolved
  XCH payment address.
- `AncestryProof` / `LineageModel` — the unforgeable output of `prove_lineage` (`Direct` | `LaunchedFrom`).
- `DidTip` — a DID singleton's reconstructed current tip.
- `Coin`, `CoinSpend`, `Bytes32`, `Proof`, `LineageProof` — re-exported Chia wire types.

---

## Module map

| Module | Owns |
|---|---|
| `types` | `Did`, `DidInfo`, `DidSpend`, `Owner`, and re-exported wire types. |
| `error` | `DidError`, `DidResult`. |
| `sign` | `required_signatures` — the signing boundary. |
| `create` / `update` / `recovery` / `transfer` / `launch` / `melt` / `attest` | The DID operations. |
| `hydrate` / `resolve` | Reconstruction + projection from chain data. |
| `resolve` | `ChainSource`/`SingletonLineage` re-export, `DidTip`, the singleton-authentication walk, `walk_did_lineage_to_tip`, `resolve_xch_address`(`_from_did_string`), `MAX_LINEAGE_DEPTH`. |
| `lineage` | `prove_lineage`, `AncestryProof`, `LineageModel`. |
| `did_string` | The `did:chia:1…` codec. |

---

## Security

dig-did holds no key and signs nothing (INV-2). Its whole job is to build correct unsigned spends and
tell you exactly what to sign. `AGG_SIG_ME` binds each owner signature to its coin (no replay);
hydration is fail-closed (ambiguous chain data is an error, never a guess). See [`SPEC.md`](./SPEC.md)
§7.

## License

Licensed under either of Apache-2.0 or MIT at your option.
