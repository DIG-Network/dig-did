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
dig-did = "0.1"
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
| `create` | Mint a new DID from a funding coin (launcher + eve + first update). | 1× `AGG_SIG_ME` (owner) |
| `update` (metadata) | Update DID metadata, recreating the child. | 1× `AGG_SIG_ME` (owner) |
| `update` (settle) | Confirm metadata so wallets can sync it; also emits conditions without transfer. | 1× `AGG_SIG_ME` (owner) |
| `recovery` (set) | Set recovery list hash / required verifications. | 1× `AGG_SIG_ME` (owner) |
| `recovery` (recover) | Rotate owner via recoverer attestations. | per `num_verifications_required` |
| `transfer` | Transfer the DID to a new owner (p2 puzzle hash). | 1× `AGG_SIG_ME` (current owner) |
| `launch` | DID-authorized launch of a child DID / NFT / CHIP-0035 datastore. | 1× `AGG_SIG_ME` (owner) |
| `melt` | Terminate the DID (no successor); `child` is `None`. | 1× `AGG_SIG_ME` (owner) |
| `attest` | Make a signed on-chain announcement as the DID. | 1× `AGG_SIG_ME` (owner) |
| `hydrate` | Reconstruct a spendable `Did` from a parent coin spend (fail-closed). | — |
| `resolve` | Project a DID's current state / DID document. | — |
| `did_string` | Encode/decode the canonical `did:chia:1…` string (bech32m). | — |

**Status:** this is the `0.1` foundation — the type surface, the error taxonomy, and the signing
boundary (`required_signatures`) are shipped and tested. The operation modules above are declared and
specified; each lands in its own release against this foundation. The table documents the complete
designed interface.

---

## Types

- `Did`, `DidInfo` — the DID singleton and its info (re-exported from `chia-wallet-sdk`).
- `DidSpend` — `{ coin_spends, child }`, the unsigned output of every operation.
- `Owner` — `Standard(PublicKey)` | `Custom(Spend)`.
- `DidError` / `DidResult<T>` — the error taxonomy ([`SPEC.md`](./SPEC.md) §6).
- `AggSigConstants`, `RequiredSignature` — re-exported so you can call and consume
  `required_signatures` without a direct chia-wallet-sdk dependency.
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
| `did_string` | The `did:chia:1…` codec. |

---

## Security

dig-did holds no key and signs nothing (INV-2). Its whole job is to build correct unsigned spends and
tell you exactly what to sign. `AGG_SIG_ME` binds each owner signature to its coin (no replay);
hydration is fail-closed (ambiguous chain data is an error, never a guess). See [`SPEC.md`](./SPEC.md)
§7.

## License

Licensed under either of Apache-2.0 or MIT at your option.
