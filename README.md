# @refoundhq/antseed-verifier

Reference verifier SDK for AntSeed's pluggable verifier system (AIP-3). It lets a
buyer cryptographically attest that a seller node runs inside a genuine Intel TDX
Trusted Execution Environment before routing paid requests to it.

One package, two halves:

- **verifier** (buyer side, the default export) drives an attestation challenge
  against the seller over the existing buyer-to-seller connection and checks the
  returned Intel TDX quote with DCAP.
- **prover** (seller side, the `prover` export) is an embedded `type:'prover'`
  plugin. The seller loads it with `--verifiers refoundhq-antseed-verifier`; the
  node dispatches reserved attestation requests to it before provider matching and
  payment. It is not a provider and stays transparent to the seller's inference
  providers.

It attests a menu of independent **capabilities**, one claim each (namespaced
`refoundhq-antseed-verifier:<capability>`). The seller produces evidence for the
capabilities its infrastructure supports; the buyer verifies each:

- **`tee-tdx-genuine`** — genuine Intel TDX enclave: DCAP-verified quote (ECDSA
  signature + PCK chain to Intel's root + acceptable TCB), TDX (TD10), debug off.
- **`seller-bound`** — the seller signs `keccak256(nonce ‖ sha256(tdx evidence) ‖
  peerId)` with its AntSeed identity key; the buyer recovers the EVM address and
  requires it to equal the seller's peer id. This makes it *seller*, not merely
  *provider*, verification, and works even when the quote binds a provider key.
- **`measured-image`** — compares the quote's MRTD/RTMR0-3 to a buyer-supplied
  approved-measurement allow-list (pure data; never passes without a policy).
- **`gpu-nvidia-cc`** — stub (advertised, not yet implemented; NRAS).

The buyer requires `tee-tdx-genuine` and `seller-bound`; the rest are reported
informationally. Provider differences are handled only by generic, config-driven
collectors (self-hosted `configfs` TDX, or any `http` attestation endpoint) — the
SDK itself carries no provider-specific hosts or schemas.

## Usage

The buyer trusts this SDK through the CLI's curated trust set and selects it per
seller; the seller advertises and serves it via `--verifiers`. See the reference
implementation in the AntSeed monorepo (`feat/antseed-plugins-verifiers`, PR #713)
for the loader, capability advertisement, and buyer policy.

## Exports

```ts
import verifier, { prover } from '@refoundhq/antseed-verifier'
// verifier: default export, type:'verifier' (buyer half)
// prover:   named export, type:'prover'   (seller half)
```

Also exported for tooling and tests: the capability registry (`registerCapability`,
`getCapability`, `listCapabilities`, `capabilityIds`) and the built-in capabilities
(`teeTdxCapability`, `sellerBoundCapability`, `measuredImageCapability`,
`gpuNvidiaCapability`); `runVerify`, `defaultVerifyQuote`, `verifyTdxEvidence`;
`VERIFIER_ID`, `ATTEST_PATH`, `claimId`, `computeReportData`, `sellerBoundPreimage`.

## Requirements

The prover collects a TDX quote via a config-selected source: `configfs` (default;
mints the quote through `/sys/kernel/config/tsm/report`, so it runs only on a real
Intel TDX VM and needs root) or `http` (fetches a pre-made quote from any endpoint
configured by URL + JSON field path). It reads the seller's peer id from
`ANTSEED_TEE_PEER_ID` and its collector/signer config from `ANTSEED_VERIFIER_*`
(`SOURCE`, `URL`, `FIELD`, `METHOD`, `BODY`, and `SIGNING_KEY` — the identity key
that produces `seller-bound` signatures), never from buyer-supplied values. The
verifier half has no special hardware requirement.

## Build and test

```bash
npm install
npm run build
npm test
```

`@antseed/node` is a peer dependency supplied by the AntSeed runtime. For local
development it links from a monorepo checkout beside this repo
(`../antseed-refound/main/packages/node`); adjust the devDependency path if your
layout differs. Once `@antseed/node` is published to npm, the peer dependency
resolves without a local link.

## Status

`v0.1.0`. Validated end to end against real Intel TDX hardware on GCP.

## License

GPL-3.0, matching the AntSeed monorepo.
