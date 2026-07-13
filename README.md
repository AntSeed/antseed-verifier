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

It attests a single claim: `refoundhq-antseed-verifier:hardware-genuine` — the
seller is a real TDX VM and the quote's report data binds the quote to that
seller's peer id (`SHA-512(nonce ‖ peerId)`).

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

Also exported for tooling and tests: `runVerify`, `defaultVerifyQuote`,
`VERIFIER_ID`, `ATTEST_PATH`, `CLAIM_HARDWARE_GENUINE`, `computeReportData`.

## Requirements

The prover generates TDX quotes through configfs-tsm, so it runs only on a real
Intel TDX VM and needs root (the `/sys/kernel/config/tsm/report` files are
root-owned). It reads the seller's peer id from `ANTSEED_TEE_PEER_ID`, set by the
operator or launcher, never from a buyer-supplied value. The verifier half has no
special hardware requirement.

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
