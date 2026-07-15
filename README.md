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

- **`seller-node-tee-genuine`** — the AntSeed seller NODE's own genuine Intel TDX
  enclave: DCAP-verified quote (ECDSA signature + PCK chain to Intel's root +
  acceptable TCB), TDX (TD10), debug off. Minted locally via `configfs`.
- **`seller-provider-tee-genuine`** — the downstream inference PROVIDER's TDX
  enclave: the same DCAP checks over an independent quote fetched from the
  provider's evidence route. Offered only when a provider evidence URL is configured.
- **`seller-bound`** — the seller signs `keccak256(nonce ‖ bundleDigest ‖ peerId)`
  with its AntSeed identity key, where `bundleDigest` covers EVERY other cap's
  evidence (the node quote AND the provider quote together). The buyer recovers the
  EVM address and requires it to equal the seller's peer id. One seller signature
  therefore binds the whole bundle to this seller and this fresh nonce — *seller*,
  not merely *provider*, verification, even when a quote binds a provider key.
- **`seller-provider-measured-image`** — compares the provider quote's MRTD/RTMR0-3
  to a buyer-supplied approved-measurement allow-list (pure data; never passes
  without a policy).
- **`seller-provider-gpu-cc`** — stub (advertised, not yet implemented; NRAS).

The buyer requires `seller-node-tee-genuine` and `seller-bound`; the rest are
reported informationally. Provider differences are handled only by generic,
config-driven collectors (self-hosted `configfs` TDX, or any `http` attestation
endpoint) — the SDK itself carries no provider-specific hosts or schemas.

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
(`nodeTeeCapability`, `providerTeeCapability`, `sellerBoundCapability`,
`measuredImageCapability`, `gpuNvidiaCapability`); the TDX cap factory (`makeTdxCap`,
`NODE_TEE_CAP_ID`, `PROVIDER_TEE_CAP_ID`); `runVerify`, `defaultVerifyQuote`,
`verifyTdxEvidence`; `VERIFIER_ID`, `ATTEST_PATH`, `claimId`, `computeReportData`,
`bundleDigest`, `sellerBoundPreimage`.

## Requirements

The prover mints the seller node's TDX quote locally through
`/sys/kernel/config/tsm/report` (so `seller-node-tee-genuine` runs only on a real
Intel TDX VM and needs root), and fetches the provider's quote from an HTTP evidence
route when configured. It reads the seller's peer id from `ANTSEED_TEE_PEER_ID` and
its collector/signer config from `ANTSEED_VERIFIER_*`, never from buyer-supplied
values:

- `ANTSEED_VERIFIER_NODE_TEE` — `seller-node-tee-genuine` source; defaults to
  `configfs` when unset.
- `ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL` — the provider's evidence route (a
  `{nonce}` placeholder is substituted with the hex nonce); when set,
  `seller-provider-tee-genuine` is offered via `http`.
- `ANTSEED_VERIFIER_PROVIDER_TEE_FIELD` — the JSON field of that route's response
  holding the base64 provider quote (defaults to `quote`).
- `ANTSEED_VERIFIER_SIGNING_KEY` — the seller identity key (hex) that produces
  `seller-bound` signatures; the cap is disabled if its address != the peer id.

The verifier half has no special hardware requirement.

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
