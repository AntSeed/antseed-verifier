# @antseed/antseed-verifier

Reference verifier SDK for AntSeed's pluggable verifier system (AIP-3). It lets a
buyer cryptographically attest that a seller node runs inside a genuine Intel TDX
Trusted Execution Environment before routing paid requests to it.

One package, two halves:

- **verifier** (buyer side, the default export) drives an attestation challenge
  against the seller over the existing buyer-to-seller connection and checks the
  returned Intel TDX quote with DCAP.
- **prover** (seller side, the `prover` export) is an embedded `type:'prover'`
  plugin. The seller loads it with `--verifiers antseed-verifier`; the
  node dispatches reserved attestation requests to it before provider matching and
  payment. It is not a provider and stays transparent to the seller's inference
  providers.

It attests a menu of independent **capabilities**, one claim each (namespaced
`antseed-verifier:<capability>`). The seller produces evidence for the
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
- **`seller-provider-gpu-cc`** — proves the provider's GPUs run NVIDIA Confidential
  Computing. The buyer submits the provider's per-GPU CC evidence + the round nonce to
  NVIDIA's Remote Attestation Service (NRAS) and verifies the returned EAR (signed JWT):
  signature valid against NVIDIA's JWKS, overall result success, CC mode, nonce bound to
  this round. The buyer-side check is an injectable `GpuVerifyFn` (default NRAS), so an
  offline verifier drops in with no cap change — reserve `ANTSEED_VERIFIER_GPU_MODE=local`
  (not yet built). Informational, never required (a CPU-only seller still verifies).
- **`seller-provider-claims`** — carries the provider's claims into the protocol with
  per-claim granularity: one claim per entry
  (`antseed-verifier:seller-provider-claims/<name>`), so buyer policy can act on
  individual guarantees. The claims menu is **frozen in the SDK** (`PROVIDER_CLAIMS_MENU`),
  never supplied by the seller or provider and version-pinned through the CLI's trust
  registry, so every buyer runs identical verification; names outside the menu can never
  pass, and growing it is an SDK version bump. The provider's document supplies VALUES only
  (provider-authored bytes, carried verbatim):

  ```json
  { "version": 1, "claims": { "<name>": <value> } }
  ```

  Frozen proof levels: `asserted` (may pass on whole-bundle `seller-bound` integrity alone —
  reported as "provider-asserted only, NOT independently verified") and `tdx-quote` (passes
  ONLY when the provider's DCAP-verified TDX quote commits to the exact document in its
  `report_data`; a bound document upgrades asserted-level claims to TEE-attested too). v0.1
  menu: `model-id` (asserted) and `serving-image-digest` (tdx-quote). Informational, never
  required.

  The provider quote uses ONE canonical 64-byte `report_data` layout (domain-separated,
  so a single provider quote serves every provider cap at once):

  ```
  report_data[ 0:32] = SHA-256( "antseed-provider-report-data-v1" ‖ nonce ‖ SHA-256(claimsDocBytes) )
  report_data[32:64] = reserved   // gpu-cc binds the GPU independently via the NRAS nonce
  ```

  `claimsReportData(nonce, docBytes)` returns the 32-byte `[0:32]` commitment; the buyer
  compares it against the provider quote's first half. (The node cap uses the separate
  `antseed-rd-v1` `{peerId}` binding — see below — as it binds identity, not a payload.)

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
import verifier, { prover } from '@antseed/antseed-verifier'
// verifier: default export, type:'verifier' (buyer half)
// prover:   named export, type:'prover'   (seller half)
```

Also exported for tooling and tests: the capability registry (`registerCapability`,
`getCapability`, `listCapabilities`, `capabilityIds`) and the built-in capabilities
(`nodeTeeCapability`, `providerTeeCapability`, `sellerBoundCapability`,
`measuredImageCapability`, `gpuNvidiaCapability`, `providerClaimsCapability`);
the provider-claims surface (`PROVIDER_CLAIMS_CAP_ID`, `claimsConfigKey`,
`claimsReportData`); the TDX cap factory (`makeTdxCap`,
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
- `ANTSEED_VERIFIER_PROVIDER_GPU_FIELD` — the JSON field holding the provider's per-GPU
  NVIDIA CC evidence; when set (with the evidence URL), `seller-provider-gpu-cc` is offered
  off the same route.
- `ANTSEED_VERIFIER_PROVIDER_CLAIMS_FIELD` — the JSON field of that route's response
  holding the base64 provider claims document; when set (with the evidence URL),
  `seller-provider-claims` is offered off the same route.
- `ANTSEED_VERIFIER_PROVIDER_BINDING_SCHEME` — the frozen `report_data` scheme the
  provider's quote uses (`antseed-rd-v1`, or `nonce-pubkey-sha256-v1` for a Chutes-style
  E2E provider). When set, the buyer verifies the provider quote is bound to this round.
- `ANTSEED_VERIFIER_PROVIDER_BINDING_PUBKEY_FIELD` — the JSON field holding the provider's
  base64 E2E public key, the ingredient the scheme binds.
- `ANTSEED_VERIFIER_SIGNING_KEY` — the seller identity key (hex) that produces
  `seller-bound` signatures; the cap is disabled if its address != the peer id.

The verifier (buyer) half has no special hardware requirement, and reads a few optional
policy knobs from the environment:

- `ANTSEED_VERIFIER_MEASURED_IMAGE_POLICY` — the `seller-provider-measured-image`
  allow-list, as inline JSON (`{"approvedMeasurements":[{"mrtd":"…"}]}`) or `@/path.json`.
  Without it the cap reports `ok:false` ("no approved measurement set configured").
- `ANTSEED_VERIFIER_STRICT_TCB` — set to `true` to require TCB status exactly `UpToDate`
  (rejecting `SWHardeningNeeded`). Default accepts both.
- `ANTSEED_VERIFIER_NRAS_URL` / `ANTSEED_VERIFIER_NRAS_JWKS_URL` — override NVIDIA's NRAS
  attest + JWKS endpoints used by `seller-provider-gpu-cc` (default to NVIDIA's production URLs).

### report_data binding schemes

A TDX quote has one 64-byte `report_data`; how a provider commits this round's freshness
(and any TEE-bound key) into it varies by stack. The SDK verifies against a **frozen,
version-pinned registry** of schemes (`src/report-data.ts`) — a provider *selects* one by id,
never defines one:

- **`antseed-rd-v1`** — our canonical, *compositional* scheme: the nonce is always bound, and
  optional fields (`peerId`, `e2ePubkey`, …) are included iff present, each domain-tagged and
  length-prefixed. One rule covers every combination, and the seller **node** cap is simply its
  `{peerId}` instance — so a genuine-but-borrowed or replayed quote cannot satisfy the required
  `seller-node-tee-genuine` cap.
- **`nonce-pubkey-sha256-v1`** — the foreign Chutes construction
  (`SHA-256(nonce_hex ‖ e2ePubkey_b64)`), replicated only so the buyer can verify a quote
  Chutes minted. Opt-in per provider via `ANTSEED_VERIFIER_PROVIDER_BINDING_SCHEME`.

The same builder runs on the prover (to mint) and the buyer (to recompute), and because the
nonce is always bound, a mis-declared or downgraded field set can only fail — never falsely
pass. See `docs/e2e-report-data-schemes.md` for the end-to-end test flows (standard + Chutes).

## Build and test

```bash
npm install
npm run build
npm test
```

The package is self-contained — no peer dependencies. The AntSeed plugin contract it
implements is vendored (`src/antseed-node-types.ts`) and re-exported, so consumers build
against this package alone; the AntSeed runtime loads the plugin structurally.

## Status

`v0.1.0`. Validated end to end against real Intel TDX hardware on GCP.

## License

GPL-3.0, matching the AntSeed monorepo.
