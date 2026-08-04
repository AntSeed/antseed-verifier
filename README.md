# @antseed/antseed-verifier

Verifier SDK for AntSeed's pluggable verifier system (AIP-3). One package, two halves: a
**buyer verifier** (default export) that challenges a seller and checks its Intel TDX
attestation before routing paid requests, and an embedded **seller prover** (`prover` export,
loaded with `--verifiers antseed-verifier`) that answers those challenges before provider
matching and payment.

```ts
import verifier, { prover } from '@antseed/antseed-verifier'
// verifier → default export (type:'verifier', buyer half)
// prover   → named export   (type:'prover',  seller half)
```

It attests a menu of independent **capabilities**, one claim each, namespaced
`antseed-verifier:<capability>`. The seller offers only the caps its infrastructure supports;
the buyer's verdict gates on two and reports the rest for policy. Provider differences are
config only (generic `configfs` or `http` collectors) — the SDK carries no provider-specific
hosts or schemas, and is self-contained (no peer dependencies).

## Capabilities

| Capability | Proves | Verdict |
|---|---|---|
| `seller-node-tee-genuine` | the seller **node** runs in a genuine Intel TDX enclave (DCAP: PCK chain to Intel's root, acceptable TCB, TD10, debug off), its quote bound to this nonce + peerId | **required** |
| `seller-bound` | the seller's identity key signed the whole evidence bundle for this fresh nonce (signer recovers to peerId) | **required** |
| `seller-provider-tee-genuine` | the downstream inference **provider's** TEE is genuine TDX; also round-bound when a `report_data` scheme is declared | informational |
| `seller-provider-gpu-cc` | the provider's GPUs run NVIDIA Confidential Computing (verified via NVIDIA NRAS, nonce-bound) | informational |
| `seller-provider-measured-image` | the provider quote's MRTD/RTMR match a buyer allow-list | informational |
| `seller-provider-claims` | named provider claims against a frozen SDK menu; each `asserted` (self-vouched) or `tdx-quote` (TEE-attested) | informational |

The two required caps together prove: *a genuine Intel TDX seller node, minted fresh this
round and cryptographically tied to the seller's marketplace identity.*

## Params

The **prover** (seller) reads its config from the environment, never from buyer-supplied values:

| Variable | Purpose |
|---|---|
| `ANTSEED_TEE_PEER_ID` | the seller's peer id (EVM address, no `0x`) |
| `ANTSEED_VERIFIER_SIGNING_KEY` | seller identity key (hex) for `seller-bound`; disabled if its address ≠ peerId |
| `ANTSEED_VERIFIER_NODE_TEE` | node quote source: `configfs` (default; bare-metal/GCP TDX), `dstack` (Phala & other dstack CVMs), or `http` |
| `ANTSEED_VERIFIER_DSTACK_SOCKET` | override the dstack guest-agent socket path (default `/var/run/dstack.sock`) |
| `ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL` | provider evidence route (`{nonce}` → hex nonce); enables the provider caps |
| `ANTSEED_VERIFIER_PROVIDER_TEE_FIELD` | JSON field with the base64 provider quote (default `quote`) |
| `ANTSEED_VERIFIER_PROVIDER_GPU_FIELD` | JSON field with per-GPU NVIDIA CC evidence → enables `seller-provider-gpu-cc` |
| `ANTSEED_VERIFIER_PROVIDER_CLAIMS_FIELD` | JSON field with the base64 claims doc → enables `seller-provider-claims` |
| `ANTSEED_VERIFIER_PROVIDER_BINDING_SCHEME` | frozen `report_data` scheme the provider quote uses (`antseed-rd-v1` \| `nonce-pubkey-sha256-v1`) |
| `ANTSEED_VERIFIER_PROVIDER_BINDING_PUBKEY_FIELD` | JSON field with the provider's base64 E2E pubkey (the scheme's ingredient) |

The **buyer** needs no special hardware; optional policy knobs:

| Variable | Purpose |
|---|---|
| `ANTSEED_VERIFIER_REQUIRED_CAPS` | comma-separated caps that gate the overall `ok` (default `seller-node-tee-genuine,seller-bound`); e.g. a provenance buyer sets `seller-provider-tee-genuine,seller-bound` to require the downstream provider's TEE |
| `ANTSEED_VERIFIER_MEASURED_IMAGE_POLICY` | approved-measurement allow-list (inline JSON or `@/path.json`) for `measured-image` |
| `ANTSEED_VERIFIER_STRICT_TCB` | `true` requires TCB exactly `UpToDate` (default also accepts `SWHardeningNeeded`) |
| `ANTSEED_VERIFIER_NRAS_URL` / `_NRAS_JWKS_URL` | override NVIDIA NRAS endpoints for `gpu-cc` |

`seller-node-tee-genuine` runs only on a real Intel TDX VM. `configfs` mints via
`/sys/kernel/config/tsm/report` (needs root); `dstack` mints via the guest-agent socket
(Phala & other dstack CVMs, where configfs-tsm is absent). Both bind the same `antseed-rd-v1`
report_data, so the buyer verifies them identically.

## Appendix — using a Chutes provider

Point the seller at a [Chutes](https://chutes.ai) chute as the inference provider — config
only, no code change. Chutes binds its quote with the `nonce-pubkey-sha256-v1` scheme and
splits the quote and the E2E pubkey across two Bearer-authed endpoints, so run a small shim
that joins them into one `{quote, e2e_pubkey, gpu_evidence}` response, then:

```bash
# shim (needs a Chutes API key) → https://api.chutes.ai
export ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL='http://127.0.0.1:9099/evidence?nonce={nonce}'
export ANTSEED_VERIFIER_PROVIDER_TEE_FIELD=quote
export ANTSEED_VERIFIER_PROVIDER_BINDING_SCHEME=nonce-pubkey-sha256-v1
export ANTSEED_VERIFIER_PROVIDER_BINDING_PUBKEY_FIELD=e2e_pubkey
export ANTSEED_VERIFIER_PROVIDER_GPU_FIELD=gpu_evidence   # optional: enable gpu-cc
```

The shim fetches `GET /e2e/instances/{chute}` (instances + `e2e_pubkey`) and
`GET /chutes/{chute}/evidence?nonce={hex}` (per-instance `quote` + `gpu_evidence`), joins them
by `instance_id`, and returns one instance flattened. The buyer then verifies the Chutes quote
is genuine TDX and bound to this round via `nonce-pubkey-sha256-v1`. Validated against live
Chutes + real Intel TDX hardware; see `docs/e2e-report-data-schemes.md` for the full flow.

---

`v0.1.0` · GPL-3.0
