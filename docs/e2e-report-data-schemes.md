# E2E: report_data schemes — standard flow and Chutes-provider flow

Both flows use ONE test seller node (a GCP `c3` Intel TDX VM) and ONE buyer. They differ
only in the **provider**: the standard flow uses a provider stand-in that mints our canonical
`antseed-rd-v1` binding; the Chutes flow points the same seller at a live Chutes chute using
the foreign `nonce-pubkey-sha256-v1` binding. Nothing in the SDK is provider-specific — the
only difference is config.

What's verified where:
- `seller-node-tee-genuine` — the seller node's own configfs quote, now bound via
  **`antseed-rd-v1` `{peerId}`** (validated on real TDX hardware: the configfs quote's
  report_data equals `antseedRdV1.build(nonce, {peerId})`, DCAP `UpToDate`).
- `seller-bound` — the seller signs the bundle; buyer recovers peerId.
- `seller-provider-tee-genuine` — the provider quote, verified against its **declared frozen
  scheme** (`antseed-rd-v1` for the stand-in, `nonce-pubkey-sha256-v1` for Chutes). This is
  the new machinery (`src/report-data.ts` + the provider cap binding check).
- `seller-provider-measured-image` — MRTD/RTMR vs a buyer allow-list (env policy, A5).
- `seller-provider-gpu-cc` — NRAS; see the GPU caveat under the Chutes flow.

Provision + stage the seller/buyer exactly as `docs/e2e-caps.md` describes (c3 TDX VM,
`npm pack` the SDK into `~/.antseed-seller/plugins`, run seller as root). Below covers only
the provider wiring that's new.

---

## Standard flow — provider stand-in minting `antseed-rd-v1`

A tiny provider that generates a key inside the (same) TDX VM, mints a quote bound to
`antseed-rd-v1 {e2ePubkey}`, and serves `{quote, e2e_pubkey}`. Run it on the seller VM
(`:9000`). It imports the SDK's own exports so the bytes match the buyer's recompute exactly:

```js
// provider-standin.mjs  — run with:  sudo node provider-standin.mjs   (configfs needs root)
import { createServer } from 'node:http'
import { generateKeyPairSync } from 'node:crypto'
import { antseedRdV1 } from '@refoundhq/antseed-verifier'
import { generateTdxQuote } from '@refoundhq/antseed-verifier/dist/collect/configfs.js'

// One TEE-generated key for this instance; its pubkey is bound into report_data.
const { publicKey } = generateKeyPairSync('ed25519')
const e2ePubkey = publicKey.export({ type: 'spki', format: 'der' }).toString('base64')

createServer((req, res) => {
  const nonceHex = new URL(req.url, 'http://x').searchParams.get('nonce')
  const nonce = Buffer.from(nonceHex, 'hex')
  const reportData = antseedRdV1.build(nonce, { e2ePubkey })   // SAME builder the buyer uses
  const quote = generateTdxQuote(reportData)                    // configfs-tsm, 64-byte report_data
  res.setHeader('content-type', 'application/json')
  res.end(JSON.stringify({ quote: Buffer.from(quote).toString('base64'), e2e_pubkey: e2ePubkey }))
}).listen(9000)
```

Seller env (adds two lines to the `docs/e2e-caps.md` config):

```bash
export ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL='http://127.0.0.1:9000/evidence?nonce={nonce}'
export ANTSEED_VERIFIER_PROVIDER_TEE_FIELD=quote
export ANTSEED_VERIFIER_PROVIDER_BINDING_SCHEME=antseed-rd-v1          # NEW: declare the scheme
export ANTSEED_VERIFIER_PROVIDER_BINDING_PUBKEY_FIELD=e2e_pubkey       # NEW: the pubkey ingredient
```

Run the buyer (`--require-verifier --verifiers refoundhq-antseed-verifier --peer <SELLER_PEER_ID>`).
Expected verdict:
- `seller-node-tee-genuine` PASS — antseed-rd-v1 `{peerId}` binding matches this round.
- `seller-bound` PASS.
- `seller-provider-tee-genuine` PASS — the provider quote's report_data equals
  `antseed-rd-v1 {e2ePubkey}` for this nonce. Flip one byte of the stand-in's pubkey and it
  must fail with `report_data does not match scheme "antseed-rd-v1"`.

This exercises the full new path on real hardware, provider-neutrally: the stand-in is just
"a provider that adopted our canonical scheme."

---

## Chutes flow — a live Chutes chute as the provider

Chutes' evidence endpoint is Bearer-authed, returns an **array** of instances, and binds
`report_data[0:32] = SHA-256(nonce_hex ‖ e2e_pubkey_b64)` — the frozen
`nonce-pubkey-sha256-v1` scheme (verified from their `chutes-api` docs/code). Two prerequisites
the SDK does not do itself, both handled by a tiny local shim (no SDK change, no Chutes code):

1. **Auth + instance selection.** Run a local reverse proxy on `:9000` that adds
   `Authorization: Bearer $CHUTES_API_KEY`, forwards `?nonce=` to
   `GET https://api.chutes.ai/chutes/{chute}/evidence?nonce={nonce}`, and returns **one**
   instance object (e.g. `body[0]`) flattened to `{quote, e2e_pubkey}`. ~20 lines of Node.
2. **GPU nonce (only if testing gpu-cc).** See the caveat below — needs one probe first.

Seller env (identical shape to the standard flow — only the scheme id + URL differ):

```bash
export ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL='http://127.0.0.1:9000/evidence?nonce={nonce}'  # local shim → Chutes
export ANTSEED_VERIFIER_PROVIDER_TEE_FIELD=quote
export ANTSEED_VERIFIER_PROVIDER_BINDING_SCHEME=nonce-pubkey-sha256-v1   # the ONLY real difference
export ANTSEED_VERIFIER_PROVIDER_BINDING_PUBKEY_FIELD=e2e_pubkey
```

Run the buyer as before. Expected:
- `seller-node-tee-genuine`, `seller-bound` PASS (unchanged — this is our seller node).
- `seller-provider-tee-genuine` PASS — the **Chutes** quote's report_data equals
  `SHA-256(nonce_hex ‖ e2e_pubkey_b64)` for this round. This proves, generically, that the
  Chutes instance minted a fresh quote for our nonce and that its E2E pubkey is enclave-born.
- `seller-provider-measured-image` — set `ANTSEED_VERIFIER_MEASURED_IMAGE_POLICY` to Chutes'
  published reference measurements to PASS; otherwise reports "no approved measurement set".

The seller config is byte-for-byte the standard flow except `BINDING_SCHEME` and the URL —
that's the whole point: swapping providers is config, and each provider's binding is a frozen
registry entry the buyer verifies, not provider-specific SDK code.

### GPU-CC caveat (must confirm before trusting a pass)

`seller-provider-gpu-cc` submits an NRAS nonce and checks `eat_nonce`. Chutes very likely
binds the GPU to the **derived** `SHA-256(nonce‖pubkey)` (= `noncePubkeySha256V1.gpuNonce`),
not the raw nonce. Two steps to turn it on:
1. **Probe once** (needs the Chutes key): fetch evidence for a known nonce, submit the GPU
   evidence to NRAS with (a) the raw nonce and (b) the derived value, see which `eat_nonce`
   NRAS echoes. This is a ~15-line script, no GPU rented.
2. **Wire** `gpu-cc` to use `scheme.gpuNonce(nonce, {e2ePubkey})` when a provider binding
   scheme is configured (today it always submits the raw nonce). Small, but land it only
   after the probe confirms the value — otherwise a pass/fail would be meaningless.

Until then, run the Chutes flow for provider-TEE + measured-image (both real, no GPU), and
treat gpu-cc as pending the probe.

---

## What's verified vs. documented

- **Unit-verified (140 tests):** the `report-data.ts` schemes, node convergence to
  `antseed-rd-v1 {peerId}`, and the provider cap's scheme-binding check (pass + fail-closed).
- **Hardware-verified:** the node configfs quote's report_data equals our computed 64 bytes and
  DCAP-verifies (construction-agnostic, so it holds for `antseed-rd-v1`).
- **Documented, not yet run this session:** the provider stand-in on a live VM, the Chutes
  auth/instance shim, and the gpu-cc probe (needs a Chutes API key).
