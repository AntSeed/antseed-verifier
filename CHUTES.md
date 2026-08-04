# Integrating Chutes with AntSeed

Two ways to run a Chutes-backed AntSeed seller with `antseed-verifier`:

- **A — Chutes provider only:** your seller proxies inference to a Chutes chute and proves the
  chute's TEE/GPU. The seller node itself may not be in a TEE. Gives **provenance** (inference
  ran on genuine, round-bound provider hardware), *not* prompt privacy from the seller.
- **B — Chutes CPU + Chutes provider:** the seller node also runs inside a Chutes CPU
  confidential VM, so the node is a TEE too. Gives the **full chain** — confidentiality (TEE
  seller node) *and* provenance (provider TEE) — and passes a default `--require-verifier` buyer.

Both share the same provider wiring (§1); B adds the node-TEE source (§3).

## 1. The provider shim + config (used by A and B)

Chutes splits its evidence across two Bearer-authed endpoints, so run a tiny local shim that
joins them into one response the SDK can fetch:

- `GET /e2e/instances/{chute}` → instances + `e2e_pubkey`
- `GET /chutes/{chute}/evidence?nonce={hex}` → per-instance `quote` + `gpu_evidence`

The shim joins them by `instance_id` and returns **one instance flattened**. Point the SDK at it:

```bash
# shim needs a Chutes API key (→ https://api.chutes.ai)
export ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL='http://127.0.0.1:9099/evidence?nonce={nonce}'
export ANTSEED_VERIFIER_PROVIDER_TEE_FIELD=quote
export ANTSEED_VERIFIER_PROVIDER_BINDING_SCHEME=nonce-pubkey-sha256-v1
export ANTSEED_VERIFIER_PROVIDER_BINDING_PUBKEY_FIELD=e2e_pubkey
export ANTSEED_VERIFIER_PROVIDER_GPU_FIELD=gpu_evidence   # optional: enable gpu-cc
```

Chutes binds its quote with `nonce-pubkey-sha256-v1` = `SHA-256(nonce_hex ‖ e2e_pubkey_b64)`,
so the buyer confirms the quote is genuine TDX **and** bound to this round + instance. Validated
against live Chutes + real hardware; full flow in [docs/e2e-report-data-schemes.md](./docs/e2e-report-data-schemes.md).

### Evidence-endpoint contract

Any adapter (Chutes shim or another platform) speaks this contract. The SDK substitutes
`{nonce}` with the 64-char lowercase-hex nonce and `GET`s the URL; the response is JSON:

```jsonc
{
  "quote":        "<base64 TDX quote>",              // → ANTSEED_VERIFIER_PROVIDER_TEE_FIELD
  "e2e_pubkey":   "<base64 provider E2E pubkey>",    // → ANTSEED_VERIFIER_PROVIDER_BINDING_PUBKEY_FIELD
  "gpu_evidence": { "arch": "HOPPER", "evidence_list": [ { "evidence": "…", "certificate": "…" } ] }, // optional
  "claims":       "<base64 claims doc>"              // optional → ANTSEED_VERIFIER_PROVIDER_CLAIMS_FIELD
}
```

Field names are whatever you set the `*_FIELD` vars to (dot-paths like `data.quote` work). The
provider quote must commit `report_data[0:32] = SHA-256(nonce_hex ‖ e2e_pubkey_b64)` for the
round binding to verify.

## 2. Path A — Chutes provider only

Set your identity + the §1 provider config, then start the seller (`--verifiers antseed-verifier`):

```bash
export ANTSEED_TEE_PEER_ID=<peer id, no 0x>
export ANTSEED_VERIFIER_SIGNING_KEY=<hex key; address == peer id>
# + the §1 provider vars
# do NOT set ANTSEED_VERIFIER_NODE_TEE — off-TEE it can't mint a node quote, and the cap is omitted
```

The seller proves `seller-provider-tee-genuine` (+ `-gpu-cc`) and `seller-bound` (which binds the
provider evidence to your identity + the fresh nonce). `seller-node-tee-genuine` is absent.

**How buyers see it:** provider caps are *informational* by default, so a buyer with the default
required set (`seller-node-tee-genuine,seller-bound`) and `--require-verifier` will **not** route
here yet. A buyer who explicitly wants provider provenance opts in:

```bash
# buyer side
export ANTSEED_VERIFIER_REQUIRED_CAPS='seller-provider-tee-genuine,seller-bound'
```

⚠️ This enforces that the **provider** is genuine TEE — it does **not** mean the seller kept the
prompt private, because a non-TEE seller node still sees plaintext. It's provenance, not
confidentiality. For confidentiality, use Path B.

## 3. Path B — Chutes CPU (TEE seller node) + Chutes provider

Run the seller node inside a Chutes CPU confidential VM, so it mints its **own** node quote, and
keep the §1 provider config. Choose the node source to match the CPU CVM's quoting interface:

```bash
export ANTSEED_TEE_PEER_ID=<peer id, no 0x>
export ANTSEED_VERIFIER_SIGNING_KEY=<hex key; address == peer id>

# node TEE — pick ONE to match the CVM:
export ANTSEED_VERIFIER_NODE_TEE=configfs   # raw Intel TDX guest (/sys/kernel/config/tsm, needs root)
# export ANTSEED_VERIFIER_NODE_TEE=dstack   # if the CPU CVM is a dstack guest (see PHALA.md)

# + the §1 provider vars
```

Now the seller proves the **full chain**: `seller-node-tee-genuine` + `seller-provider-tee-genuine`
(+ `-gpu-cc`) + `seller-bound`. A default `--require-verifier` buyer routes here with no extra
config — the required `seller-node-tee-genuine` is satisfied by the TEE seller node, and the
provider caps are reported as informational (or a buyer can add them to `ANTSEED_VERIFIER_REQUIRED_CAPS`
to require both).

## Which path

| | Seller node | Guarantee to buyer | Default `--require-verifier` routes? |
|---|---|---|---|
| **A** provider only | not a TEE | provider provenance | no (needs `ANTSEED_VERIFIER_REQUIRED_CAPS`) |
| **B** CPU + provider | TEE (Chutes CPU) | confidentiality + provenance | yes |

Start with A to advertise provider capabilities immediately; move to B once the seller node runs
on Chutes CPU to close the confidentiality gap.
