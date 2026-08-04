# Chutes

Start the seller with `--verifiers antseed-verifier`.

## Shim

Chutes splits evidence across two Bearer-authed endpoints; run a local shim that joins them:

- `GET /e2e/instances/{chute}` → `e2e_pubkey`
- `GET /chutes/{chute}/evidence?nonce={hex}` → `quote`, `gpu_evidence`

Join by `instance_id`, return one instance flattened at `ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL`.

## Provider config

```bash
export ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL='http://127.0.0.1:9099/evidence?nonce={nonce}'
export ANTSEED_VERIFIER_PROVIDER_TEE_FIELD=quote
export ANTSEED_VERIFIER_PROVIDER_BINDING_SCHEME=nonce-pubkey-sha256-v1
export ANTSEED_VERIFIER_PROVIDER_BINDING_PUBKEY_FIELD=e2e_pubkey
export ANTSEED_VERIFIER_PROVIDER_GPU_FIELD=gpu_evidence   # optional
```

Evidence endpoint response (`{nonce}` is substituted with the hex nonce; field names = the
`*_FIELD` vars, dot-paths ok):

```jsonc
{
  "quote":        "<base64 TDX quote>",
  "e2e_pubkey":   "<base64 provider E2E pubkey>",
  "gpu_evidence": { "arch": "HOPPER", "evidence_list": [ { "evidence": "…", "certificate": "…" } ] },
  "claims":       "<base64 claims doc>"
}
```

## Chutes provider

Identity + provider config, no node quote:

```bash
export ANTSEED_TEE_PEER_ID=<peer id, no 0x>
export ANTSEED_VERIFIER_SIGNING_KEY=<hex key; address == peer id>
# + provider config above
```

Buyers must require the provider cap:

```bash
export ANTSEED_VERIFIER_REQUIRED_CAPS='seller-provider-tee-genuine,seller-bound'
```

## Seller node on Chutes CPU + Chutes provider

Add the node TEE source (match the CVM):

```bash
export ANTSEED_TEE_PEER_ID=<peer id, no 0x>
export ANTSEED_VERIFIER_SIGNING_KEY=<hex key; address == peer id>
export ANTSEED_VERIFIER_NODE_TEE=configfs   # or dstack (see PHALA.md)
# + provider config above
```

Buyers attest with `--require-verifier` (default required caps).
