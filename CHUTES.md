# Chutes

Start the seller with `--verifiers antseed-verifier`.

## Adapter

Chutes' evidence endpoint is Bearer-authed and returns an array of instances, so the SDK can't
fetch it directly. Run the bundled adapter next to the seller node — it adds auth, picks an
instance, and serves the SDK's evidence shape on localhost:

```bash
export CHUTES_API_KEY=<chutes api key>
export CHUTES_CHUTE=<chute id>
node adapters/chutes/chutes-adapter.mjs      # → http://127.0.0.1:9099/evidence?nonce={hex}
```

## Provider config

```bash
export ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL='http://127.0.0.1:9099/evidence?nonce={nonce}'
export ANTSEED_VERIFIER_PROVIDER_TEE_FIELD=quote
export ANTSEED_VERIFIER_PROVIDER_BINDING_SCHEME=nonce-pubkey-sha256-v1
export ANTSEED_VERIFIER_PROVIDER_BINDING_PUBKEY_FIELD=e2e_pubkey
```

## Chutes provider

Identity + adapter + provider config, no node quote:

```bash
export ANTSEED_TEE_PEER_ID=<peer id, no 0x>
export ANTSEED_VERIFIER_SIGNING_KEY=<hex key; address == peer id>
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
```

Buyers attest with `--require-verifier` (default required caps).
