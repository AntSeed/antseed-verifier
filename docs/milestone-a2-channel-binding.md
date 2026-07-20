# Milestone A2 — bind attestation to the traffic path (per-response signing)

**Status:** agreed milestone, not yet implemented. This is the single largest gap
between `@antseed/antseed-verifier` and production-grade confidential-inference
verifiers (Tinfoil, NEAR AI, Phala/RedPill).

## The problem

The buyer↔seller channel is **not authenticated to the seller's peerId**. The p2p
connection handshake signs only the *buyer's* identity to the seller; the buyer never
verifies any envelope from the seller. In WebRTC mode the data channel is DTLS with an
**ephemeral self-signed cert whose fingerprint is never bound to the peerId**; in TCP
fallback it is plaintext. `ResponseAuth` exists but is optional and verified *after* the
response is already delivered (non-blocking). So there is **no authenticated channel to
bind attestation to**, and — critically — no TLS key to commit into `report_data`.

Consequence: even with A1 landed (the node quote committing to `nonce‖peerId`), an on-path
MITM answering the connection to peerId X can relay the attestation round to the real
seller, pass it back verbatim, then serve inference itself. Attestation proves state at
attestation time; nothing binds the *bytes the buyer consumes* to the attested enclave.
The verdict is also cached with a TTL while traffic flows, widening the TOCTOU window.

## The fix (no TLS → authenticate the payload, not the channel)

Because there is no channel key to bind, bind a **TEE-generated signing key** into the
attestation and require **every response to be signed by it**. Then a MITM may relay but
cannot forge or substitute: the enclave's signature travels with the bytes.

This is exactly what the sibling **`antseed-tee-seller` Python PoC already implements** and
what this milestone ports into the TS SDK + host:

1. **TEE signing key.** The provider (and/or seller node) generates an Ed25519 keypair
   *inside* the enclave at startup; the private key never leaves the process
   (`attestation/attest_server.py:get_signing_key`).
2. **Key bound into the quote.** The pubkey folds into the canonical provider
   `report_data[0:32]` preimage (this SDK already reserves and domain-separates that half —
   `PROVIDER_REPORT_DATA_DOMAIN`), so the buyer proves the key was generated in the
   attested TEE.
3. **Per-response signing.** The provider signs each response (for streaming SSE: a Merkle
   root over the chunks, plus a trailing `event: signature`), keyed by the TEE key and
   committing to the round nonce + request id (`sidecar/signer.py`, `sidecar/proxy.py`).
4. **Buyer enforcement.** The buyer verifies the signature against the attested key
   **before delivering**, and **fails closed** if it is missing or invalid.

## Deltas

| Layer | Work | Est. |
|-------|------|------|
| SDK | New cap exposing the verified TEE signing key (extend `report_data[0:32]` preimage to include the pubkey; verify + surface it) | ~80 LOC (port from PoC) |
| Host (PR #713) | Buyer proxy verifies a per-response signature from the attested key before delivering; fail-closed | ~150–250 LOC |
| Provider (🔵) | Emit the canonical composite `report_data` (incl. pubkey) + sign responses (the PoC's `attest_server.py` + `sidecar/` already do this; align the `report_data` layout) | port/align |

Reference implementations already exist end-to-end in Python (`antseed-tee-seller/main/`):
`attestation/attest_server.py`, `attestation/verify.py`, `sidecar/signer.py`,
`sidecar/proxy.py`. This milestone is largely a port + host integration, not new design.

## Scope boundary

- **Integrity/authenticity** of responses is closed by signing.
- **Confidentiality vs. an on-path MITM** is NOT — the channel is plaintext-to-MITM in TCP
  mode. Closing that needs E2EE (encrypt to the TEE pubkey, X25519), a separate follow-up
  the PoC explicitly defers.

## Alternative / complement (host-only)

Fixing the p2p handshake so the **buyer verifies a seller intro envelope and binds the
session to peerId** would authenticate the *seller-node* channel (~30–50 LOC in
`connection-manager.ts`). It does NOT cover the downstream **provider** hop (a different
machine reached over plain HTTP), so per-response signing is still required for provider
guarantees. Do both: channel auth for the node, payload signing for the provider.
