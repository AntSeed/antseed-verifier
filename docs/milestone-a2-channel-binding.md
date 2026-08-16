# Milestone A2 — bind attestation to the traffic path (per-response signing)

**Status:** not implemented yet. This is the single largest gap
between `@antseed/antseed-verifier` and production-grade confidential-inference
verifiers (Tinfoil, NEAR AI, Phala/RedPill).

## The problem

The buyer↔seller channel is **not authenticated to the seller's peerId**. The p2p
connection handshake signs only the *buyer's* identity to the seller. The buyer never
verifies any envelope from the seller. In WebRTC mode the data channel is DTLS with an
**ephemeral self-signed cert whose fingerprint is never bound to the peerId**. In TCP
fallback it is plaintext. `ResponseAuth` exists, but it is optional and the buyer verifies it
*after* the response is already delivered (non-blocking). So there is **no authenticated channel
to bind attestation to**. There is also no TLS key to commit into `report_data`.

Consequence: even with A1 in place (the node quote commits to `nonce‖peerId`), an on-path
MITM can answer the connection to peerId X. The MITM relays the attestation round to the real
seller, passes it back verbatim, then serves inference itself. Attestation proves state at
attestation time. Nothing binds the *bytes the buyer consumes* to the attested enclave.
The SDK also caches the verdict with a TTL while traffic flows, which widens the TOCTOU window.

## The fix (no TLS → authenticate the payload, not the channel)

There is no channel key to bind. So bind a **TEE-generated signing key** into the
attestation and require the enclave to sign **every response** with it. Then a MITM can relay,
but it cannot forge or substitute: the enclave's signature travels with the bytes.

The sibling **`antseed-tee-seller` Python PoC already implements this**. This milestone ports it
into the TS SDK and host:

1. **TEE signing key.** The provider (and/or seller node) generates an Ed25519 keypair
   *inside* the enclave at startup. The private key never leaves the process
   (`attestation/attest_server.py:get_signing_key`).
2. **Key bound into the quote.** The pubkey folds into the canonical provider
   `report_data[0:32]` preimage. This SDK already reserves and domain-separates that half
   (`PROVIDER_REPORT_DATA_DOMAIN`). So the buyer proves the key comes from the attested TEE.
3. **Per-response signing.** The provider signs each response with the TEE key (for streaming
   SSE: a Merkle root over the chunks, plus a trailing `event: signature`). Each signature
   commits to the round nonce and request id (`sidecar/signer.py`, `sidecar/proxy.py`).
4. **Buyer enforcement.** The buyer verifies the signature against the attested key
   **before it delivers the response**. It **fails closed** if the signature is missing or invalid.

## Deltas

| Layer | Work | Est. |
|-------|------|------|
| SDK | A capability that exposes the verified TEE signing key (extend the `report_data[0:32]` preimage to include the pubkey; verify and surface it) | ~80 LOC (port from PoC) |
| Host | The buyer proxy verifies a per-response signature from the attested key before it delivers; fail-closed | ~150–250 LOC |
| Provider (🔵) | Emit the canonical composite `report_data` (incl. pubkey) and sign responses (the PoC's `attest_server.py` and `sidecar/` already do this; align the `report_data` layout) | port/align |

Reference implementations already exist end-to-end in Python (`antseed-tee-seller/main/`):
`attestation/attest_server.py`, `attestation/verify.py`, `sidecar/signer.py`,
`sidecar/proxy.py`. This milestone is mostly a port and host integration, not new design.

## Scope boundary

- Signing closes the **integrity and authenticity** of responses.
- It does NOT close **confidentiality against an on-path MITM**. The channel is plaintext-to-MITM
  in TCP mode. To close that needs E2EE (encrypt to the TEE pubkey, X25519), a separate follow-up
  that the PoC defers.

## Alternative / complement (host-only)

Fix the p2p handshake so the **buyer verifies a seller intro envelope and binds the
session to peerId**. This authenticates the *seller-node* channel (~30–50 LOC in
`connection-manager.ts`). It does NOT cover the downstream **provider** hop (a different
machine reached over plain HTTP). So the provider still needs per-response signing for its
guarantees. Do both: channel auth for the node, payload signing for the provider.
