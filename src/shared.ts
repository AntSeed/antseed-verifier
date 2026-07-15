import { createHash } from 'node:crypto'
import { sha256 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'

/**
 * Shared constants + wire codecs used by BOTH halves of the SDK (buyer verifier
 * and seller prover). The single source of truth for the attestation request /
 * response shape and the seller-bound preimage, so both sides agree byte-for-byte.
 */

/**
 * The advertised + pinned verifier id (also the seller-side prover's name).
 * Hyphenated — no '@' or '/' — so capability strings satisfy PEER_CAPABILITY_PATTERN.
 */
export const VERIFIER_ID = 'refoundhq-antseed-verifier'

/**
 * A claim id is the verifier id namespaced by the capability id, e.g.
 * 'refoundhq-antseed-verifier:tee-tdx-genuine'. One claim per capability.
 */
export function claimId(capId: string): string {
  return `${VERIFIER_ID}:${capId}`
}

/**
 * Reserved control-plane path the buyer's verifier reaches the seller's prover at.
 * The prefix MUST match @antseed/node's ANTSEED_ATTEST_PATH; the seller dispatches it
 * (before provider/service matching, free) to the prover whose name === VERIFIER_ID.
 */
export const ATTEST_PATH = `/_antseed/attest/${VERIFIER_ID}`

/** Freshness nonce length, in bytes. */
export const NONCE_BYTES = 32

/**
 * A PeerId is the canonical AntSeed identifier: 40 lowercase hex chars (the peer's
 * EVM address, no 0x prefix). Lowercase + validate so bindings are symmetric on
 * both sides regardless of input casing.
 */
export function normalizePeerId(peerId: string): string {
  const p = peerId.trim().toLowerCase()
  if (!/^[0-9a-f]{40}$/.test(p)) {
    throw new Error(`invalid peerId: expected 40 hex chars (EVM address, no 0x), got "${peerId.slice(0, 16)}..."`)
  }
  return p
}

/**
 * report_data binding scheme (64 bytes = the TDX REPORTDATA field size):
 *
 *   report_data = SHA-512( nonce(32 raw bytes) || utf8(peerId) )
 *
 * Used by the self-hosted (configfs) collector to bind the quote it mints to both
 * freshness and identity at generation time. Providers that hand back a pre-made
 * quote (http collector) bind their own report_data (often a provider key); in that
 * case the freshness+identity binding is carried by the seller-bound capability
 * instead, which is why this stays a helper rather than a hard requirement.
 */
export function computeReportData(nonce: Uint8Array, peerId: string): Buffer {
  const h = createHash('sha512')
  h.update(Buffer.from(nonce))
  h.update(Buffer.from(normalizePeerId(peerId), 'utf8'))
  return h.digest() // 64 bytes
}

/**
 * seller-bound preimage — the 32-byte digest the seller signs with its AntSeed
 * identity key:
 *
 *   keccak256( nonce(32) || sha256(tdxQuoteEvidence) || utf8(peerId) )
 *
 * Binds the seller's identity signature to THIS specific quote (via its evidence
 * hash), THIS nonce (freshness) and THIS peer id (identity), so nobody can pair a
 * seller's signature with a different quote or replay it. Defined here so both
 * halves compute the identical bytes.
 */
export function sellerBoundPreimage(nonce: Uint8Array, quoteEvidence: Uint8Array, peerId: string): Uint8Array {
  const qh = sha256(quoteEvidence)
  const pid = new TextEncoder().encode(normalizePeerId(peerId))
  const preimage = new Uint8Array(nonce.length + qh.length + pid.length)
  preimage.set(nonce, 0)
  preimage.set(qh, nonce.length)
  preimage.set(pid, nonce.length + qh.length)
  return keccak_256(preimage)
}

/**
 * Config key under which a prover exposes an already-collected capability's evidence
 * (base64) to LATER collectors in the same request. Lets a dependent capability
 * (seller-bound) read the tee-tdx evidence it must bind to, without provider specifics.
 */
export function evidenceConfigKey(capId: string): string {
  return `evidence:${capId}`
}

/** Body the buyer sends to the prover: a fresh nonce + the menu of caps it wants. */
export interface AttestRequestBody {
  /** base64 of the 32-byte freshness nonce. */
  nonce: string
  /** capability ids the buyer is asking the seller to attest. */
  caps: string[]
}

/** Body the seller's prover returns: per-capability evidence (a cap may have none). */
export interface AttestResponseBody {
  /** capId -> base64 of that capability's opaque evidence bytes. */
  evidence: Record<string, string>
}

export function encodeAttestRequest(nonce: Uint8Array, caps: string[]): Uint8Array {
  const body: AttestRequestBody = { nonce: Buffer.from(nonce).toString('base64'), caps }
  return new TextEncoder().encode(JSON.stringify(body))
}

export function decodeAttestRequest(body: Uint8Array): { nonce: Uint8Array; caps: string[] } {
  const parsed = JSON.parse(new TextDecoder().decode(body)) as Partial<AttestRequestBody>
  if (typeof parsed.nonce !== 'string' || parsed.nonce.length === 0) {
    throw new Error('attestation request missing "nonce"')
  }
  const nonce = Buffer.from(parsed.nonce, 'base64')
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`attestation nonce must be ${NONCE_BYTES} bytes, got ${nonce.length}`)
  }
  if (!Array.isArray(parsed.caps) || !parsed.caps.every((c) => typeof c === 'string')) {
    throw new Error('attestation request missing "caps" (string[])')
  }
  return { nonce, caps: parsed.caps }
}

export function encodeAttestResponse(evidence: Record<string, Uint8Array>): Uint8Array {
  const enc: Record<string, string> = {}
  for (const [capId, bytes] of Object.entries(evidence)) {
    enc[capId] = Buffer.from(bytes).toString('base64')
  }
  const body: AttestResponseBody = { evidence: enc }
  return new TextEncoder().encode(JSON.stringify(body))
}

export function decodeAttestResponse(body: Uint8Array): Record<string, Uint8Array> {
  const parsed = JSON.parse(new TextDecoder().decode(body)) as Partial<AttestResponseBody>
  if (parsed.evidence === null || typeof parsed.evidence !== 'object') {
    throw new Error('attestation response missing "evidence" object')
  }
  const out: Record<string, Uint8Array> = {}
  for (const [capId, b64] of Object.entries(parsed.evidence)) {
    if (typeof b64 !== 'string') {
      throw new Error(`attestation evidence for "${capId}" is not base64`)
    }
    out[capId] = new Uint8Array(Buffer.from(b64, 'base64'))
  }
  return out
}
