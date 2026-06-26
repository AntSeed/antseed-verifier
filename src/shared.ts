import { createHash } from 'node:crypto'

/**
 * Shared constants + wire codecs used by BOTH halves of the SDK (buyer verifier
 * and seller prover). Pure — depends only on node builtins, no npm deps. This is
 * the single source of truth for the attestation request/response shape and the
 * report_data binding scheme so both sides agree byte-for-byte.
 */

/**
 * The advertised + pinned verifier id (also the seller-side prover's name).
 * Hyphenated — no '@' or '/' — so capability strings satisfy PEER_CAPABILITY_PATTERN.
 */
export const VERIFIER_ID = 'refoundhq-antseed-verifier'

/** The single claim this SDK proves. */
export const CLAIM_HARDWARE_GENUINE = `${VERIFIER_ID}:hardware-genuine`

/**
 * Reserved control-plane path the buyer's verifier reaches the seller's prover at.
 * The prefix MUST match @antseed/node's ANTSEED_ATTEST_PATH; the seller dispatches it
 * (before provider/service matching, free) to the prover whose name === VERIFIER_ID.
 */
export const ATTEST_PATH = `/_antseed/attest/${VERIFIER_ID}`

/** Freshness nonce length, in bytes. Exactly fills half of report_data's preimage. */
export const NONCE_BYTES = 32

/**
 * A PeerId is the canonical AntSeed identifier: 40 lowercase hex chars (the peer's
 * EVM address, no 0x prefix). Lowercase + validate so the binding is symmetric on
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
 * peerId is the normalized 40-char lowercase hex peer id (its UTF-8 bytes). This
 * binds a quote to BOTH freshness (the buyer's random nonce) and the seller's
 * identity, so a relay cannot replay another TEE's quote for its own peer id.
 */
export function computeReportData(nonce: Uint8Array, peerId: string): Buffer {
  const h = createHash('sha512')
  h.update(Buffer.from(nonce))
  h.update(Buffer.from(normalizePeerId(peerId), 'utf8'))
  return h.digest() // 64 bytes
}

/** Body the buyer sends to the prover. */
export interface AttestRequestBody {
  /** base64 of the 32-byte freshness nonce. */
  nonce: string
}

/** Body the seller's prover returns. */
export interface AttestResponseBody {
  /** base64 of the raw Intel TDX quote bytes (configfs-tsm outblob). */
  quote: string
  /**
   * Optional DCAP collateral (PCK CRLs, TCB info, QE identity). When omitted the
   * buyer fetches collateral from a public PCCS itself. Shape matches the
   * `Collateral` interface of @phala/dcap-qvl.
   */
  collateral?: unknown
}

export function encodeAttestRequest(nonce: Uint8Array): Uint8Array {
  const body: AttestRequestBody = { nonce: Buffer.from(nonce).toString('base64') }
  return new TextEncoder().encode(JSON.stringify(body))
}

export function decodeAttestRequestNonce(body: Uint8Array): Uint8Array {
  const parsed = JSON.parse(new TextDecoder().decode(body)) as Partial<AttestRequestBody>
  if (typeof parsed.nonce !== 'string' || parsed.nonce.length === 0) {
    throw new Error('attestation request missing "nonce"')
  }
  const nonce = Buffer.from(parsed.nonce, 'base64')
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(`attestation nonce must be ${NONCE_BYTES} bytes, got ${nonce.length}`)
  }
  return nonce
}

export function encodeAttestResponse(quote: Uint8Array, collateral?: unknown): Uint8Array {
  const body: AttestResponseBody = {
    quote: Buffer.from(quote).toString('base64'),
    ...(collateral !== undefined ? { collateral } : {}),
  }
  return new TextEncoder().encode(JSON.stringify(body))
}

export function decodeAttestResponse(body: Uint8Array): { quote: Uint8Array; collateral?: unknown } {
  const parsed = JSON.parse(new TextDecoder().decode(body)) as Partial<AttestResponseBody>
  if (typeof parsed.quote !== 'string' || parsed.quote.length === 0) {
    throw new Error('attestation response missing "quote"')
  }
  const quote = Buffer.from(parsed.quote, 'base64')
  if (quote.length === 0) {
    throw new Error('attestation response "quote" is not valid base64')
  }
  return { quote, ...(parsed.collateral !== undefined ? { collateral: parsed.collateral } : {}) }
}
