import { describe, it, expect } from 'vitest'
import { createHash, randomBytes } from 'node:crypto'
import {
  ATTEST_SERVICE_ID,
  NONCE_BYTES,
  computeReportData,
  decodeAttestRequestNonce,
  decodeAttestResponse,
  encodeAttestRequest,
  encodeAttestResponse,
  normalizePeerId,
  type AttestRequestBody,
} from './shared.js'

const PEER = 'a'.repeat(40)

describe('normalizePeerId', () => {
  it('lowercases and accepts a 40-hex peer id', () => {
    expect(normalizePeerId('AbCd' + 'e'.repeat(36))).toBe('abcd' + 'e'.repeat(36))
  })
  it('rejects non-40-hex input', () => {
    expect(() => normalizePeerId('xyz')).toThrow(/invalid peerId/)
    expect(() => normalizePeerId('0x' + 'a'.repeat(40))).toThrow(/invalid peerId/)
    expect(() => normalizePeerId('g'.repeat(40))).toThrow(/invalid peerId/)
  })
})

describe('computeReportData', () => {
  it('is 64 bytes and equals SHA-512(nonce ‖ utf8(peerId))', () => {
    const nonce = randomBytes(NONCE_BYTES)
    const rd = computeReportData(nonce, PEER)
    expect(rd.length).toBe(64)
    const expected = createHash('sha512')
      .update(Buffer.from(nonce))
      .update(Buffer.from(PEER, 'utf8'))
      .digest()
    expect(Buffer.from(rd).equals(expected)).toBe(true)
  })
  it('is deterministic and binds to both nonce and peer', () => {
    const nonce = randomBytes(NONCE_BYTES)
    expect(Buffer.from(computeReportData(nonce, PEER)).equals(computeReportData(nonce, PEER))).toBe(true)
    expect(Buffer.from(computeReportData(nonce, PEER)).equals(computeReportData(randomBytes(NONCE_BYTES), PEER))).toBe(false)
    expect(Buffer.from(computeReportData(nonce, PEER)).equals(computeReportData(nonce, 'b'.repeat(40)))).toBe(false)
  })
  it('normalizes peer id casing so both sides agree', () => {
    const nonce = randomBytes(NONCE_BYTES)
    expect(Buffer.from(computeReportData(nonce, PEER)).equals(computeReportData(nonce, PEER.toUpperCase()))).toBe(true)
  })
})

describe('attestation request codec', () => {
  it('round-trips the nonce and targets the attest service', () => {
    const nonce = randomBytes(NONCE_BYTES)
    const body = encodeAttestRequest(nonce)
    const parsed = JSON.parse(new TextDecoder().decode(body)) as AttestRequestBody
    expect(parsed.model).toBe(ATTEST_SERVICE_ID)
    expect(Buffer.from(decodeAttestRequestNonce(body)).equals(nonce)).toBe(true)
  })
  it('rejects a missing nonce', () => {
    const body = new TextEncoder().encode(JSON.stringify({ model: ATTEST_SERVICE_ID }))
    expect(() => decodeAttestRequestNonce(body)).toThrow(/missing "nonce"/)
  })
  it('rejects a wrong-size nonce', () => {
    const body = new TextEncoder().encode(JSON.stringify({ model: ATTEST_SERVICE_ID, nonce: Buffer.from([1, 2, 3]).toString('base64') }))
    expect(() => decodeAttestRequestNonce(body)).toThrow(/must be 32 bytes/)
  })
})

describe('attestation response codec', () => {
  it('round-trips quote and optional collateral', () => {
    const quote = randomBytes(100)
    const collateral = { tcb_info: 'x' }
    const decoded = decodeAttestResponse(encodeAttestResponse(quote, collateral))
    expect(Buffer.from(decoded.quote).equals(quote)).toBe(true)
    expect(decoded.collateral).toEqual(collateral)
  })
  it('omits collateral when not provided', () => {
    const decoded = decodeAttestResponse(encodeAttestResponse(randomBytes(10)))
    expect(decoded.collateral).toBeUndefined()
  })
  it('rejects a missing quote', () => {
    const body = new TextEncoder().encode(JSON.stringify({ collateral: {} }))
    expect(() => decodeAttestResponse(body)).toThrow(/missing "quote"/)
  })
})
