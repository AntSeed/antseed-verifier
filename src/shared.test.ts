import { describe, it, expect } from 'vitest'
import { createHash, randomBytes } from 'node:crypto'
import {
  NONCE_BYTES,
  VERIFIER_ID,
  claimId,
  computeReportData,
  decodeAttestRequest,
  decodeAttestResponse,
  encodeAttestRequest,
  encodeAttestResponse,
  normalizePeerId,
  sellerBoundPreimage,
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

describe('claimId', () => {
  it('namespaces the capability id under the verifier id', () => {
    expect(claimId('tee-tdx-genuine')).toBe(`${VERIFIER_ID}:tee-tdx-genuine`)
  })
})

describe('computeReportData', () => {
  it('is 64 bytes and equals SHA-512(nonce ‖ utf8(peerId))', () => {
    const nonce = randomBytes(NONCE_BYTES)
    const rd = computeReportData(nonce, PEER)
    expect(rd.length).toBe(64)
    const expected = createHash('sha512').update(Buffer.from(nonce)).update(Buffer.from(PEER, 'utf8')).digest()
    expect(Buffer.from(rd).equals(expected)).toBe(true)
  })
  it('normalizes peer id casing so both sides agree', () => {
    const nonce = randomBytes(NONCE_BYTES)
    expect(Buffer.from(computeReportData(nonce, PEER)).equals(computeReportData(nonce, PEER.toUpperCase()))).toBe(true)
  })
})

describe('sellerBoundPreimage', () => {
  it('is a deterministic 32-byte digest', () => {
    const nonce = randomBytes(NONCE_BYTES)
    const ev = randomBytes(120)
    const a = sellerBoundPreimage(nonce, ev, PEER)
    expect(a.length).toBe(32)
    expect(Buffer.from(a).equals(sellerBoundPreimage(nonce, ev, PEER))).toBe(true)
  })
  it('binds to nonce, quote evidence and peer id independently', () => {
    const nonce = randomBytes(NONCE_BYTES)
    const ev = randomBytes(120)
    const base = sellerBoundPreimage(nonce, ev, PEER)
    expect(Buffer.from(base).equals(sellerBoundPreimage(randomBytes(NONCE_BYTES), ev, PEER))).toBe(false)
    expect(Buffer.from(base).equals(sellerBoundPreimage(nonce, randomBytes(120), PEER))).toBe(false)
    expect(Buffer.from(base).equals(sellerBoundPreimage(nonce, ev, 'b'.repeat(40)))).toBe(false)
  })
})

describe('attestation request codec (multi-cap)', () => {
  it('round-trips the nonce and cap menu', () => {
    const nonce = randomBytes(NONCE_BYTES)
    const caps = ['tee-tdx-genuine', 'seller-bound']
    const decoded = decodeAttestRequest(encodeAttestRequest(nonce, caps))
    expect(Buffer.from(decoded.nonce).equals(nonce)).toBe(true)
    expect(decoded.caps).toEqual(caps)
  })
  it('rejects a missing nonce', () => {
    const body = new TextEncoder().encode(JSON.stringify({ caps: [] }))
    expect(() => decodeAttestRequest(body)).toThrow(/missing "nonce"/)
  })
  it('rejects a wrong-size nonce', () => {
    const body = new TextEncoder().encode(JSON.stringify({ nonce: Buffer.from([1, 2, 3]).toString('base64'), caps: [] }))
    expect(() => decodeAttestRequest(body)).toThrow(/must be 32 bytes/)
  })
  it('rejects a missing caps array', () => {
    const body = new TextEncoder().encode(JSON.stringify({ nonce: randomBytes(NONCE_BYTES).toString('base64') }))
    expect(() => decodeAttestRequest(body)).toThrow(/missing "caps"/)
  })
})

describe('attestation response codec (per-cap evidence)', () => {
  it('round-trips a per-cap evidence map, including an empty entry', () => {
    const evidence = { 'tee-tdx-genuine': randomBytes(100), 'seller-bound': randomBytes(65), 'measured-image': new Uint8Array() }
    const decoded = decodeAttestResponse(encodeAttestResponse(evidence))
    expect(Buffer.from(decoded['tee-tdx-genuine']!).equals(evidence['tee-tdx-genuine'])).toBe(true)
    expect(Buffer.from(decoded['seller-bound']!).equals(evidence['seller-bound'])).toBe(true)
    expect(decoded['measured-image']!.length).toBe(0)
  })
  it('round-trips an empty evidence map', () => {
    expect(decodeAttestResponse(encodeAttestResponse({}))).toEqual({})
  })
  it('rejects a missing evidence object', () => {
    const body = new TextEncoder().encode(JSON.stringify({}))
    expect(() => decodeAttestResponse(body)).toThrow(/missing "evidence"/)
  })
})
