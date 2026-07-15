import { describe, it, expect } from 'vitest'
import { randomBytes } from 'node:crypto'
import {
  evmAddressFromPrivateKey,
  recoverEvmAddress,
  sellerBoundCapability,
  signerFromPrivateKey,
} from './seller-bound.js'
import { claimId, evidenceConfigKey, sellerBoundPreimage } from '../shared.js'
import type { ParsedTdxQuote } from './tee-tdx.js'

// Fixed test keypairs (valid secp256k1 scalars, < curve order, != 0).
const PRIV = '01'.repeat(32)
const PRIV2 = '02'.repeat(32)
const PEER = evmAddressFromPrivateKey(PRIV)
const CLAIM = claimId('seller-bound')

/** Minimal shared quote — seller-bound only needs the raw tee-tdx evidence bytes. */
function parsed(quoteEvidence: Uint8Array): ParsedTdxQuote {
  return { quoteEvidence, status: 'UpToDate', td: null }
}

async function collect(peerId: string, quoteEvidence: Uint8Array, nonce: Uint8Array, sign = signerFromPrivateKey(PRIV)) {
  const config = { [evidenceConfigKey('tee-tdx-genuine')]: Buffer.from(quoteEvidence).toString('base64') }
  return sellerBoundCapability.collect!({ nonce, peerId, config, sign })
}

describe('seller-bound helpers', () => {
  it('evmAddressFromPrivateKey yields a 40-hex lowercase address', () => {
    expect(PEER).toMatch(/^[0-9a-f]{40}$/)
  })
  it('recoverEvmAddress recovers the signer of a digest', async () => {
    const digest = randomBytes(32)
    const sig = await signerFromPrivateKey(PRIV)(digest)
    expect(sig.length).toBe(65)
    expect(recoverEvmAddress(digest, sig)).toBe(PEER)
  })
  it('recoverEvmAddress rejects a wrong-length signature', () => {
    expect(() => recoverEvmAddress(randomBytes(32), randomBytes(64))).toThrow(/65 bytes/)
  })
})

describe('seller-bound capability', () => {
  it('collect → verify round-trips: the signer matches the peer id', async () => {
    const nonce = randomBytes(32)
    const quoteEvidence = randomBytes(120)
    const sig = await collect(PEER, quoteEvidence, nonce)
    const r = await sellerBoundCapability.verify({ nonce, peerId: PEER, evidence: sig, parsedQuote: parsed(quoteEvidence) })
    expect(r).toMatchObject({ claim: CLAIM, ok: true })
  })

  it('signs the exact seller-bound preimage', async () => {
    const nonce = randomBytes(32)
    const quoteEvidence = randomBytes(120)
    const sig = await collect(PEER, quoteEvidence, nonce)
    // Independently recover against the canonical preimage — must yield the seller's address.
    expect(recoverEvmAddress(sellerBoundPreimage(nonce, quoteEvidence, PEER), sig)).toBe(PEER)
  })

  it('fails when a different key signed (signer != peer)', async () => {
    const nonce = randomBytes(32)
    const quoteEvidence = randomBytes(120)
    const sig = await collect(PEER, quoteEvidence, nonce, signerFromPrivateKey(PRIV2))
    const r = await sellerBoundCapability.verify({ nonce, peerId: PEER, evidence: sig, parsedQuote: parsed(quoteEvidence) })
    expect(r.ok).toBe(false)
    expect(r.detail).toMatch(/does not match peer/)
  })

  it('fails when the seller returned no signature', async () => {
    const r = await sellerBoundCapability.verify({ nonce: randomBytes(32), peerId: PEER, parsedQuote: parsed(randomBytes(120)) })
    expect(r.ok).toBe(false)
    expect(r.detail).toMatch(/no identity signature/)
  })

  it('fails when there is no tee-tdx quote to bind to', async () => {
    const r = await sellerBoundCapability.verify({ nonce: randomBytes(32), peerId: PEER, evidence: randomBytes(65) })
    expect(r.ok).toBe(false)
    expect(r.detail).toMatch(/requires a tee-tdx quote/)
  })

  it('fails on a malformed (wrong-length) signature', async () => {
    const qe = randomBytes(120)
    const r = await sellerBoundCapability.verify({ nonce: randomBytes(32), peerId: PEER, evidence: randomBytes(10), parsedQuote: parsed(qe) })
    expect(r.ok).toBe(false)
    expect(r.detail).toMatch(/recovery failed|65 bytes/)
  })

  it('collect throws (cap not offered) without a signer', async () => {
    const config = { [evidenceConfigKey('tee-tdx-genuine')]: Buffer.from(randomBytes(50)).toString('base64') }
    await expect(sellerBoundCapability.collect!({ nonce: randomBytes(32), peerId: PEER, config })).rejects.toThrow(/requires a signer/)
  })

  it('collect throws without tee-tdx evidence to bind to', async () => {
    await expect(
      sellerBoundCapability.collect!({ nonce: randomBytes(32), peerId: PEER, config: {}, sign: signerFromPrivateKey(PRIV) }),
    ).rejects.toThrow(/requires tee-tdx evidence/)
  })
})
