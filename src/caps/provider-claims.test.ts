import { describe, it, expect, vi, afterEach } from 'vitest'
import { randomBytes } from 'node:crypto'
import type { ClaimResult } from '@antseed/node'
import {
  PROVIDER_CLAIMS_CAP_ID,
  claimsConfigKey,
  claimsReportData,
  providerClaimsCapability,
} from './provider-claims.js'
import type { ParsedTdxQuote, TdMeasurements } from './tee-tdx.js'
import { claimId } from '../shared.js'

const NONCE = randomBytes(32)
const PEER = 'ab'.repeat(20)
const PARENT = claimId(PROVIDER_CLAIMS_CAP_ID)

/** Claim id of one named provider claim: <verifier>:seller-provider-claims/<name>. */
const child = (name: string): string => `${PARENT}/${name}`

function doc(claims: Record<string, unknown>, version: unknown = 1): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ version, claims }))
}

function td(reportData: Uint8Array, over: Partial<TdMeasurements> = {}): TdMeasurements {
  return {
    mrTd: new Uint8Array(48).fill(7),
    rtMr0: new Uint8Array(48),
    rtMr1: new Uint8Array(48),
    rtMr2: new Uint8Array(48),
    rtMr3: new Uint8Array(48),
    reportData,
    debug: false,
    ...over,
  }
}

/** A provider TDX parse as the orchestrator hands it over (genuine + current TCB by default). */
function parsed(reportData: Uint8Array, over: Partial<ParsedTdxQuote> = {}): ParsedTdxQuote {
  return { quoteEvidence: new Uint8Array([1]), status: 'UpToDate', td: td(reportData), ...over }
}

async function verify(
  evidence: Uint8Array | undefined,
  parsedQuote?: ParsedTdxQuote,
): Promise<ClaimResult[]> {
  const out = await providerClaimsCapability.verify({ nonce: NONCE, peerId: PEER, evidence, parsedQuote })
  return Array.isArray(out) ? out : [out]
}

const find = (claims: ClaimResult[], id: string): ClaimResult | undefined =>
  claims.find((c) => c.claim === id)

afterEach(() => vi.unstubAllGlobals())

describe('claimsReportData', () => {
  it('is 64 bytes (the TDX REPORTDATA size) and binds both nonce and document', () => {
    const bytes = doc({ a: { value: 1 } })
    const rd = claimsReportData(NONCE, bytes)
    expect(rd.length).toBe(64)
    expect(Buffer.from(claimsReportData(NONCE, bytes)).equals(rd)).toBe(true)
    expect(Buffer.from(claimsReportData(randomBytes(32), bytes)).equals(rd)).toBe(false)
    expect(Buffer.from(claimsReportData(NONCE, doc({ a: { value: 2 } }))).equals(rd)).toBe(false)
  })
})

describe('providerClaimsCapability.verify — document-level failures (one parent claim)', () => {
  it('fails when the seller returned no claims document', async () => {
    const r = await verify(undefined)
    expect(r).toHaveLength(1)
    expect(r[0]).toMatchObject({ claim: PARENT, ok: false })
    expect(r[0]!.detail).toMatch(/no claims document/)
  })

  it('fails on malformed JSON', async () => {
    const r = await verify(new TextEncoder().encode('not json'))
    expect(r[0]).toMatchObject({ claim: PARENT, ok: false })
    expect(r[0]!.detail).toMatch(/malformed claims document/)
  })

  it('fails on an unsupported document version', async () => {
    const r = await verify(doc({ a: { value: 1 } }, 2))
    expect(r[0]).toMatchObject({ claim: PARENT, ok: false })
    expect(r[0]!.detail).toMatch(/unsupported claims document version/)
  })

  it('fails when the document declares no claims', async () => {
    const r = await verify(doc({}))
    expect(r[0]).toMatchObject({ claim: PARENT, ok: false })
    expect(r[0]!.detail).toMatch(/declares no claims/)
  })

  it('rejects the whole document on an invalid claim name (protocol-safe ids only)', async () => {
    const r = await verify(doc({ 'Bad Name': { value: 1 }, 'good-claim': { value: 2 } }))
    expect(r).toHaveLength(1)
    expect(r[0]).toMatchObject({ claim: PARENT, ok: false })
    expect(r[0]!.detail).toMatch(/invalid claim name/)
  })

  it('rejects a document with too many claims', async () => {
    const many: Record<string, unknown> = {}
    for (let i = 0; i < 65; i++) many[`claim-${i}`] = { value: i }
    const r = await verify(doc(many))
    expect(r[0]).toMatchObject({ claim: PARENT, ok: false })
    expect(r[0]!.detail).toMatch(/too many claims/)
  })
})

describe('providerClaimsCapability.verify — per-claim granularity', () => {
  it('emits one namespaced ClaimResult per declared claim', async () => {
    const r = await verify(doc({
      'model-image': { value: 'sha256:abc' },
      'gpu-count': { value: 8 },
    }))
    expect(r).toHaveLength(2)
    expect(find(r, child('model-image'))).toBeDefined()
    expect(find(r, child('gpu-count'))).toBeDefined()
  })

  it('asserted claims (the default proof) pass, marked as provider-asserted', async () => {
    const r = await verify(doc({ 'gpu-count': { value: 8 } }))
    const c = find(r, child('gpu-count'))
    expect(c?.ok).toBe(true)
    expect(c?.detail).toMatch(/asserted by provider/)
    expect(c?.detail).toContain('8')
  })

  it('fails a claim declaring an unknown proof kind', async () => {
    const r = await verify(doc({ x: { value: 1, proof: 'zk-snark' } }))
    expect(find(r, child('x'))?.ok).toBe(false)
    expect(find(r, child('x'))?.detail).toMatch(/unknown proof kind "zk-snark"/)
  })
})

describe('providerClaimsCapability.verify — tdx-quote proof (provider-TEE-bound claims)', () => {
  const tdxClaim = { 'model-image': { value: 'sha256:abc', proof: 'tdx-quote' } }

  it('passes when the verified provider quote report_data commits to this document + nonce', async () => {
    const bytes = doc(tdxClaim)
    const r = await verify(bytes, parsed(claimsReportData(NONCE, bytes)))
    const c = find(r, child('model-image'))
    expect(c?.ok).toBe(true)
    expect(c?.detail).toMatch(/attested by provider TEE/)
  })

  it('fails when there is no provider TDX quote in the round', async () => {
    const r = await verify(doc(tdxClaim))
    expect(find(r, child('model-image'))?.ok).toBe(false)
    expect(find(r, child('model-image'))?.detail).toMatch(/no verified provider TDX quote/)
  })

  it('fails when the provider quote itself did not verify', async () => {
    const bytes = doc(tdxClaim)
    const p = parsed(claimsReportData(NONCE, bytes), { td: null, status: '', error: 'quote verification failed: boom' })
    expect(find(await verify(bytes, p), child('model-image'))?.ok).toBe(false)
  })

  it('fails on an unacceptable provider TCB', async () => {
    const bytes = doc(tdxClaim)
    const p = parsed(claimsReportData(NONCE, bytes), { status: 'OutOfDate' })
    const c = find(await verify(bytes, p), child('model-image'))
    expect(c?.ok).toBe(false)
    expect(c?.detail).toMatch(/TCB/)
  })

  it('fails when TDX debug mode is enabled', async () => {
    const bytes = doc(tdxClaim)
    const p = parsed(claimsReportData(NONCE, bytes))
    p.td = td(claimsReportData(NONCE, bytes), { debug: true })
    expect(find(await verify(bytes, p), child('model-image'))?.ok).toBe(false)
  })

  it('fails when report_data does not commit to this document (stale/foreign doc)', async () => {
    const bytes = doc(tdxClaim)
    const c = find(await verify(bytes, parsed(claimsReportData(NONCE, doc({ other: { value: 1 } })))), child('model-image'))
    expect(c?.ok).toBe(false)
    expect(c?.detail).toMatch(/report_data does not commit to this claims document/)
  })

  it('judges each claim independently: asserted passes while tdx-quote fails', async () => {
    const bytes = doc({
      'gpu-count': { value: 8 },
      'model-image': { value: 'sha256:abc', proof: 'tdx-quote' },
    })
    const r = await verify(bytes) // no provider quote this round
    expect(find(r, child('gpu-count'))?.ok).toBe(true)
    expect(find(r, child('model-image'))?.ok).toBe(false)
  })
})

describe('providerClaimsCapability.collect', () => {
  it('is not offered without a configured evidence url', async () => {
    await expect(
      providerClaimsCapability.collect!({ nonce: NONCE, peerId: PEER, config: {} }),
    ).rejects.toThrow(/not offered/)
  })

  it('is not offered without a configured claims field', async () => {
    await expect(
      providerClaimsCapability.collect!({
        nonce: NONCE,
        peerId: PEER,
        config: { [claimsConfigKey('url')]: 'https://x.example/att/{nonce}' },
      }),
    ).rejects.toThrow(/not offered/)
  })

  it('fetches the provider route and returns the base64 claims document bytes VERBATIM', async () => {
    const bytes = doc({ 'gpu-count': { value: 8 } })
    let seenUrl = ''
    vi.stubGlobal('fetch', vi.fn(async (u: string) => {
      seenUrl = u
      return { ok: true, status: 200, json: async () => ({ claims_doc: Buffer.from(bytes).toString('base64') }) }
    }))
    const out = await providerClaimsCapability.collect!({
      nonce: NONCE,
      peerId: PEER,
      config: {
        [claimsConfigKey('url')]: 'https://x.example/att/{nonce}',
        [claimsConfigKey('field')]: 'claims_doc',
      },
    })
    expect(seenUrl).toBe(`https://x.example/att/${Buffer.from(NONCE).toString('hex')}`)
    // Byte-exact: tdx-quote proof commits to these bytes, so no re-encoding is allowed.
    expect(Buffer.from(out).equals(bytes)).toBe(true)
  })
})
