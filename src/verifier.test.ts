import { describe, it, expect } from 'vitest'
import { randomBytes } from 'node:crypto'
import type { VerifyContext, SellerRequest, SellerResponse } from '@antseed/node'
import { runVerify, type VerifyQuoteFn } from './verifier.js'
import {
  ATTEST_PATH,
  ATTEST_SERVICE_ID,
  CLAIM_HARDWARE_GENUINE,
  computeReportData,
  decodeAttestRequestNonce,
  encodeAttestResponse,
  type AttestRequestBody,
} from './shared.js'

const PEER = 'f'.repeat(40)

/**
 * Build a VerifyContext whose fetchFromSeller returns a controllable response and
 * captures the buyer's request (so tests can assert the request shape and reuse the
 * nonce to forge a matching report_data).
 */
function makeCtx(
  respond: (req: SellerRequest, nonce: Uint8Array) => SellerResponse,
  peerId = PEER,
): { ctx: VerifyContext; seen: { req?: SellerRequest; nonce?: Uint8Array } } {
  const seen: { req?: SellerRequest; nonce?: Uint8Array } = {}
  const ctx: VerifyContext = {
    peerId,
    fetchFromSeller: async (req) => {
      const nonce = decodeAttestRequestNonce(req.body ?? new Uint8Array())
      seen.req = req
      seen.nonce = nonce
      return respond(req, nonce)
    },
  }
  return { ctx, seen }
}

const ok200 = (body: Uint8Array): SellerResponse => ({ statusCode: 200, headers: {}, body })

/** A verifyQuote stub that reports a chosen TCB status and report_data. */
const stubQuote = (status: string, reportData: Uint8Array | null): VerifyQuoteFn =>
  async () => ({ status, reportData })

describe('runVerify — happy path', () => {
  it('issues an OpenAI-shaped POST to the attest service with a 32-byte nonce', async () => {
    const { ctx, seen } = makeCtx(() => ok200(encodeAttestResponse(randomBytes(64))))
    await runVerify(ctx, stubQuote('UpToDate', computeReportData(randomBytes(32), PEER)))
    expect(seen.req?.method).toBe('POST')
    expect(seen.req?.path).toBe(ATTEST_PATH)
    expect(seen.req?.headers?.['content-type']).toBe('application/json')
    const parsed = JSON.parse(new TextDecoder().decode(seen.req!.body!)) as AttestRequestBody
    expect(parsed.model).toBe(ATTEST_SERVICE_ID)
    expect(seen.nonce?.length).toBe(32)
  })

  it('passes when the quote is genuine and report_data matches', async () => {
    const { ctx, seen } = makeCtx(() => ok200(encodeAttestResponse(randomBytes(64))))
    // Run once to capture the nonce, then forge a matching report_data via the stub.
    const verify: VerifyQuoteFn = async () => ({
      status: 'UpToDate',
      reportData: computeReportData(seen.nonce!, PEER),
    })
    const result = await runVerify(ctx, verify)
    expect(result.ok).toBe(true)
    expect(result.claims).toHaveLength(1)
    expect(result.claims[0]).toMatchObject({ claim: CLAIM_HARDWARE_GENUINE, ok: true })
    expect(result.claims[0]?.detail).toMatch(/genuine Intel TDX quote/)
  })

  it('accepts SWHardeningNeeded as hardware-genuine', async () => {
    const { ctx, seen } = makeCtx(() => ok200(encodeAttestResponse(randomBytes(64))))
    const verify: VerifyQuoteFn = async () => ({ status: 'SWHardeningNeeded', reportData: computeReportData(seen.nonce!, PEER) })
    expect((await runVerify(ctx, verify)).ok).toBe(true)
  })
})

describe('runVerify — failure paths (all return ok:false, never throw)', () => {
  it('fails on report_data mismatch (replayed / wrong peer / stale)', async () => {
    const { ctx } = makeCtx(() => ok200(encodeAttestResponse(randomBytes(64))))
    const result = await runVerify(ctx, stubQuote('UpToDate', randomBytes(64)))
    expect(result.ok).toBe(false)
    expect(result.claims[0]?.detail).toMatch(/report_data mismatch/)
  })

  it('fails on an unacceptable TCB status', async () => {
    const { ctx, seen } = makeCtx(() => ok200(encodeAttestResponse(randomBytes(64))))
    const verify: VerifyQuoteFn = async () => ({ status: 'OutOfDate', reportData: computeReportData(seen.nonce!, PEER) })
    const result = await runVerify(ctx, verify)
    expect(result.ok).toBe(false)
    expect(result.claims[0]?.detail).toMatch(/TCB status not acceptable: OutOfDate/)
  })

  it('fails when the quote is not a TDX quote', async () => {
    const { ctx } = makeCtx(() => ok200(encodeAttestResponse(randomBytes(64))))
    const result = await runVerify(ctx, stubQuote('UpToDate', null))
    expect(result.ok).toBe(false)
    expect(result.claims[0]?.detail).toMatch(/not an Intel TDX quote/)
  })

  it('fails when DCAP verification throws', async () => {
    const { ctx } = makeCtx(() => ok200(encodeAttestResponse(randomBytes(64))))
    const verify: VerifyQuoteFn = async () => { throw new Error('bad signature') }
    const result = await runVerify(ctx, verify)
    expect(result.ok).toBe(false)
    expect(result.claims[0]?.detail).toMatch(/quote verification failed: bad signature/)
  })

  it('fails on a non-200 attestation response', async () => {
    const { ctx } = makeCtx(() => ({ statusCode: 402, headers: {}, body: new Uint8Array() }))
    const result = await runVerify(ctx, stubQuote('UpToDate', randomBytes(64)))
    expect(result.ok).toBe(false)
    expect(result.claims[0]?.detail).toMatch(/HTTP 402/)
  })

  it('fails on a malformed (non-JSON) response body', async () => {
    const { ctx } = makeCtx(() => ok200(new TextEncoder().encode('not json')))
    const result = await runVerify(ctx, stubQuote('UpToDate', randomBytes(64)))
    expect(result.ok).toBe(false)
    expect(result.claims[0]?.detail).toMatch(/malformed attestation response/)
  })

  it('fails on an invalid peer id', async () => {
    const { ctx } = makeCtx(() => ok200(encodeAttestResponse(randomBytes(64))), 'not-a-peer')
    const result = await runVerify(ctx, stubQuote('UpToDate', randomBytes(64)))
    expect(result.ok).toBe(false)
    expect(result.claims[0]?.detail).toMatch(/invalid peerId/)
  })

  it('fails when fetchFromSeller rejects', async () => {
    const ctx: VerifyContext = {
      peerId: PEER,
      fetchFromSeller: async () => { throw new Error('peer unreachable') },
    }
    const result = await runVerify(ctx, stubQuote('UpToDate', randomBytes(64)))
    expect(result.ok).toBe(false)
    expect(result.claims[0]?.detail).toMatch(/attestation request failed: peer unreachable/)
  })
})

/**
 * Guard test: lock the report_data field location our default verifier relies on
 * (verified.report.asTd10().reportData) against @phala/dcap-qvl's parser, using a
 * synthetic but structurally-valid v4 TDX quote. The full cryptographic verify is
 * exercised only in the GCP e2e (needs a genuine signed quote + collateral).
 */
describe('@phala/dcap-qvl TDX report_data extraction', () => {
  it('Quote.parse(...).report.asTd10().reportData returns the embedded 64 bytes', async () => {
    const reportData = randomBytes(64)
    const quote = buildSyntheticTdxQuote(reportData)
    const mod = (await import('@phala/dcap-qvl')) as typeof import('@phala/dcap-qvl') & { default?: typeof import('@phala/dcap-qvl') }
    const dcap = mod.default ?? mod
    const parsed = dcap.Quote.parse(quote)
    const td = parsed.report.asTd10()
    expect(td).not.toBeNull()
    expect(Buffer.from(td!.reportData).equals(reportData)).toBe(true)
  })
})

/** Construct a minimal v4 TDX quote that Quote.parse accepts, with a chosen report_data. */
function buildSyntheticTdxQuote(reportData: Uint8Array): Uint8Array {
  // Header (48 bytes): version=4, attestationKeyType=2, teeType=TDX(0x81), ...
  const header = Buffer.alloc(48)
  header.writeUInt16LE(4, 0) // version
  header.writeUInt16LE(2, 2) // attestation key type
  header.writeUInt32LE(0x00000081, 4) // teeType = TDX
  // remaining qeSvn/pceSvn/qeVendorId(16)/userData(20) left zero

  // TD10 report (584 bytes): report_data is the final 64 bytes (offset 520).
  const tdReport = Buffer.alloc(584)
  Buffer.from(reportData).copy(tdReport, 584 - 64)

  // QEReportCertificationData body: qeReport(384) + sig(64) + authSize(2)=0 + cert(certType u16=0, size u32=0)
  const qeCertBody = Buffer.alloc(384 + 64 + 2 + 2 + 4) // 456 bytes, all zero

  // AuthDataV4: ecdsaSig(64) + attestKey(64) + CertificationData(certType u16=5, size u32, body)
  const certHeader = Buffer.alloc(6)
  certHeader.writeUInt16LE(5, 0) // certType = PCK_CERT_CHAIN
  certHeader.writeUInt32LE(qeCertBody.length, 2)
  const authData = Buffer.concat([
    Buffer.alloc(64), // ecdsaSignature
    Buffer.alloc(64), // ecdsaAttestationKey
    certHeader,
    qeCertBody,
  ])

  const authSize = Buffer.alloc(4)
  authSize.writeUInt32LE(authData.length, 0)

  return new Uint8Array(Buffer.concat([header, tdReport, authSize, authData]))
}
