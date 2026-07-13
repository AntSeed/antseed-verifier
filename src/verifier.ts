import { randomBytes, timingSafeEqual } from 'node:crypto'
import type { AntseedVerifierPlugin, VerifyContext, VerifyResult } from '@antseed/node'
import {
  CLAIM_HARDWARE_GENUINE,
  NONCE_BYTES,
  VERIFIER_ID,
  computeReportData,
  decodeAttestResponse,
  encodeAttestRequest,
  normalizePeerId,
} from './shared.js'

/**
 * Buyer half. Fetches a fresh TDX quote from the seller, verifies it with @phala/dcap-qvl
 * and checks the report_data binding. Returns one claim: hardware-genuine.
 */

/**
 * TCB statuses accepted for a "hardware-genuine" verdict. These indicate genuine
 * Intel hardware with a current platform TCB; SWHardeningNeeded flags guest-side
 * software mitigations only and does not impugn the hardware. Anything else
 * (OutOfDate, Revoked, Unknown, ...) is rejected.
 */
const ACCEPTABLE_TCB = new Set<string>(['UpToDate', 'SWHardeningNeeded'])

export interface QuoteVerification {
  /** Intel DCAP TCB status string from @phala/dcap-qvl (e.g. 'UpToDate'). */
  status: string
  /** Authenticated TDX REPORTDATA (64 bytes), or null if the quote is not TDX. */
  reportData: Uint8Array | null
}

/** Injectable DCAP check — the default verifies for real; tests inject a stub. */
export type VerifyQuoteFn = (
  quote: Uint8Array,
  collateral: unknown | undefined,
  nowSecs: number,
) => Promise<QuoteVerification>

/**
 * Default DCAP verifier: validates the quote's ECDSA signature + PCK cert chain to
 * Intel's production root CA + TCB. When the seller supplied collateral we use it;
 * otherwise we fetch collateral from a public PCCS. @phala/dcap-qvl is imported
 * lazily so the seller/prover half never loads it.
 */
export const defaultVerifyQuote: VerifyQuoteFn = async (quote, collateral, nowSecs) => {
  type Dcap = typeof import('@phala/dcap-qvl')
  const mod = (await import('@phala/dcap-qvl')) as Dcap & { default?: Dcap }
  const dcap = mod.default ?? mod
  const verified = collateral !== undefined
    ? dcap.verify(Buffer.from(quote), collateral as never, nowSecs)
    : await dcap.getCollateralAndVerify(Buffer.from(quote))
  const td = verified.report.asTd10()
  return { status: verified.status, reportData: td ? td.reportData : null }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  return timingSafeEqual(Buffer.from(a), Buffer.from(b))
}

/** Core orchestration; the DCAP check is injectable for testing. */
export async function runVerify(
  ctx: VerifyContext,
  verifyQuote: VerifyQuoteFn = defaultVerifyQuote,
): Promise<VerifyResult> {
  const fail = (detail: string): VerifyResult => ({
    ok: false,
    claims: [{ claim: CLAIM_HARDWARE_GENUINE, ok: false, detail }],
  })

  let peerId: string
  try {
    peerId = normalizePeerId(ctx.peerId)
  } catch (err) {
    return fail(err instanceof Error ? err.message : String(err))
  }

  const nonce = randomBytes(NONCE_BYTES)

  let resp
  try {
    resp = await ctx.fetchFromSeller({
      method: 'POST',
      path: ctx.attestPath,
      headers: { 'content-type': 'application/json' },
      body: encodeAttestRequest(nonce),
    })
  } catch (err) {
    return fail(`attestation request failed: ${err instanceof Error ? err.message : String(err)}`)
  }

  if (resp.statusCode !== 200) {
    return fail(`attestation service returned HTTP ${resp.statusCode}`)
  }

  let quote: Uint8Array
  let collateral: unknown
  try {
    const decoded = decodeAttestResponse(resp.body)
    quote = decoded.quote
    collateral = decoded.collateral
  } catch (err) {
    return fail(`malformed attestation response: ${err instanceof Error ? err.message : String(err)}`)
  }

  let verification: QuoteVerification
  try {
    verification = await verifyQuote(quote, collateral, Math.floor(Date.now() / 1000))
  } catch (err) {
    return fail(`quote verification failed: ${err instanceof Error ? err.message : String(err)}`)
  }

  if (!ACCEPTABLE_TCB.has(verification.status)) {
    return fail(`TCB status not acceptable: ${verification.status}`)
  }
  if (!verification.reportData) {
    return fail('quote is not an Intel TDX quote')
  }

  const expected = computeReportData(nonce, peerId)
  if (!bytesEqual(verification.reportData, expected)) {
    return fail('report_data mismatch: quote not fresh or not bound to this peer (expected SHA-512(nonce ‖ peerId))')
  }

  return {
    ok: true,
    claims: [{
      claim: CLAIM_HARDWARE_GENUINE,
      ok: true,
      detail: `genuine Intel TDX quote (TCB ${verification.status}); report_data bound to ${peerId.slice(0, 10)}…`,
    }],
  }
}

const verifierPlugin: AntseedVerifierPlugin = {
  type: 'verifier',
  name: VERIFIER_ID,
  displayName: 'TEE attestation verifier (Intel TDX / DCAP)',
  version: '0.1.0',
  description: 'Verifies a seller runs in a genuine Intel TDX enclave: DCAP quote validated to Intel\'s root with an acceptable TCB, and report_data bound to a fresh nonce and the seller\'s peer id.',
  verify: (ctx) => runVerify(ctx),
}

export default verifierPlugin
