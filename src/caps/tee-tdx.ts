import type { ClaimResult } from '@antseed/node'
import type { Capability, CapabilityCollectInput, CapabilityVerifyInput } from '../capability.js'
import { claimId, computeReportData } from '../shared.js'
import { generateTdxQuote } from '../collect/configfs.js'
import { collectViaHttp } from '../collect/http.js'

/**
 * Capability 'tee-tdx-genuine': proves the seller runs in a genuine Intel TDX enclave.
 * DCAP-verifies the quote (ECDSA sig + PCK chain to Intel's root + TCB), requires an
 * acceptable TCB, requires it is a TDX (TD10) quote, and requires TDX debug not enabled.
 * It ALSO parses out the authenticated measurements (MRTD, RTMR0-3, report_data) into a
 * shared ParsedTdxQuote so dependent caps (seller-bound, measured-image) reuse the exact
 * same verified quote instead of re-parsing untrusted bytes.
 */

const CAP_ID = 'tee-tdx-genuine'

/**
 * TCB statuses accepted as genuine hardware: current Intel platform TCB. SWHardeningNeeded
 * flags guest-side software mitigations only and does not impugn the hardware. Anything
 * else (OutOfDate, Revoked, Unknown, ...) is rejected.
 */
export const ACCEPTABLE_TCB = new Set<string>(['UpToDate', 'SWHardeningNeeded'])

/** Authenticated TD10 measurements, extracted from a verified quote. */
export interface TdMeasurements {
  mrTd: Uint8Array
  rtMr0: Uint8Array
  rtMr1: Uint8Array
  rtMr2: Uint8Array
  rtMr3: Uint8Array
  reportData: Uint8Array
  /** TUD.DEBUG (tdAttributes bit 0); null if not determinable. */
  debug: boolean | null
}

/** Raw output of a DCAP check — status + measurements (td null when not a TDX quote). */
export interface RawTdxVerification {
  status: string
  td: TdMeasurements | null
}

/** Injectable DCAP check — the default verifies for real; tests inject a stub. */
export type VerifyQuoteFn = (
  quote: Uint8Array,
  collateral: unknown | undefined,
  nowSecs: number,
) => Promise<RawTdxVerification>

/**
 * The shared, verified quote handed to every capability for this attestation round.
 * `quoteEvidence` is always the exact tee-tdx evidence bytes the seller returned (so
 * seller-bound can hash the same bytes); `td` is present only when DCAP parsing yielded
 * a TDX report.
 */
export interface ParsedTdxQuote {
  quoteEvidence: Uint8Array
  status: string
  td: TdMeasurements | null
  /** Set when DCAP verification or evidence decoding threw. */
  error?: string
}

/** tee-tdx evidence blob: the raw quote (b64) plus optional DCAP collateral. */
interface TeeTdxEvidence {
  quote: string
  collateral?: unknown
}

export function encodeTeeTdxEvidence(quote: Uint8Array, collateral?: unknown): Uint8Array {
  const blob: TeeTdxEvidence = {
    quote: Buffer.from(quote).toString('base64'),
    ...(collateral !== undefined ? { collateral } : {}),
  }
  return new TextEncoder().encode(JSON.stringify(blob))
}

export function decodeTeeTdxEvidence(bytes: Uint8Array): { quote: Uint8Array; collateral?: unknown } {
  const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Partial<TeeTdxEvidence>
  if (typeof parsed.quote !== 'string' || parsed.quote.length === 0) {
    throw new Error('tee-tdx evidence missing "quote"')
  }
  const quote = new Uint8Array(Buffer.from(parsed.quote, 'base64'))
  if (quote.length === 0) {
    throw new Error('tee-tdx evidence "quote" is not valid base64')
  }
  return { quote, ...(parsed.collateral !== undefined ? { collateral: parsed.collateral } : {}) }
}

/**
 * Default DCAP verifier: validates the quote's ECDSA signature + PCK cert chain to
 * Intel's production root CA + TCB, and extracts the TD10 measurements. When the seller
 * supplied collateral we use it; otherwise we fetch it from a public PCCS. @phala/dcap-qvl
 * is imported lazily so the seller/prover half never loads it.
 */
export const defaultVerifyQuote: VerifyQuoteFn = async (quote, collateral, nowSecs) => {
  type Dcap = typeof import('@phala/dcap-qvl')
  const mod = (await import('@phala/dcap-qvl')) as Dcap & { default?: Dcap }
  const dcap = mod.default ?? mod
  const verified = collateral !== undefined
    ? dcap.verify(Buffer.from(quote), collateral as never, nowSecs)
    : await dcap.getCollateralAndVerify(Buffer.from(quote))
  const td = verified.report.asTd10()
  if (!td) return { status: verified.status, td: null }
  return {
    status: verified.status,
    td: {
      mrTd: td.mrTd,
      rtMr0: td.rtMr0,
      rtMr1: td.rtMr1,
      rtMr2: td.rtMr2,
      rtMr3: td.rtMr3,
      reportData: td.reportData,
      debug: td.tdAttributes.length > 0 ? (td.tdAttributes[0]! & 0x01) === 1 : null,
    },
  }
}

/**
 * DCAP-verify the tee-tdx evidence and build the shared ParsedTdxQuote. Never throws:
 * decode/verify errors are captured in `error` so dependent caps still see the raw
 * `quoteEvidence` bytes (seller-bound only needs those to bind identity to the quote).
 */
export async function verifyTdxEvidence(
  evidence: Uint8Array,
  verifyQuote: VerifyQuoteFn,
  nowSecs: number,
): Promise<ParsedTdxQuote> {
  let quote: Uint8Array
  let collateral: unknown
  try {
    ;({ quote, collateral } = decodeTeeTdxEvidence(evidence))
  } catch (err) {
    return { quoteEvidence: evidence, status: '', td: null, error: `malformed tee-tdx evidence: ${msg(err)}` }
  }
  try {
    const raw = await verifyQuote(quote, collateral, nowSecs)
    return { quoteEvidence: evidence, status: raw.status, td: raw.td }
  } catch (err) {
    return { quoteEvidence: evidence, status: '', td: null, error: `quote verification failed: ${msg(err)}` }
  }
}

function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex')
}

export const teeTdxCapability: Capability = {
  id: CAP_ID,

  verify(input: CapabilityVerifyInput): ClaimResult {
    const claim = claimId(CAP_ID)
    if (!input.evidence) return { claim, ok: false, detail: 'seller returned no tee-tdx quote' }
    const p = input.parsedQuote as ParsedTdxQuote | undefined
    if (!p) return { claim, ok: false, detail: 'tee-tdx quote was not verified' }
    if (p.error) return { claim, ok: false, detail: p.error }
    if (!ACCEPTABLE_TCB.has(p.status)) return { claim, ok: false, detail: `TCB status not acceptable: ${p.status || 'unknown'}` }
    if (!p.td) return { claim, ok: false, detail: 'quote is not an Intel TDX quote' }
    if (p.td.debug === true) return { claim, ok: false, detail: 'TDX debug mode is enabled' }
    return {
      claim,
      ok: true,
      detail: `genuine Intel TDX quote (TCB ${p.status}); MRTD ${hex(p.td.mrTd).slice(0, 16)}…`,
    }
  },

  /**
   * Mint fresh evidence. `config.source` selects the generic collector:
   *   'configfs' (default): self-hosted TDX; report_data = SHA-512(nonce ‖ peerId)
   *   'http': fetch a pre-made quote from a config-supplied endpoint
   * Throws when the chosen source is unavailable, so the prover simply omits the cap.
   */
  async collect(input: CapabilityCollectInput): Promise<Uint8Array> {
    const source = input.config.source ?? 'configfs'
    if (source === 'configfs') {
      const quote = generateTdxQuote(computeReportData(input.nonce, input.peerId))
      return encodeTeeTdxEvidence(quote)
    }
    if (source === 'http') {
      const quote = await collectViaHttp(input.config, input.nonce)
      return encodeTeeTdxEvidence(quote)
    }
    throw new Error(`unknown tee-tdx source "${source}" (expected "configfs" or "http")`)
  },
}
