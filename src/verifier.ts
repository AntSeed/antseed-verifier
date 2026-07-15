import { randomBytes } from 'node:crypto'
import type { AntseedVerifierPlugin, ClaimResult, VerifyContext, VerifyResult } from '@antseed/node'
import './caps/index.js' // side-effect: register the capability menu
import { capabilityIds, getCapability } from './capability.js'
import { defaultVerifyQuote, verifyTdxEvidence, type ParsedTdxQuote, type VerifyQuoteFn } from './caps/tee-tdx.js'
import {
  NONCE_BYTES,
  VERIFIER_ID,
  claimId,
  decodeAttestResponse,
  encodeAttestRequest,
  normalizePeerId,
} from './shared.js'

/**
 * Buyer half. Fetches per-capability evidence from the seller in one attestation round,
 * verifies each requested capability, and returns one ClaimResult per capability. The
 * overall verdict is pass iff every REQUIRED capability passed; extra caps the seller
 * evidenced are reported as informational claims.
 */

/**
 * The caps that MUST pass for ok=true. @antseed/node's VerifyContext carries no buyer
 * config yet, so this is a fixed default: genuine TDX hardware AND seller-identity binding.
 * Everything else (measured-image, gpu) is informational until buyers can pass policy.
 */
const REQUIRED_CAPS = ['tee-tdx-genuine', 'seller-bound']
const TEE_TDX_ID = 'tee-tdx-genuine'
/** Derived cap (no own evidence): always worth reporting when a TDX quote is present. */
const DERIVED_CAPS = ['measured-image']

function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** When we can't even get evidence, fail every required cap with the same reason. */
function failAll(detail: string): VerifyResult {
  return { ok: false, claims: REQUIRED_CAPS.map((id) => ({ claim: claimId(id), ok: false, detail })) }
}

/** Core orchestration; the DCAP check is injectable for testing. */
export async function runVerify(
  ctx: VerifyContext,
  verifyQuote: VerifyQuoteFn = defaultVerifyQuote,
): Promise<VerifyResult> {
  let peerId: string
  try {
    peerId = normalizePeerId(ctx.peerId)
  } catch (err) {
    return failAll(msg(err))
  }

  const nonce = randomBytes(NONCE_BYTES)
  // Offer the whole menu; the seller returns evidence only for the caps its infra supports.
  const requested = capabilityIds()

  let resp
  try {
    resp = await ctx.fetchFromSeller({
      method: 'POST',
      path: ctx.attestPath,
      headers: { 'content-type': 'application/json' },
      body: encodeAttestRequest(nonce, requested),
    })
  } catch (err) {
    return failAll(`attestation request failed: ${msg(err)}`)
  }

  if (resp.statusCode !== 200) {
    return failAll(`attestation service returned HTTP ${resp.statusCode}`)
  }

  let evidence: Record<string, Uint8Array>
  try {
    evidence = decodeAttestResponse(resp.body)
  } catch (err) {
    return failAll(`malformed attestation response: ${msg(err)}`)
  }

  // DCAP-verify the tee-tdx quote once; share the parsed result with every dependent cap.
  let parsed: ParsedTdxQuote | undefined
  const teeEv = evidence[TEE_TDX_ID]
  if (teeEv) {
    parsed = await verifyTdxEvidence(teeEv, verifyQuote, Math.floor(Date.now() / 1000))
  }

  // Verify the required caps, any cap the seller returned evidence for, and derived caps.
  const wanted = new Set([...REQUIRED_CAPS, ...Object.keys(evidence), ...DERIVED_CAPS])
  const claims: ClaimResult[] = []
  for (const capId of capabilityIds()) {
    if (!wanted.has(capId)) continue
    const cap = getCapability(capId)
    if (!cap) continue
    try {
      claims.push(await cap.verify({ nonce, peerId, evidence: evidence[capId], parsedQuote: parsed }))
    } catch (err) {
      claims.push({ claim: claimId(capId), ok: false, detail: `verify threw: ${msg(err)}` })
    }
  }

  const ok = REQUIRED_CAPS.every((id) => claims.some((c) => c.claim === claimId(id) && c.ok))
  return { ok, claims }
}

const verifierPlugin: AntseedVerifierPlugin = {
  type: 'verifier',
  name: VERIFIER_ID,
  displayName: 'TEE attestation verifier (Intel TDX / DCAP)',
  version: '0.1.0',
  description:
    'Capability-based seller attestation: one claim per capability. Requires genuine Intel TDX hardware (tee-tdx-genuine) and a seller-identity binding (seller-bound); also reports measured-image and gpu-nvidia-cc when available.',
  verify: (ctx) => runVerify(ctx),
}

export default verifierPlugin
