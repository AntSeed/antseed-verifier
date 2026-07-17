import { createHash } from 'node:crypto'
import type { ClaimResult } from '@antseed/node'
import type { Capability, CapabilityCollectInput, CapabilityVerifyInput } from '../capability.js'
import { claimId } from '../shared.js'
import { collectViaHttp } from '../collect/http.js'
import { ACCEPTABLE_TCB, type ParsedTdxQuote } from './tee-tdx.js'

/**
 * Capability 'seller-provider-claims': carries the inference PROVIDER's own claims into
 * the protocol with per-claim granularity. The provider publishes a claims DOCUMENT (a
 * named map of claims); the buyer emits one ClaimResult per claim, namespaced
 * '<verifier>:seller-provider-claims/<name>', so downstream policy can act on individual
 * provider guarantees instead of one opaque blob.
 *
 * Each claim declares how it is proven:
 *   'asserted'  (default) the provider asserts it. Integrity, freshness and seller
 *               identity still come for free from the whole-bundle seller-bound signature
 *               (this cap's evidence is part of the bundle it signs).
 *   'tdx-quote' the provider's TDX quote (independently DCAP-verified this round as
 *               seller-provider-tee-genuine) must commit to THIS document + THIS nonce in
 *               its report_data — the claims are then attested by the provider's TEE, not
 *               merely asserted. See claimsReportData for the commitment scheme.
 *
 * The document is provider-authored BYTES carried verbatim (base64 field on the same
 * config-driven evidence route as the provider quote): tdx-quote proof hashes the exact
 * bytes, so no re-encoding is allowed anywhere. No provider specifics live here.
 */

export const PROVIDER_CLAIMS_CAP_ID = 'seller-provider-claims'

/** Config-key convention for this cap's collector, mirroring tdxConfigKey. */
export function claimsConfigKey(key: string): string {
  return `${PROVIDER_CLAIMS_CAP_ID}.${key}`
}

/**
 * report_data commitment for tdx-quote proof (64 bytes = the TDX REPORTDATA size):
 *
 *   report_data = SHA-512( nonce(32 raw bytes) || claimsDocumentBytes )
 *
 * Providers minting a fresh quote per attestation round compute this over the exact
 * document bytes they return; the buyer recomputes it from the received bytes and the
 * round nonce, so a bound document is both fresh and provider-TEE-attested.
 */
export function claimsReportData(nonce: Uint8Array, docBytes: Uint8Array): Uint8Array {
  const h = createHash('sha512')
  h.update(Buffer.from(nonce))
  h.update(Buffer.from(docBytes))
  return new Uint8Array(h.digest())
}

/** Claim names become protocol claim-id path segments; keep them id-safe and bounded. */
const CLAIM_NAME_RE = /^[a-z0-9][a-z0-9.-]{0,63}$/
/** Hard bound on claims per document, so a provider cannot flood the buyer's report. */
const MAX_CLAIMS = 64
const PROOF_KINDS = new Set(['asserted', 'tdx-quote'])

interface ProviderClaim {
  value: unknown
  proof: string
}

/** Parse + validate a claims document. Throws with a doc-level reason on any violation. */
function parseClaimsDoc(bytes: Uint8Array): Map<string, ProviderClaim> {
  let root: unknown
  try {
    root = JSON.parse(new TextDecoder().decode(bytes))
  } catch (err) {
    throw new Error(`malformed claims document: ${err instanceof Error ? err.message : String(err)}`)
  }
  if (root === null || typeof root !== 'object' || Array.isArray(root)) {
    throw new Error('malformed claims document: not a JSON object')
  }
  const { version, claims } = root as { version?: unknown; claims?: unknown }
  if (version !== undefined && version !== 1) {
    throw new Error(`unsupported claims document version ${JSON.stringify(version)} (expected 1)`)
  }
  if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new Error('malformed claims document: "claims" is not an object')
  }
  const entries = Object.entries(claims as Record<string, unknown>)
  if (entries.length === 0) throw new Error('claims document declares no claims')
  if (entries.length > MAX_CLAIMS) {
    throw new Error(`claims document has too many claims (${entries.length} > ${MAX_CLAIMS})`)
  }
  const out = new Map<string, ProviderClaim>()
  for (const [name, entry] of entries) {
    if (!CLAIM_NAME_RE.test(name)) {
      throw new Error(`invalid claim name "${name}": use lowercase letters, digits, hyphen or dot (max 64 chars)`)
    }
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`claim "${name}" is not an object`)
    }
    const { value, proof } = entry as { value?: unknown; proof?: unknown }
    if (proof !== undefined && typeof proof !== 'string') {
      throw new Error(`claim "${name}" has a non-string proof`)
    }
    out.set(name, { value, proof: proof ?? 'asserted' })
  }
  return out
}

/** Compact human summary of a claim's value for ClaimResult.detail. */
function summarize(value: unknown): string {
  const s = JSON.stringify(value) ?? 'undefined'
  return s.length > 80 ? `${s.slice(0, 77)}…` : s
}

/**
 * One binding verdict per document: is the provider quote genuine AND committed to these
 * exact document bytes? Shared by every tdx-quote claim in the doc.
 */
function quoteBinding(
  p: ParsedTdxQuote | undefined,
  nonce: Uint8Array,
  docBytes: Uint8Array,
): string | null {
  if (!p) return 'no verified provider TDX quote in this round (tdx-quote proof requires seller-provider-tee-genuine evidence)'
  if (p.error) return p.error
  if (!ACCEPTABLE_TCB.has(p.status)) return `provider TCB status not acceptable: ${p.status || 'unknown'}`
  if (!p.td) return 'provider quote is not an Intel TDX quote'
  if (p.td.debug === true) return 'provider TDX debug mode is enabled'
  const expected = claimsReportData(nonce, docBytes)
  if (!Buffer.from(p.td.reportData).equals(Buffer.from(expected))) {
    return 'provider quote report_data does not commit to this claims document'
  }
  return null
}

export const providerClaimsCapability: Capability = {
  id: PROVIDER_CLAIMS_CAP_ID,

  verify(input: CapabilityVerifyInput): ClaimResult[] {
    const parent = claimId(PROVIDER_CLAIMS_CAP_ID)
    if (!input.evidence) {
      return [{ claim: parent, ok: false, detail: 'seller returned no claims document' }]
    }
    let claims: Map<string, ProviderClaim>
    try {
      claims = parseClaimsDoc(input.evidence)
    } catch (err) {
      return [{ claim: parent, ok: false, detail: err instanceof Error ? err.message : String(err) }]
    }
    // Bind once per document; every tdx-quote claim shares the verdict.
    const p = input.parsedQuote as ParsedTdxQuote | undefined
    const bindingFailure = quoteBinding(p, input.nonce, input.evidence)

    const results: ClaimResult[] = []
    for (const [name, c] of claims) {
      const claim = `${parent}/${name}`
      if (!PROOF_KINDS.has(c.proof)) {
        results.push({ claim, ok: false, detail: `unknown proof kind "${c.proof}"` })
      } else if (c.proof === 'tdx-quote') {
        results.push(
          bindingFailure
            ? { claim, ok: false, detail: bindingFailure }
            : { claim, ok: true, detail: `attested by provider TEE (report_data-bound TDX quote): ${summarize(c.value)}` },
        )
      } else {
        results.push({ claim, ok: true, detail: `asserted by provider (integrity/freshness via seller-bound): ${summarize(c.value)}` })
      }
    }
    return results
  },

  async collect(input: CapabilityCollectInput): Promise<Uint8Array> {
    const url = input.config[claimsConfigKey('url')]
    const field = input.config[claimsConfigKey('field')]
    if (!url || !field) {
      throw new Error(`${PROVIDER_CLAIMS_CAP_ID} requires an evidence url and a claims field; not offered`)
    }
    // collectViaHttp base64-decodes the field — the document bytes arrive VERBATIM,
    // which tdx-quote proof depends on (report_data hashes the exact bytes).
    return collectViaHttp(url, input.nonce, field)
  },
}
