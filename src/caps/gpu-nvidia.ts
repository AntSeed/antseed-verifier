import type { JWTVerifyGetKey } from 'jose'
import type { ClaimResult } from '../antseed-node-types.js'
import type { Capability, CapabilityCollectInput, CapabilityVerifyInput } from '../capability.js'
import { claimId } from '../shared.js'
import { collectJsonFieldViaHttp } from '../collect/http.js'
import { decodeTeeTdxEvidence, PROVIDER_TEE_CAP_ID } from './tee-tdx.js'
import { getReportDataScheme } from '../report-data.js'
import {
  NRAS_GPU_ATTEST_URL_DEFAULT,
  NRAS_JWKS_URL_DEFAULT,
  buildNrasRequest,
  defaultNrasSubmit,
  verifyEar,
  type NrasSubmitFn,
  type NvidiaGpuEvidence,
} from '../nras.js'

/**
 * Capability 'seller-provider-gpu-cc': proves the inference PROVIDER's GPUs run NVIDIA
 * Confidential Computing, via NVIDIA's Remote Attestation Service (NRAS). The buyer submits
 * the provider's per-GPU CC evidence + the buyer's nonce to NRAS and verifies the returned
 * EAR (signed JWT): signature valid against NVIDIA's JWKS, overall result success, CC mode,
 * and the nonce bound to THIS round.
 *
 * INFORMATIONAL, not required: a CPU-only seller (no GPUs) must still verify, so this cap is
 * never in the buyer's required set. It's offered only when the seller configures a provider
 * evidence route AND a GPU evidence field; otherwise the seller simply omits it. The buyer-side
 * check goes through an injectable GpuVerifyFn (see below) so a future offline verifier drops in.
 */

export const GPU_CAP_ID = 'seller-provider-gpu-cc'

/** Reserved mode switch: 'nras' (default, verify via NRAS) | 'local' (offline; not yet built). */
const GPU_MODE_ENV = 'ANTSEED_VERIFIER_GPU_MODE'
/** Env overrides for NVIDIA's endpoints (defaults point at NRAS; handy for tests/staging). */
const NRAS_URL_ENV = 'ANTSEED_VERIFIER_NRAS_URL'
const NRAS_JWKS_ENV = 'ANTSEED_VERIFIER_NRAS_JWKS_URL'

/** Result of a GPU-CC check — the cap maps this into a ClaimResult. */
export interface GpuVerification {
  ok: boolean
  detail: string
  /** Set on network/service errors (NRAS unreachable), which are retryable, not a real verdict. */
  transient?: boolean
}

/**
 * The injectable seam: verify a provider's GPU-CC evidence against the buyer's nonce. The
 * default is NRAS; a future localGpuVerify implements the offline path behind the SAME type,
 * so swapping it in requires no cap change. Tests inject a stub to exercise the cap's policy.
 */
export type GpuVerifyFn = (evidence: Uint8Array, nonce: Uint8Array) => Promise<GpuVerification>

/** Decode the provider's GPU evidence bytes (JSON: { arch, evidence_list }). */
function decodeGpuEvidence(bytes: Uint8Array): NvidiaGpuEvidence {
  return JSON.parse(new TextDecoder().decode(bytes)) as NvidiaGpuEvidence
}

/** Config for the NRAS verifier; all optional so production uses NVIDIA defaults + real JWKS. */
export interface NrasOptions {
  nrasUrl?: string
  jwksUrl?: string
  /** Injectable NRAS submit (default POSTs to NRAS). */
  submit?: NrasSubmitFn
  /** Injectable jose key resolver (default fetches NVIDIA's JWKS). */
  getKey?: JWTVerifyGetKey
}

/**
 * Build a NRAS-backed GpuVerifyFn. Submits the provider evidence + nonce to NRAS and verifies
 * the EAR. Network/service errors are marked transient (retryable); anything else (malformed
 * evidence, bad signature, failed claim, nonce mismatch) fails closed as a real verdict. jose
 * is imported lazily (only here) so the seller half and CPU-only buyers never load it.
 */
export function makeNrasGpuVerify(opts: NrasOptions = {}): GpuVerifyFn {
  return async (evidenceBytes, nonce) => {
    const nrasUrl = opts.nrasUrl ?? process.env[NRAS_URL_ENV]?.trim() ?? NRAS_GPU_ATTEST_URL_DEFAULT

    let request
    try {
      request = buildNrasRequest(decodeGpuEvidence(evidenceBytes), nonce)
    } catch (err) {
      return { ok: false, detail: `invalid GPU evidence: ${msg(err)}` }
    }

    let response: unknown
    try {
      response = await (opts.submit ?? defaultNrasSubmit)(nrasUrl, request)
    } catch (err) {
      // NRAS unreachable / 5xx — transient, not an attestation verdict.
      return { ok: false, transient: true, detail: `NRAS request failed: ${msg(err)}` }
    }

    let getKey = opts.getKey
    if (!getKey) {
      const jwksUrl = opts.jwksUrl ?? process.env[NRAS_JWKS_ENV]?.trim() ?? NRAS_JWKS_URL_DEFAULT
      const jose = await import('jose')
      getKey = jose.createRemoteJWKSet(new URL(jwksUrl))
    }

    const r = await verifyEar(response, nonce, getKey)
    return { ok: r.ok, detail: r.reason }
  }
}

/** Default NRAS verifier (production). */
export const nrasGpuVerify: GpuVerifyFn = makeNrasGpuVerify()

/**
 * Offline GPU verifier — reserved for the nvtrust-style local path (report + device cert chain
 * + RIM, no external service). Not yet built: returns a clear, non-transient error so operators
 * who set ANTSEED_VERIFIER_GPU_MODE=local get an explicit "not implemented" rather than silence.
 */
export const localGpuVerify: GpuVerifyFn = async () => ({
  ok: false,
  detail: 'offline GPU verification not yet implemented (ANTSEED_VERIFIER_GPU_MODE=local)',
})

/** Dispatch on ANTSEED_VERIFIER_GPU_MODE: NRAS now, local later. Unknown mode fails closed. */
export const defaultGpuVerify: GpuVerifyFn = (evidence, nonce) => {
  const mode = (process.env[GPU_MODE_ENV]?.trim() || 'nras').toLowerCase()
  if (mode === 'local') return localGpuVerify(evidence, nonce)
  if (mode === 'nras') return nrasGpuVerify(evidence, nonce)
  return Promise.resolve({ ok: false, detail: `unknown ${GPU_MODE_ENV} "${mode}" (expected "nras" or "local")` })
}

/** Config-key convention for this cap's collector settings (mirrors tee-tdx's tdxConfigKey). */
export function gpuConfigKey(key: string): string {
  return `${GPU_CAP_ID}.${key}`
}

function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/**
 * The nonce to submit to NRAS this round. A provider that binds its TDX quote with a report_data
 * scheme (e.g. Chutes' nonce-pubkey-sha256-v1) also binds its GPU evidence to that scheme's DERIVED
 * nonce, not the raw round nonce — so we ask the declared scheme for it. Absent a scheme, the raw
 * nonce. Read from the already-collected provider quote in the bundle; any decode issue falls back
 * to the raw nonce (fail-open here is safe — verifyEar still enforces the eat_nonce match).
 */
function nrasNonceFor(nonce: Uint8Array, bundle: Record<string, Uint8Array> | undefined): Uint8Array {
  const providerEvidence = bundle?.[PROVIDER_TEE_CAP_ID]
  if (!providerEvidence) return nonce
  try {
    const { binding } = decodeTeeTdxEvidence(providerEvidence)
    if (!binding) return nonce
    const scheme = getReportDataScheme(binding.scheme)
    return scheme ? scheme.gpuNonce(nonce, binding.ingredients) : nonce
  } catch {
    return nonce
  }
}

/**
 * Mint the GPU-CC capability. `gpuVerify` is the injected buyer-side check (default: NRAS);
 * tests pass a stub. collect fetches the provider's GPU evidence from the SAME provider
 * evidence route as the TDX quote (config-supplied url + field), and throws — so the cap is
 * omitted — when either is absent.
 */
export function makeGpuNvidiaCap(gpuVerify: GpuVerifyFn = defaultGpuVerify): Capability {
  return {
    id: GPU_CAP_ID,

    async verify(input: CapabilityVerifyInput): Promise<ClaimResult> {
      const claim = claimId(GPU_CAP_ID)
      // Fail-closed: no evidence means we cannot attest the GPUs.
      if (!input.evidence) return { claim, ok: false, detail: 'seller returned no GPU CC evidence' }
      const r = await gpuVerify(input.evidence, nrasNonceFor(input.nonce, input.evidenceBundle))
      // ClaimResult has no transient field; surface retryability in the human-readable detail.
      const detail = r.transient ? `[transient] ${r.detail}` : r.detail
      return { claim, ok: r.ok, detail }
    },

    async collect(input: CapabilityCollectInput): Promise<Uint8Array> {
      const url = input.config[gpuConfigKey('url')]
      const field = input.config[gpuConfigKey('field')]
      if (!url || !field) throw new Error('seller-provider-gpu-cc requires a provider url + gpu field; not offered')
      // The GPU evidence is a structured JSON object ({ arch, evidence_list }), not a lone
      // base64 blob — collect it as JSON bytes so its shape survives to the NRAS submit.
      return collectJsonFieldViaHttp(url, input.nonce, field)
    },
  }
}

export const gpuNvidiaCapability = makeGpuNvidiaCap()
