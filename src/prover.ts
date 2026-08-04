import type { Prover, SellerRequest, SellerResponse } from './antseed-node-types.js'
import './caps/index.js' // side-effect: register the capability menu
import { listCapabilities } from './capability.js'
import { evmAddressFromPrivateKey, signerFromPrivateKey } from './caps/seller-bound.js'
import { NODE_TEE_CAP_ID, PROVIDER_TEE_CAP_ID, tdxConfigKey } from './caps/tee-tdx.js'
import { gpuConfigKey } from './caps/gpu-nvidia.js'
import { claimsConfigKey } from './caps/provider-claims.js'
import {
  VERIFIER_ID,
  decodeAttestRequest,
  encodeAttestResponse,
  evidenceConfigKey,
  normalizePeerId,
} from './shared.js'

/**
 * Seller half — embedded prover (type:'prover'). For each requested capability the seller
 * SUPPORTS (has a collector for, and whose collection succeeds), it produces evidence and
 * assembles a per-cap evidence map. Unsupported caps are simply omitted. Provider
 * differences are handled purely by config (no provider specifics live here).
 *
 * Env config (each provider cap is offered only when the evidence URL AND its field are set,
 * all off the SAME route):
 *   ANTSEED_TEE_PEER_ID                    this node's peer id (EVM address, no 0x) — required
 *   ANTSEED_VERIFIER_NODE_TEE              seller-node-tee-genuine source: "configfs" (default), "dstack", or "http"
 *   ANTSEED_VERIFIER_DSTACK_SOCKET         override the dstack guest-agent socket path (default /var/run/dstack.sock)
 *   ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL provider evidence route ({nonce} hex placeholder); enables seller-provider-tee-genuine via http
 *   ANTSEED_VERIFIER_PROVIDER_TEE_FIELD    JSON field holding the base64 provider quote (default "quote")
 *   ANTSEED_VERIFIER_PROVIDER_GPU_FIELD    JSON field holding the provider's GPU CC evidence; enables seller-provider-gpu-cc
 *   ANTSEED_VERIFIER_PROVIDER_CLAIMS_FIELD JSON field holding the provider's base64 claims document; enables seller-provider-claims
 *   ANTSEED_VERIFIER_PROVIDER_BINDING_SCHEME       frozen report_data scheme the provider quote uses (e.g. "nonce-pubkey-sha256-v1"); buyer then verifies round binding
 *   ANTSEED_VERIFIER_PROVIDER_BINDING_PUBKEY_FIELD JSON field holding the provider's base64 E2E pubkey (the ingredient that scheme binds)
 *   ANTSEED_VERIFIER_SIGNING_KEY           seller identity private key (hex) for seller-bound
 */

const PEER_ID_KEY = 'ANTSEED_TEE_PEER_ID'
const SIGNING_KEY = 'ANTSEED_VERIFIER_SIGNING_KEY'
const NODE_TEE_SOURCE = 'ANTSEED_VERIFIER_NODE_TEE'
const DSTACK_SOCKET = 'ANTSEED_VERIFIER_DSTACK_SOCKET'
const PROVIDER_EVIDENCE_URL = 'ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL'
const PROVIDER_TEE_FIELD = 'ANTSEED_VERIFIER_PROVIDER_TEE_FIELD'
const PROVIDER_GPU_FIELD = 'ANTSEED_VERIFIER_PROVIDER_GPU_FIELD'
const PROVIDER_CLAIMS_FIELD = 'ANTSEED_VERIFIER_PROVIDER_CLAIMS_FIELD'
const PROVIDER_BINDING_SCHEME = 'ANTSEED_VERIFIER_PROVIDER_BINDING_SCHEME'
const PROVIDER_BINDING_PUBKEY_FIELD = 'ANTSEED_VERIFIER_PROVIDER_BINDING_PUBKEY_FIELD'

function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function json(statusCode: number, body: unknown): SellerResponse {
  return {
    statusCode,
    headers: { 'content-type': 'application/json' },
    body: new TextEncoder().encode(JSON.stringify(body)),
  }
}

/**
 * Generic, provider-neutral collector config, namespaced per TDX cap so the node cap and
 * the provider cap never collide. The node cap defaults to a local configfs quote; the
 * provider cap is offered (via http) only when a provider evidence URL is configured.
 */
function baseConfig(): Record<string, string> {
  const cfg: Record<string, string> = {}
  // seller-node-tee-genuine: mint the quote locally; default to configfs when unset.
  cfg[tdxConfigKey(NODE_TEE_CAP_ID, 'source')] = process.env[NODE_TEE_SOURCE]?.trim() || 'configfs'
  // Optional dstack guest-agent socket override (Phala CVMs); default locations are used when unset.
  const dstackSocket = process.env[DSTACK_SOCKET]?.trim()
  if (dstackSocket) cfg[tdxConfigKey(NODE_TEE_CAP_ID, 'dstack.socket')] = dstackSocket
  // seller-provider-tee-genuine: only offered when a provider evidence route is configured.
  const provUrl = process.env[PROVIDER_EVIDENCE_URL]?.trim()
  if (provUrl) {
    cfg[tdxConfigKey(PROVIDER_TEE_CAP_ID, 'source')] = 'http'
    cfg[tdxConfigKey(PROVIDER_TEE_CAP_ID, 'url')] = provUrl
    cfg[tdxConfigKey(PROVIDER_TEE_CAP_ID, 'field')] = process.env[PROVIDER_TEE_FIELD]?.trim() || 'quote'
    // Optional: declare the provider's frozen report_data scheme so the buyer verifies the
    // provider quote is bound to THIS round + instance (e.g. Chutes' nonce-pubkey-sha256-v1).
    const bindingScheme = process.env[PROVIDER_BINDING_SCHEME]?.trim()
    if (bindingScheme) {
      cfg[tdxConfigKey(PROVIDER_TEE_CAP_ID, 'binding.scheme')] = bindingScheme
      const pubkeyField = process.env[PROVIDER_BINDING_PUBKEY_FIELD]?.trim()
      if (pubkeyField) cfg[tdxConfigKey(PROVIDER_TEE_CAP_ID, 'binding.pubkeyField')] = pubkeyField
    }
    // seller-provider-gpu-cc: same evidence route, but only offered when a GPU field is named.
    const gpuField = process.env[PROVIDER_GPU_FIELD]?.trim()
    if (gpuField) {
      cfg[gpuConfigKey('url')] = provUrl
      cfg[gpuConfigKey('field')] = gpuField
    }
    // seller-provider-claims: same evidence route, only offered when a claims field is named.
    const claimsField = process.env[PROVIDER_CLAIMS_FIELD]?.trim()
    if (claimsField) {
      cfg[claimsConfigKey('url')] = provUrl
      cfg[claimsConfigKey('field')] = claimsField
    }
  }
  return cfg
}

/**
 * A signer for seller-bound, built from the seller's private key. Returns undefined when
 * no key is set (cap not offered) or the key's address does not match this node's peer id
 * (a mismatch would only fail on the buyer, so we disable it and log instead).
 */
function buildSigner(peerId: string): ((m: Uint8Array) => Promise<Uint8Array>) | undefined {
  const key = process.env[SIGNING_KEY]?.trim()
  if (!key) return undefined
  try {
    if (evmAddressFromPrivateKey(key) !== peerId) {
      process.stderr.write(`[${VERIFIER_ID}] ${SIGNING_KEY} address != ${PEER_ID_KEY}; seller-bound disabled\n`)
      return undefined
    }
    return signerFromPrivateKey(key)
  } catch (err) {
    process.stderr.write(`[${VERIFIER_ID}] invalid ${SIGNING_KEY}; seller-bound disabled: ${msg(err)}\n`)
    return undefined
  }
}

const prover: Prover = {
  type: 'prover',
  name: VERIFIER_ID,
  displayName: 'TEE attestation prover (capability-based)',
  version: '0.1.0',
  description: 'Produces per-capability seller attestation evidence (Intel TDX quote, seller-identity signature) for buyers to verify.',

  async prove(req: SellerRequest): Promise<SellerResponse> {
    const rawPeer = process.env[PEER_ID_KEY]?.trim()
    if (!rawPeer) {
      return json(500, {
        error: { message: `${PEER_ID_KEY} is not set; the prover must know this node's peer id (EVM address)`, type: 'tee_error' },
      })
    }
    let peerId: string
    try {
      peerId = normalizePeerId(rawPeer)
    } catch (err) {
      return json(500, { error: { message: msg(err), type: 'tee_error' } })
    }

    let nonce: Uint8Array
    let caps: string[]
    try {
      ;({ nonce, caps } = decodeAttestRequest(req.body ?? new Uint8Array()))
    } catch (err) {
      return json(400, { error: { message: msg(err), type: 'invalid_request_error' } })
    }

    const config = baseConfig()
    const sign = buildSigner(peerId)

    const evidence: Record<string, Uint8Array> = {}
    // Registry order guarantees a dependency (tee-tdx) is collected before its dependents.
    for (const cap of listCapabilities()) {
      if (!caps.includes(cap.id) || !cap.collect) continue
      try {
        const bytes = await cap.collect({ nonce, peerId, config, sign })
        evidence[cap.id] = bytes
        // Expose to later dependent collectors (seller-bound binds to the tee-tdx evidence).
        config[evidenceConfigKey(cap.id)] = Buffer.from(bytes).toString('base64')
      } catch (err) {
        // Unsupported by this seller's infra (or a dependency was missing) — omit the cap.
        process.stderr.write(`[${VERIFIER_ID}] capability "${cap.id}" not offered: ${msg(err)}\n`)
      }
    }

    return { statusCode: 200, headers: { 'content-type': 'application/json' }, body: encodeAttestResponse(evidence) }
  },
}

export default prover
