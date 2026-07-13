import type { Prover, SellerRequest, SellerResponse } from '@antseed/node'
import { generateTdxQuote } from './tee.js'
import {
  VERIFIER_ID,
  computeReportData,
  decodeAttestRequestNonce,
  encodeAttestResponse,
  normalizePeerId,
} from './shared.js'

/**
 * Seller half — embedded prover (type:'prover'). On each attestation request it reads
 * the buyer's nonce and returns a fresh Intel TDX quote over SHA-512(nonce ‖ peerId).
 * Runs only on a real TDX VM (quote generation needs configfs-tsm).
 */

/** This node's peer id (EVM address, no 0x), bound into the report_data so the quote is
 *  attributable to this seller. From a trusted env var, never a buyer-supplied value. */
const PEER_ID_KEY = 'ANTSEED_TEE_PEER_ID'

function json(statusCode: number, body: unknown): SellerResponse {
  return {
    statusCode,
    headers: { 'content-type': 'application/json' },
    body: new TextEncoder().encode(JSON.stringify(body)),
  }
}

const prover: Prover = {
  type: 'prover',
  name: VERIFIER_ID,
  displayName: 'TEE attestation prover (Intel TDX)',
  version: '0.1.0',
  description: 'Generates Intel TDX attestation quotes so buyers can verify this seller runs in a genuine enclave.',

  async prove(req: SellerRequest): Promise<SellerResponse> {
    const peerId = process.env[PEER_ID_KEY]?.trim()
    if (!peerId) {
      return json(500, {
        error: {
          message: `${PEER_ID_KEY} is not set; the prover must know this node's peer id (EVM address) to bind the TDX report_data`,
          type: 'tee_error',
        },
      })
    }
    let nonce: Uint8Array
    try {
      nonce = decodeAttestRequestNonce(req.body ?? new Uint8Array())
    } catch (err) {
      return json(400, { error: { message: err instanceof Error ? err.message : String(err), type: 'invalid_request_error' } })
    }
    try {
      const reportData = computeReportData(nonce, normalizePeerId(peerId))
      const quote = generateTdxQuote(reportData)
      return { statusCode: 200, headers: { 'content-type': 'application/json' }, body: encodeAttestResponse(quote) }
    } catch (err) {
      return json(500, {
        error: { message: `TDX quote generation failed: ${err instanceof Error ? err.message : String(err)}`, type: 'tee_error' },
      })
    }
  },
}

export default prover
