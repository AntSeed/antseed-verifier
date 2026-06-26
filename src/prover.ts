import type { AntseedProviderPlugin, Provider } from '@antseed/node'
import { generateTdxQuote } from './tee.js'
import {
  ATTEST_SERVICE_ID,
  computeReportData,
  decodeAttestRequestNonce,
  encodeAttestResponse,
  normalizePeerId,
} from './shared.js'

/**
 * SELLER half. A normal AntSeed provider that serves ONE free service
 * (ATTEST_SERVICE_ID). On each request it reads the buyer's nonce, generates a
 * fresh Intel TDX quote over report_data = SHA-512(nonce ‖ peerId), and returns
 * it. Runs only on a real TDX VM (quote generation needs configfs-tsm).
 */

// SerializedHttpRequest/Response are not re-exported from @antseed/node's public
// entry, so derive them structurally from the Provider contract.
type Req = Parameters<Provider['handleRequest']>[0]
type Res = Awaited<ReturnType<Provider['handleRequest']>>

/** Env var / config key carrying this node's peer id (EVM address, no 0x). */
const PEER_ID_KEY = 'ANTSEED_TEE_PEER_ID'

function jsonResponse(requestId: string, statusCode: number, body: unknown): Res {
  return {
    requestId,
    statusCode,
    headers: { 'content-type': 'application/json' },
    body: new TextEncoder().encode(JSON.stringify(body)),
  }
}

class TeeAttestProvider implements Provider {
  readonly name = '@refoundhq/antseed-verifier'
  readonly services = [ATTEST_SERVICE_ID]
  // Free: zero on every axis → the seller skips ReserveAuth/402 for this service.
  readonly pricing: Provider['pricing'] = {
    defaults: { inputUsdPerMillion: 0, outputUsdPerMillion: 0, cachedInputUsdPerMillion: 0 },
  }
  readonly maxConcurrency: number
  private readonly _peerId: string
  private _current = 0

  constructor(peerId: string, maxConcurrency: number) {
    this._peerId = normalizePeerId(peerId)
    this.maxConcurrency = maxConcurrency
  }

  async handleRequest(req: Req): Promise<Res> {
    this._current++
    try {
      let nonce: Uint8Array
      try {
        nonce = decodeAttestRequestNonce(req.body)
      } catch (err) {
        return jsonResponse(req.requestId, 400, {
          error: { message: err instanceof Error ? err.message : String(err), type: 'invalid_request_error' },
        })
      }
      try {
        const reportData = computeReportData(nonce, this._peerId)
        const quote = generateTdxQuote(reportData)
        return {
          requestId: req.requestId,
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          body: encodeAttestResponse(quote),
        }
      } catch (err) {
        return jsonResponse(req.requestId, 500, {
          error: { message: `TDX quote generation failed: ${err instanceof Error ? err.message : String(err)}`, type: 'tee_error' },
        })
      }
    } finally {
      this._current--
    }
  }

  getCapacity(): { current: number; max: number } {
    return { current: this._current, max: this.maxConcurrency }
  }
}

const plugin: AntseedProviderPlugin = {
  type: 'provider',
  name: '@refoundhq/antseed-verifier',
  displayName: 'TEE attestation prover (Intel TDX)',
  version: '0.1.0',
  description: 'Serves a free Intel TDX attestation service so buyers can verify this seller runs in a genuine enclave.',
  configSchema: [
    {
      key: PEER_ID_KEY,
      label: 'Peer ID',
      type: 'string',
      required: true,
      description: 'This node\'s 40-hex peer id (EVM address, no 0x). Bound into the TDX report_data so the quote is attributable to this seller. Set by the launcher.',
    },
    {
      key: 'ANTSEED_MAX_CONCURRENCY',
      label: 'Max Concurrency',
      type: 'number',
      required: false,
      default: 4,
      description: 'Max concurrent attestation requests.',
    },
  ],
  createProvider(config: Record<string, string>): Provider {
    const peerId = config[PEER_ID_KEY]?.trim()
    if (!peerId) {
      throw new Error(`${PEER_ID_KEY} is required: the prover must know this node's peer id (EVM address) to bind it into the TDX report_data`)
    }
    const maxConcurrency = parseInt(config['ANTSEED_MAX_CONCURRENCY'] ?? '4', 10)
    if (Number.isNaN(maxConcurrency) || maxConcurrency <= 0) {
      throw new Error('ANTSEED_MAX_CONCURRENCY must be a positive number')
    }
    return new TeeAttestProvider(peerId, maxConcurrency)
  },
}

export default plugin
