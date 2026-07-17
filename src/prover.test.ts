import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { randomBytes } from 'node:crypto'
import prover from './prover.js'
import { decodeAttestResponse, encodeAttestRequest } from './shared.js'
import { PROVIDER_CLAIMS_CAP_ID } from './caps/provider-claims.js'

/**
 * Seller-side opt-in semantics: the prover offers ONLY the capabilities that are (a)
 * requested by the buyer AND (b) configured/supported by this seller — everything else
 * is omitted, not failed. Committing to the verifier never means committing to every claim.
 */

const PEER = 'ab'.repeat(20)
const NONCE = randomBytes(32)
const PROVIDER_TEE = 'seller-provider-tee-genuine'

const CLAIMS_DOC = new TextEncoder().encode(JSON.stringify({
  version: 1,
  claims: { 'gpu-count': { value: 8 } },
}))

const ENV_KEYS = [
  'ANTSEED_TEE_PEER_ID',
  'ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL',
  'ANTSEED_VERIFIER_PROVIDER_TEE_FIELD',
  'ANTSEED_VERIFIER_PROVIDER_CLAIMS_FIELD',
] as const
let saved: Record<string, string | undefined>

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]))
  process.env['ANTSEED_TEE_PEER_ID'] = PEER
  process.env['ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL'] = 'https://prov.example/att/{nonce}'
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      quote: Buffer.from(randomBytes(64)).toString('base64'),
      claims_doc: Buffer.from(CLAIMS_DOC).toString('base64'),
    }),
  })))
})

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k]
    else process.env[k] = saved[k]
  }
  vi.unstubAllGlobals()
})

async function attest(caps: string[]): Promise<Record<string, Uint8Array>> {
  const resp = await prover.prove({
    method: 'POST',
    path: '/_antseed/attest/refoundhq-antseed-verifier',
    headers: { 'content-type': 'application/json' },
    body: encodeAttestRequest(NONCE, caps),
  })
  expect(resp.statusCode).toBe(200)
  return decodeAttestResponse(resp.body)
}

describe('prover — provider-claims opt-in', () => {
  it('offers seller-provider-claims (verbatim doc bytes) when the claims field is configured', async () => {
    process.env['ANTSEED_VERIFIER_PROVIDER_CLAIMS_FIELD'] = 'claims_doc'
    const evidence = await attest([PROVIDER_TEE, PROVIDER_CLAIMS_CAP_ID])
    expect(evidence[PROVIDER_TEE]).toBeDefined()
    expect(Buffer.from(evidence[PROVIDER_CLAIMS_CAP_ID]!).equals(CLAIMS_DOC)).toBe(true)
  })

  it('omits seller-provider-claims when the claims field is not configured', async () => {
    delete process.env['ANTSEED_VERIFIER_PROVIDER_CLAIMS_FIELD']
    const evidence = await attest([PROVIDER_TEE, PROVIDER_CLAIMS_CAP_ID])
    expect(evidence[PROVIDER_TEE]).toBeDefined()
    expect(evidence[PROVIDER_CLAIMS_CAP_ID]).toBeUndefined()
  })

  it('omits any capability the buyer did not request, even when configured', async () => {
    process.env['ANTSEED_VERIFIER_PROVIDER_CLAIMS_FIELD'] = 'claims_doc'
    const evidence = await attest([PROVIDER_TEE])
    expect(evidence[PROVIDER_CLAIMS_CAP_ID]).toBeUndefined()
  })
})
