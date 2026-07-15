import { describe, it, expect } from 'vitest'
import { randomBytes } from 'node:crypto'
import type { SellerRequest, SellerResponse, VerifyContext } from '@antseed/node'
import { runVerify } from './verifier.js'
import {
  ATTEST_PATH,
  VERIFIER_ID,
  bundleDigest,
  claimId,
  decodeAttestRequest,
  encodeAttestResponse,
  sellerBoundPreimage,
} from './shared.js'
import { encodeTeeTdxEvidence, type TdMeasurements, type VerifyQuoteFn } from './caps/tee-tdx.js'
import { evmAddressFromPrivateKey, signerFromPrivateKey } from './caps/seller-bound.js'

// A real seller keypair — seller-bound signatures must recover to this peer id.
const PRIV = '03'.repeat(32)
const PEER = evmAddressFromPrivateKey(PRIV)
const sign = signerFromPrivateKey(PRIV)

const NODE = claimId('seller-node-tee-genuine')
const PROVIDER = claimId('seller-provider-tee-genuine')
const BOUND = claimId('seller-bound')
const MEASURED = claimId('seller-provider-measured-image')

function td(over: Partial<TdMeasurements> = {}): TdMeasurements {
  return {
    mrTd: new Uint8Array(48).fill(7),
    rtMr0: new Uint8Array(48),
    rtMr1: new Uint8Array(48),
    rtMr2: new Uint8Array(48),
    rtMr3: new Uint8Array(48),
    reportData: new Uint8Array(64),
    debug: false,
    ...over,
  }
}

/** Stub DCAP: genuine TDX, current TCB (applied to every quote in the round). */
const okVerify: VerifyQuoteFn = async () => ({ status: 'UpToDate', td: td() })

const ok200 = (body: Uint8Array): SellerResponse => ({ statusCode: 200, headers: {}, body })

/** seller-bound signature over the given evidence bundle (as the prover would produce it). */
async function signBundle(nonce: Uint8Array, bundle: Record<string, Uint8Array>, signer = sign): Promise<Uint8Array> {
  return signer(sellerBoundPreimage(nonce, bundleDigest(bundle), PEER))
}

/** Minimal required bundle: the node quote + a seller-bound signature over it. */
async function nodeEvidence(nonce: Uint8Array, signer = sign): Promise<Uint8Array> {
  const bundle = { 'seller-node-tee-genuine': encodeTeeTdxEvidence(randomBytes(64)) }
  return encodeAttestResponse({ ...bundle, 'seller-bound': await signBundle(nonce, bundle, signer) })
}

/** Full bundle: node quote + provider quote + one seller-bound signature covering both. */
async function fullBundleEvidence(nonce: Uint8Array, signer = sign): Promise<Uint8Array> {
  const bundle = {
    'seller-node-tee-genuine': encodeTeeTdxEvidence(randomBytes(64)),
    'seller-provider-tee-genuine': encodeTeeTdxEvidence(randomBytes(64)),
  }
  return encodeAttestResponse({ ...bundle, 'seller-bound': await signBundle(nonce, bundle, signer) })
}

function makeCtx(
  responder: (nonce: Uint8Array, caps: string[]) => SellerResponse | Promise<SellerResponse>,
  peerId = PEER,
): { ctx: VerifyContext; seen: { req?: SellerRequest; nonce?: Uint8Array; caps?: string[] } } {
  const seen: { req?: SellerRequest; nonce?: Uint8Array; caps?: string[] } = {}
  const ctx: VerifyContext = {
    peerId,
    verifierId: VERIFIER_ID,
    attestPath: ATTEST_PATH,
    fetchFromSeller: async (req) => {
      const { nonce, caps } = decodeAttestRequest(req.body ?? new Uint8Array())
      seen.req = req
      seen.nonce = nonce
      seen.caps = caps
      return responder(nonce, caps)
    },
  }
  return { ctx, seen }
}

const findClaim = (r: { claims: { claim: string; ok: boolean; detail?: string }[] }, id: string) =>
  r.claims.find((c) => c.claim === id)

describe('runVerify — request shape', () => {
  it('POSTs the reserved path with a 32-byte nonce and the full cap menu', async () => {
    const { ctx, seen } = makeCtx(async (nonce) => ok200(await nodeEvidence(nonce)))
    await runVerify(ctx, okVerify)
    expect(seen.req?.method).toBe('POST')
    expect(seen.req?.path).toBe(ATTEST_PATH)
    expect(seen.req?.headers?.['content-type']).toBe('application/json')
    expect(seen.nonce?.length).toBe(32)
    expect(seen.caps).toEqual(
      expect.arrayContaining([
        'seller-node-tee-genuine',
        'seller-provider-tee-genuine',
        'seller-bound',
        'seller-provider-measured-image',
        'seller-provider-gpu-cc',
      ]),
    )
  })
})

describe('runVerify — happy path (one claim per capability)', () => {
  it('passes on node tee + seller-bound; reports provider tee + measured-image', async () => {
    const { ctx } = makeCtx(async (nonce) => ok200(await fullBundleEvidence(nonce)))
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(true)
    expect(findClaim(r, NODE)?.ok).toBe(true)
    expect(findClaim(r, BOUND)?.ok).toBe(true)
    // provider tee is present + genuine, but informational (not in the required set).
    expect(findClaim(r, PROVIDER)?.ok).toBe(true)
    // measured-image derives from the provider quote but never passes without a policy.
    expect(findClaim(r, MEASURED)?.ok).toBe(false)
    expect(findClaim(r, MEASURED)?.detail).toMatch(/no approved measurement set configured/)
  })
})

describe('runVerify — required caps gate ok (all return ok:false, never throw)', () => {
  it('fails overall when the node tee TCB is unacceptable', async () => {
    const outOfDate: VerifyQuoteFn = async () => ({ status: 'OutOfDate', td: td() })
    const { ctx } = makeCtx(async (nonce) => ok200(await nodeEvidence(nonce)))
    const r = await runVerify(ctx, outOfDate)
    expect(r.ok).toBe(false)
    expect(findClaim(r, NODE)?.ok).toBe(false)
    expect(findClaim(r, NODE)?.detail).toMatch(/TCB status not acceptable/)
    // seller-bound is independent of the quote's TCB, so it still passes.
    expect(findClaim(r, BOUND)?.ok).toBe(true)
  })

  it('fails overall when seller-bound is signed by the wrong key', async () => {
    const { ctx } = makeCtx(async (nonce) => ok200(await nodeEvidence(nonce, signerFromPrivateKey('04'.repeat(32)))))
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(false)
    expect(findClaim(r, NODE)?.ok).toBe(true)
    expect(findClaim(r, BOUND)?.ok).toBe(false)
    expect(findClaim(r, BOUND)?.detail).toMatch(/does not match peer/)
  })

  it('fails when the seller omits all evidence', async () => {
    const { ctx } = makeCtx(() => ok200(encodeAttestResponse({})))
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(false)
    expect(findClaim(r, NODE)?.ok).toBe(false)
    expect(findClaim(r, BOUND)?.ok).toBe(false)
  })

  it('fails closed when a required cap (node tee) evidence is missing', async () => {
    // Seller returns only the provider quote + a valid seller-bound over it — but node tee is required.
    const { ctx } = makeCtx(async (nonce) => {
      const bundle = { 'seller-provider-tee-genuine': encodeTeeTdxEvidence(randomBytes(64)) }
      return ok200(encodeAttestResponse({ ...bundle, 'seller-bound': await signBundle(nonce, bundle) }))
    })
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(false)
    expect(findClaim(r, NODE)?.ok).toBe(false)
    expect(findClaim(r, NODE)?.detail).toMatch(/no TDX quote/)
    // Non-required caps are fine; the overall verdict still fails on the missing required node cap.
    expect(findClaim(r, PROVIDER)?.ok).toBe(true)
    expect(findClaim(r, BOUND)?.ok).toBe(true)
  })

  it('fails when DCAP verification throws', async () => {
    const throwing: VerifyQuoteFn = async () => { throw new Error('bad signature') }
    const { ctx } = makeCtx(async (nonce) => ok200(await nodeEvidence(nonce)))
    const r = await runVerify(ctx, throwing)
    expect(r.ok).toBe(false)
    expect(findClaim(r, NODE)?.detail).toMatch(/quote verification failed: bad signature/)
  })
})

describe('runVerify — transport failures fail every required cap', () => {
  const onlyRequired = (r: { claims: { claim: string }[] }) =>
    r.claims.map((c) => c.claim).sort()

  it('fails on a non-200 attestation response', async () => {
    const { ctx } = makeCtx(() => ({ statusCode: 402, headers: {}, body: new Uint8Array() }))
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(false)
    expect(r.claims.every((c) => !c.ok)).toBe(true)
    expect(r.claims[0]?.detail).toMatch(/HTTP 402/)
    expect(onlyRequired(r)).toEqual([BOUND, NODE].sort())
  })

  it('fails on a malformed (non-JSON) response body', async () => {
    const { ctx } = makeCtx(() => ok200(new TextEncoder().encode('not json')))
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(false)
    expect(r.claims[0]?.detail).toMatch(/malformed attestation response/)
  })

  it('fails on an invalid peer id', async () => {
    const { ctx } = makeCtx(async (nonce) => ok200(await nodeEvidence(nonce)), 'not-a-peer')
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(false)
    expect(r.claims[0]?.detail).toMatch(/invalid peerId/)
  })

  it('fails when fetchFromSeller rejects', async () => {
    const ctx: VerifyContext = {
      peerId: PEER,
      verifierId: VERIFIER_ID,
      attestPath: ATTEST_PATH,
      fetchFromSeller: async () => { throw new Error('peer unreachable') },
    }
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(false)
    expect(r.claims[0]?.detail).toMatch(/attestation request failed: peer unreachable/)
  })
})
