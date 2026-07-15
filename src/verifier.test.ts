import { describe, it, expect } from 'vitest'
import { randomBytes } from 'node:crypto'
import type { SellerRequest, SellerResponse, VerifyContext } from '@antseed/node'
import { runVerify } from './verifier.js'
import {
  ATTEST_PATH,
  VERIFIER_ID,
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

const TEE = claimId('tee-tdx-genuine')
const BOUND = claimId('seller-bound')
const MEASURED = claimId('measured-image')

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

/** Stub DCAP: genuine TDX, current TCB. */
const okVerify: VerifyQuoteFn = async () => ({ status: 'UpToDate', td: td() })

const ok200 = (body: Uint8Array): SellerResponse => ({ statusCode: 200, headers: {}, body })

/** A well-formed response evidencing both required caps for the buyer's nonce. */
async function fullEvidence(nonce: Uint8Array, signer = sign): Promise<Uint8Array> {
  const teeEv = encodeTeeTdxEvidence(randomBytes(64))
  const sbSig = await signer(sellerBoundPreimage(nonce, teeEv, PEER))
  return encodeAttestResponse({ 'tee-tdx-genuine': teeEv, 'seller-bound': sbSig })
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
    const { ctx, seen } = makeCtx(async (nonce) => ok200(await fullEvidence(nonce)))
    await runVerify(ctx, okVerify)
    expect(seen.req?.method).toBe('POST')
    expect(seen.req?.path).toBe(ATTEST_PATH)
    expect(seen.req?.headers?.['content-type']).toBe('application/json')
    expect(seen.nonce?.length).toBe(32)
    expect(seen.caps).toEqual(expect.arrayContaining(['tee-tdx-genuine', 'seller-bound', 'measured-image', 'gpu-nvidia-cc']))
  })
})

describe('runVerify — happy path (one claim per capability)', () => {
  it('passes when tee-tdx + seller-bound verify, and reports measured-image informationally', async () => {
    const { ctx } = makeCtx(async (nonce) => ok200(await fullEvidence(nonce)))
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(true)
    expect(findClaim(r, TEE)?.ok).toBe(true)
    expect(findClaim(r, BOUND)?.ok).toBe(true)
    // measured-image is verified (derives from the tdx quote) but never passes without policy.
    expect(findClaim(r, MEASURED)?.ok).toBe(false)
    expect(findClaim(r, MEASURED)?.detail).toMatch(/no approved measurement set configured/)
  })
})

describe('runVerify — required caps gate ok (all return ok:false, never throw)', () => {
  it('fails overall when tee-tdx TCB is unacceptable', async () => {
    const outOfDate: VerifyQuoteFn = async () => ({ status: 'OutOfDate', td: td() })
    const { ctx } = makeCtx(async (nonce) => ok200(await fullEvidence(nonce)))
    const r = await runVerify(ctx, outOfDate)
    expect(r.ok).toBe(false)
    expect(findClaim(r, TEE)?.ok).toBe(false)
    expect(findClaim(r, TEE)?.detail).toMatch(/TCB status not acceptable/)
    // seller-bound is independent of the quote's TCB, so it still passes.
    expect(findClaim(r, BOUND)?.ok).toBe(true)
  })

  it('fails overall when seller-bound is signed by the wrong key', async () => {
    const { ctx } = makeCtx(async (nonce) => ok200(await fullEvidence(nonce, signerFromPrivateKey('04'.repeat(32)))))
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(false)
    expect(findClaim(r, TEE)?.ok).toBe(true)
    expect(findClaim(r, BOUND)?.ok).toBe(false)
    expect(findClaim(r, BOUND)?.detail).toMatch(/does not match peer/)
  })

  it('fails when the seller omits all evidence', async () => {
    const { ctx } = makeCtx(() => ok200(encodeAttestResponse({})))
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(false)
    expect(findClaim(r, TEE)?.ok).toBe(false)
    expect(findClaim(r, BOUND)?.ok).toBe(false)
  })

  it('fails when DCAP verification throws', async () => {
    const throwing: VerifyQuoteFn = async () => { throw new Error('bad signature') }
    const { ctx } = makeCtx(async (nonce) => ok200(await fullEvidence(nonce)))
    const r = await runVerify(ctx, throwing)
    expect(r.ok).toBe(false)
    expect(findClaim(r, TEE)?.detail).toMatch(/quote verification failed: bad signature/)
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
    expect(onlyRequired(r)).toEqual([BOUND, TEE].sort())
  })

  it('fails on a malformed (non-JSON) response body', async () => {
    const { ctx } = makeCtx(() => ok200(new TextEncoder().encode('not json')))
    const r = await runVerify(ctx, okVerify)
    expect(r.ok).toBe(false)
    expect(r.claims[0]?.detail).toMatch(/malformed attestation response/)
  })

  it('fails on an invalid peer id', async () => {
    const { ctx } = makeCtx(async (nonce) => ok200(await fullEvidence(nonce)), 'not-a-peer')
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
