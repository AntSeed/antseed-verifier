import type { ClaimResult } from '@antseed/node'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import type { Capability, CapabilityCollectInput, CapabilityVerifyInput } from '../capability.js'
import type { ParsedTdxQuote } from './tee-tdx.js'
import { claimId, evidenceConfigKey, normalizePeerId, sellerBoundPreimage } from '../shared.js'

/**
 * Capability 'seller-bound': turns provider verification into SELLER verification. The
 * seller signs the seller-bound preimage (keccak256 over nonce ‖ sha256(tdx evidence) ‖
 * peerId) with its AntSeed identity key. The buyer recovers the signer's EVM address and
 * requires it to equal the peer id. Freshness (nonce) + identity (peerId) live entirely
 * here, independent of what the quote's own report_data binds — so it works even when the
 * TDX quote binds a provider key rather than the seller's peer id.
 */

const CAP_ID = 'seller-bound'
const TEE_TDX_ID = 'tee-tdx-genuine'

/** Recover the 40-hex (lowercase, no 0x) EVM address that produced an r‖s‖v signature. */
export function recoverEvmAddress(digest: Uint8Array, sig: Uint8Array): string {
  if (sig.length !== 65) throw new Error(`signature must be 65 bytes, got ${sig.length}`)
  const recovery = sig[64]! >= 27 ? sig[64]! - 27 : sig[64]!
  if (recovery !== 0 && recovery !== 1) throw new Error(`invalid recovery byte: ${sig[64]}`)
  // noble's recovered format is v(1) ‖ r(32) ‖ s(32); repack our r‖s‖v into it.
  const noble = new Uint8Array(65)
  noble[0] = recovery
  noble.set(sig.subarray(0, 64), 1)
  const compressed = secp256k1.recoverPublicKey(noble, digest, { prehash: false })
  const uncompressed = secp256k1.Point.fromBytes(compressed).toBytes(false) // 0x04 ‖ X ‖ Y
  return bytesToHex(keccak_256(uncompressed.subarray(1)).subarray(-20))
}

/** Build a signer over 32-byte digests from a hex private key, emitting r‖s‖v (v = 27/28). */
export function signerFromPrivateKey(privHex: string): (msg: Uint8Array) => Promise<Uint8Array> {
  const priv = hexToBytes(privHex.replace(/^0x/i, ''))
  if (priv.length !== 32) throw new Error(`private key must be 32 bytes, got ${priv.length}`)
  return async (msg: Uint8Array): Promise<Uint8Array> => {
    // prehash:false — msg is already the 32-byte keccak preimage digest, sign it directly.
    const recovered = secp256k1.sign(msg, priv, { prehash: false, format: 'recovered' })
    const out = new Uint8Array(65)
    out.set(recovered.subarray(1), 0) // r ‖ s
    out[64] = recovered[0]! + 27 // v
    return out
  }
}

/** The 40-hex EVM address a private key corresponds to (for seller-side consistency checks). */
export function evmAddressFromPrivateKey(privHex: string): string {
  const priv = hexToBytes(privHex.replace(/^0x/i, ''))
  const uncompressed = secp256k1.getPublicKey(priv, false)
  return bytesToHex(keccak_256(uncompressed.subarray(1)).subarray(-20))
}

export const sellerBoundCapability: Capability = {
  id: CAP_ID,

  verify(input: CapabilityVerifyInput): ClaimResult {
    const claim = claimId(CAP_ID)
    if (!input.evidence) return { claim, ok: false, detail: 'seller returned no identity signature' }
    const p = input.parsedQuote as ParsedTdxQuote | undefined
    if (!p) return { claim, ok: false, detail: 'seller-bound requires a tee-tdx quote to bind to' }
    let peerId: string
    try {
      peerId = normalizePeerId(input.peerId)
    } catch (err) {
      return { claim, ok: false, detail: err instanceof Error ? err.message : String(err) }
    }
    const preimage = sellerBoundPreimage(input.nonce, p.quoteEvidence, peerId)
    let signer: string
    try {
      signer = recoverEvmAddress(preimage, input.evidence)
    } catch (err) {
      return { claim, ok: false, detail: `signature recovery failed: ${err instanceof Error ? err.message : String(err)}` }
    }
    if (signer !== peerId) {
      return { claim, ok: false, detail: `signer ${signer.slice(0, 10)}… does not match peer ${peerId.slice(0, 10)}…` }
    }
    return { claim, ok: true, detail: `seller identity ${peerId.slice(0, 10)}… signed this quote (fresh nonce bound)` }
  },

  async collect(input: CapabilityCollectInput): Promise<Uint8Array> {
    if (!input.sign) throw new Error('seller-bound requires a signer (seller identity key); not offered')
    const teeB64 = input.config[evidenceConfigKey(TEE_TDX_ID)]
    if (!teeB64) throw new Error('seller-bound requires tee-tdx evidence to bind to; collect tee-tdx first')
    const quoteEvidence = new Uint8Array(Buffer.from(teeB64, 'base64'))
    const preimage = sellerBoundPreimage(input.nonce, quoteEvidence, input.peerId)
    const sig = await input.sign(preimage)
    if (sig.length !== 65) throw new Error(`signer returned ${sig.length}-byte signature, expected 65 (r‖s‖v)`)
    return sig
  },
}
