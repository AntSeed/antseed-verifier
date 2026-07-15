import { describe, it, expect } from 'vitest'
import { randomBytes } from 'node:crypto'
import { gpuNvidiaCapability } from './gpu-nvidia.js'
import { claimId } from '../shared.js'

describe('seller-provider-gpu-cc capability (stub)', () => {
  it('is registered in the menu but reports not-implemented', () => {
    const r = gpuNvidiaCapability.verify({ nonce: randomBytes(32), peerId: 'f'.repeat(40) })
    expect(r).toMatchObject({ claim: claimId('seller-provider-gpu-cc'), ok: false })
    expect(r.detail).toMatch(/not yet implemented \(NRAS\)/)
  })
  it('has no collector (nothing for a seller to produce yet)', () => {
    expect(gpuNvidiaCapability.collect).toBeUndefined()
  })
})
