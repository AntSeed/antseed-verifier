import type { ClaimResult } from '@antseed/node'
import type { Capability } from '../capability.js'
import { claimId } from '../shared.js'

/**
 * Capability 'seller-provider-gpu-cc': STUB. Registered so the menu advertises it, but not
 * yet implemented — a real version would verify the inference provider's NVIDIA Confidential
 * Computing GPU attestation via NRAS (NVIDIA Remote Attestation Service). Left for a later pass.
 */

const CAP_ID = 'seller-provider-gpu-cc'

export const gpuNvidiaCapability: Capability = {
  id: CAP_ID,
  verify(): ClaimResult {
    return { claim: claimId(CAP_ID), ok: false, detail: 'seller-provider-gpu-cc not yet implemented (NRAS)' }
  },
}
