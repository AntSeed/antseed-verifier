import { registerCapability } from '../capability.js'
import { nodeTeeCapability, providerTeeCapability } from './tee-tdx.js'
import { sellerBoundCapability } from './seller-bound.js'
import { measuredImageCapability } from './measured-image.js'
import { gpuNvidiaCapability } from './gpu-nvidia.js'
import { providerClaimsCapability } from './provider-claims.js'

/**
 * Registration order defines both the advertised menu order and the seller's collect
 * order. seller-bound signs over the WHOLE bundle, so every cap that produces evidence
 * (the TDX caps, the GPU-CC cap AND the provider-claims cap) MUST be registered BEFORE
 * seller-bound, so they are already collected and visible when seller-bound builds the
 * digest it signs. measured-image derives from the provider quote and has no own
 * evidence, so its position is immaterial.
 */
registerCapability(nodeTeeCapability)
registerCapability(providerTeeCapability)
registerCapability(gpuNvidiaCapability)
registerCapability(providerClaimsCapability)
registerCapability(sellerBoundCapability)
registerCapability(measuredImageCapability)

export { nodeTeeCapability, providerTeeCapability, sellerBoundCapability, measuredImageCapability, gpuNvidiaCapability, providerClaimsCapability }
