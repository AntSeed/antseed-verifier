import { registerCapability } from '../capability.js'
import { nodeTeeCapability, providerTeeCapability } from './tee-tdx.js'
import { sellerBoundCapability } from './seller-bound.js'
import { measuredImageCapability } from './measured-image.js'
import { gpuNvidiaCapability } from './gpu-nvidia.js'
import { providerClaimsCapability } from './provider-claims.js'

/**
 * Registration order defines both the advertised menu order and the seller's collect order.
 * INVARIANT: seller-bound signs over the WHOLE bundle, so every evidence-producing cap (the
 * TDX caps, gpu-cc AND provider-claims) MUST be registered BEFORE seller-bound, so they are
 * already collected when it builds the digest it signs. measured-image derives from the
 * provider quote (no own evidence), so its position is immaterial.
 */
registerCapability(nodeTeeCapability)
registerCapability(providerTeeCapability)
registerCapability(gpuNvidiaCapability)
registerCapability(providerClaimsCapability)
registerCapability(sellerBoundCapability)
registerCapability(measuredImageCapability)

export { nodeTeeCapability, providerTeeCapability, sellerBoundCapability, measuredImageCapability, gpuNvidiaCapability, providerClaimsCapability }
