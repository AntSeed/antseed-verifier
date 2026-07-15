import { registerCapability } from '../capability.js'
import { nodeTeeCapability, providerTeeCapability } from './tee-tdx.js'
import { sellerBoundCapability } from './seller-bound.js'
import { measuredImageCapability } from './measured-image.js'
import { gpuNvidiaCapability } from './gpu-nvidia.js'

/**
 * Registration order defines both the advertised menu order and the seller's collect
 * order. Both TDX caps come first because seller-bound signs over their evidence (the
 * whole bundle) and measured-image derives from the provider quote — so seller-bound
 * MUST be registered after both TDX caps to see them when it collects.
 */
registerCapability(nodeTeeCapability)
registerCapability(providerTeeCapability)
registerCapability(sellerBoundCapability)
registerCapability(measuredImageCapability)
registerCapability(gpuNvidiaCapability)

export { nodeTeeCapability, providerTeeCapability, sellerBoundCapability, measuredImageCapability, gpuNvidiaCapability }
