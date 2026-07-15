import { registerCapability } from '../capability.js'
import { teeTdxCapability } from './tee-tdx.js'
import { sellerBoundCapability } from './seller-bound.js'
import { measuredImageCapability } from './measured-image.js'
import { gpuNvidiaCapability } from './gpu-nvidia.js'

/**
 * Registration order defines both the advertised menu order and the buyer's verify
 * order. tee-tdx first because seller-bound + measured-image derive from its quote.
 */
registerCapability(teeTdxCapability)
registerCapability(sellerBoundCapability)
registerCapability(measuredImageCapability)
registerCapability(gpuNvidiaCapability)

export { teeTdxCapability, sellerBoundCapability, measuredImageCapability, gpuNvidiaCapability }
