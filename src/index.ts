import verifierPlugin from './verifier.js'
import proverPlugin from './prover.js'

/**
 * One package, two halves — both named `refoundhq-antseed-verifier`. The monorepo
 * plugin loader imports this module and picks the export matching the requested kind:
 *   - type:'verifier' -> the default export (buyer half)
 *   - type:'prover'   -> the `prover` export  (seller half; embedded, not a provider)
 */
export default verifierPlugin
export const prover = proverPlugin

// Capability model — the menu, its registry, and helpers.
export type {
  Capability,
  CapabilityVerifyInput,
  CapabilityCollectInput,
} from './capability.js'
export {
  registerCapability,
  getCapability,
  listCapabilities,
  capabilityIds,
} from './capability.js'
export {
  teeTdxCapability,
  sellerBoundCapability,
  measuredImageCapability,
  gpuNvidiaCapability,
} from './caps/index.js'

// Buyer-side orchestration + the injectable DCAP seam (useful for tooling/tests).
export { runVerify } from './verifier.js'
export { defaultVerifyQuote, verifyTdxEvidence } from './caps/tee-tdx.js'
export type { VerifyQuoteFn, RawTdxVerification, ParsedTdxQuote, TdMeasurements } from './caps/tee-tdx.js'
export type { ApprovedMeasurement, MeasuredImagePolicy } from './caps/measured-image.js'

// Shared constants + helpers.
export {
  VERIFIER_ID,
  ATTEST_PATH,
  claimId,
  computeReportData,
  sellerBoundPreimage,
} from './shared.js'
