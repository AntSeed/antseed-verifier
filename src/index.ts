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
  nodeTeeCapability,
  providerTeeCapability,
  sellerBoundCapability,
  measuredImageCapability,
  gpuNvidiaCapability,
  providerClaimsCapability,
} from './caps/index.js'

// Provider-claims: the SDK-frozen claims menu (the per-version claim definitions buyers
// verify against) + the canonical provider report_data scheme (domain tag + the [0:32]
// commitment provider tooling computes when binding a claims document into its TDX quote).
export {
  PROVIDER_CLAIMS_CAP_ID,
  PROVIDER_CLAIMS_MENU,
  PROVIDER_REPORT_DATA_DOMAIN,
  claimsConfigKey,
  claimsReportData,
} from './caps/provider-claims.js'
export type { ProviderClaimDefinition } from './caps/provider-claims.js'

// Buyer measured-image policy loader (A5 interim; replaced by VerifyContext.policy in #713).
export { readMeasuredImagePolicy } from './verifier.js'

// Report_data binding schemes — the frozen registry the buyer verifies provider quotes against.
// antseedRdV1 is our canonical compositional scheme (the node cap is its {peerId} instance);
// noncePubkeySha256V1 is the foreign Chutes construction, replicated only to verify their quotes.
export {
  antseedRdV1,
  noncePubkeySha256V1,
  getReportDataScheme,
  verifyReportData,
  REPORT_DATA_SCHEMES,
} from './report-data.js'
export type { ReportDataScheme, BindingIngredients } from './report-data.js'
export type { ReportDataBinding } from './caps/tee-tdx.js'

// Buyer-side orchestration + the injectable DCAP seam (useful for tooling/tests).
export { runVerify } from './verifier.js'
export {
  makeTdxCap,
  defaultVerifyQuote,
  verifyTdxEvidence,
  isTcbAcceptable,
  NODE_TEE_CAP_ID,
  PROVIDER_TEE_CAP_ID,
} from './caps/tee-tdx.js'
export type { VerifyQuoteFn, RawTdxVerification, ParsedTdxQuote, TdMeasurements } from './caps/tee-tdx.js'
export type { ApprovedMeasurement, MeasuredImagePolicy } from './caps/measured-image.js'

// GPU-CC capability + its injectable buyer-side seam (NRAS now, offline local later).
export {
  makeGpuNvidiaCap,
  makeNrasGpuVerify,
  nrasGpuVerify,
  localGpuVerify,
  defaultGpuVerify,
} from './caps/gpu-nvidia.js'
export type { GpuVerifyFn, GpuVerification, NrasOptions } from './caps/gpu-nvidia.js'
export {
  NRAS_GPU_ATTEST_URL_DEFAULT,
  NRAS_JWKS_URL_DEFAULT,
  buildNrasRequest,
  verifyEar,
} from './nras.js'
export type { NvidiaGpuEvidence, NrasEvidenceItem, NrasRequest, NrasSubmitFn, EarVerification } from './nras.js'

// Shared constants + helpers.
export {
  VERIFIER_ID,
  ATTEST_PATH,
  claimId,
  computeReportData,
  bundleDigest,
  sellerBoundPreimage,
} from './shared.js'
