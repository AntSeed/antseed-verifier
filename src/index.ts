import verifierPlugin from './verifier.js'
import providerPlugin from './prover.js'

/**
 * One package, two halves — both named `@refoundhq/antseed-verifier`. The monorepo
 * plugin loader imports this module and picks the export matching the requested kind:
 *   - type:'verifier' -> the default export (buyer half)
 *   - type:'provider' -> the `prover` export  (seller half)
 */
export default verifierPlugin
export const prover = providerPlugin

// Public helpers (useful for tooling/tests; not required by the loader).
export { runVerify, defaultVerifyQuote } from './verifier.js'
export type { QuoteVerification, VerifyQuoteFn } from './verifier.js'
export {
  ATTEST_SERVICE_ID,
  ATTEST_PATH,
  CLAIM_HARDWARE_GENUINE,
  computeReportData,
} from './shared.js'
