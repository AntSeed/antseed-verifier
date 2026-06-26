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

// Public helpers (useful for tooling/tests; not required by the loader).
export { runVerify, defaultVerifyQuote } from './verifier.js'
export type { QuoteVerification, VerifyQuoteFn } from './verifier.js'
export {
  VERIFIER_ID,
  ATTEST_PATH,
  CLAIM_HARDWARE_GENUINE,
  computeReportData,
} from './shared.js'
