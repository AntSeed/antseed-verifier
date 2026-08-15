import type { BindingIngredients } from '../report-data.js'
import type { NvidiaGpuEvidence } from '../nras.js'

/**
 * Provider evidence in the SDK's neutral shape, produced by an in-process adapter. The prover
 * maps this onto the provider capabilities (tee / gpu), so a foreign provider's API is bridged
 * with NO provider specifics in the core: the adapter is the only provider-aware code, and it is
 * loaded lazily — by id, only when ANTSEED_VERIFIER_PROVIDER_ADAPTER selects it.
 */
export interface ProviderEvidence {
  /** The provider's raw TDX quote bytes. */
  quote: Uint8Array
  /** Frozen report_data scheme the quote binds (e.g. 'nonce-pubkey-sha256-v1', 'aci-keyset-v1'). */
  bindingScheme?: string
  /** The scheme's ingredients (e.g. { e2ePubkey } for Chutes, { keysetDigest } for ACI). */
  ingredients?: Pick<BindingIngredients, 'peerId' | 'e2ePubkey' | 'keysetDigest'>
  /** Provider GPU CC evidence for seller-provider-gpu-cc, when the provider offers it. */
  gpuEvidence?: NvidiaGpuEvidence
}

/** A provider adapter: given the buyer nonce + the process env, fetch the provider's evidence. */
export interface ProviderAdapter {
  id: string
  fetchEvidence(nonce: Uint8Array, env: Record<string, string | undefined>): Promise<ProviderEvidence>
}

/**
 * Allowlisted lazy registry — the ONE place adapter ids map to modules. The env only ever selects
 * a key here (never a path), so a hostile value cannot dynamic-import an arbitrary file. Add a
 * provider by adding its module + one line here; the core verify/collect path never changes.
 */
const REGISTRY: Record<string, () => Promise<{ default: ProviderAdapter }>> = {
  chutes: () => import('./chutes.js'),
  aci: () => import('./aci.js'),
}

export function adapterIds(): string[] {
  return Object.keys(REGISTRY)
}

export async function loadAdapter(id: string): Promise<ProviderAdapter> {
  const load = REGISTRY[id]
  if (!load) throw new Error(`unknown provider adapter "${id}" (known: ${adapterIds().join(', ') || 'none'})`)
  return (await load()).default
}
