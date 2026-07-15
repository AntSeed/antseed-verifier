/**
 * Generic HTTP collector: fetch a TDX quote from a seller-configured attestation
 * endpoint. Everything provider-specific (host, path, request shape, where the quote
 * sits in the JSON) is supplied via config — there are NO hardcoded hosts or schemas
 * here, so any HTTP attestation service can be wired up purely through config.
 *
 * Config keys (all under the seller's generic config map):
 *   url    (required)  endpoint; may contain {nonce} (hex) / {nonce_b64} placeholders
 *   field  (required)  dot-path to the base64 quote in the JSON response, e.g. "data.quote"
 *   method (optional)  HTTP method; defaults to GET, or POST when `body` is present
 *   body   (optional)  request body template; same {nonce}/{nonce_b64} substitution
 */

function substitute(template: string, nonce: Uint8Array): string {
  const hex = Buffer.from(nonce).toString('hex')
  const b64 = Buffer.from(nonce).toString('base64')
  return template.replace(/\{nonce\}/g, hex).replace(/\{nonce_b64\}/g, b64)
}

/** Resolve a dot-separated path (e.g. "data.quote") against a parsed JSON value. */
function pluck(obj: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc && typeof acc === 'object' && key in (acc as Record<string, unknown>)) {
      return (acc as Record<string, unknown>)[key]
    }
    return undefined
  }, obj)
}

export async function collectViaHttp(
  config: Record<string, string>,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  const url = config.url
  const field = config.field
  if (!url) throw new Error('http collector requires config "url"')
  if (!field) throw new Error('http collector requires config "field" (JSON path to the base64 quote)')

  const hasBody = typeof config.body === 'string' && config.body.length > 0
  const method = config.method ?? (hasBody ? 'POST' : 'GET')

  const resp = await fetch(substitute(url, nonce), {
    method,
    headers: hasBody ? { 'content-type': 'application/json' } : undefined,
    body: hasBody ? substitute(config.body as string, nonce) : undefined,
  })
  if (!resp.ok) {
    throw new Error(`http attestation endpoint returned HTTP ${resp.status}`)
  }
  const json: unknown = await resp.json()
  const value = pluck(json, field)
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`http attestation response has no base64 quote at "${field}"`)
  }
  const quote = new Uint8Array(Buffer.from(value, 'base64'))
  if (quote.length === 0) {
    throw new Error(`http attestation quote at "${field}" is not valid base64`)
  }
  return quote
}
