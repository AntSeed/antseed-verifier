/**
 * Generic HTTP collector: fetch a TDX quote from a seller-configured attestation
 * endpoint. Everything provider-specific (host, path, where the quote sits in the JSON)
 * is supplied by the caller — there are NO hardcoded hosts or schemas here, so any HTTP
 * attestation service can be wired up purely through config.
 *
 * Arguments:
 *   urlTemplate  the endpoint; any {nonce} placeholder is replaced with the HEX nonce
 *   nonce        the buyer's freshness nonce (used only for {nonce} substitution)
 *   field        dot-path to the base64 quote in the JSON response (e.g. "quote" or "data.quote")
 */

/** Resolve a dot-separated path (e.g. "data.quote") against a parsed JSON value. */
function pluck(obj: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc && typeof acc === 'object' && key in (acc as Record<string, unknown>)) {
      return (acc as Record<string, unknown>)[key]
    }
    return undefined
  }, obj)
}

/**
 * Fetch the provider evidence route ONCE, returning the base64-decoded quote and, when a pubkey
 * field is named, the report_data-binding pubkey string. Single fetch so the quote and the
 * pubkey come from the same response — a two-fetch split could pair a quote with a different
 * instance's key.
 */
export async function collectTdxAndPubkey(
  urlTemplate: string,
  nonce: Uint8Array,
  quoteField: string,
  pubkeyField?: string,
): Promise<{ quote: Uint8Array; pubkey?: string }> {
  const url = urlTemplate.replace(/\{nonce\}/g, Buffer.from(nonce).toString('hex'))
  const resp = await fetch(url)
  if (!resp.ok) {
    throw new Error(`http attestation endpoint returned HTTP ${resp.status}`)
  }
  const json: unknown = await resp.json()
  const q = pluck(json, quoteField)
  if (typeof q !== 'string' || q.length === 0) {
    throw new Error(`http attestation response has no base64 quote at "${quoteField}"`)
  }
  const quote = new Uint8Array(Buffer.from(q, 'base64'))
  if (quote.length === 0) {
    throw new Error(`http attestation quote at "${quoteField}" is not valid base64`)
  }
  if (!pubkeyField) return { quote }
  const pk = pluck(json, pubkeyField)
  if (typeof pk !== 'string' || pk.length === 0) {
    throw new Error(`http attestation response has no string at "${pubkeyField}"`)
  }
  return { quote, pubkey: pk }
}

export async function collectViaHttp(
  urlTemplate: string,
  nonce: Uint8Array,
  field: string,
): Promise<Uint8Array> {
  const url = urlTemplate.replace(/\{nonce\}/g, Buffer.from(nonce).toString('hex'))
  const resp = await fetch(url)
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

/**
 * Like collectViaHttp, but returns the extracted field re-encoded as JSON bytes instead of
 * base64-decoding it. WHY separate: the TDX path wants a lone base64 quote decoded to raw
 * bytes; the GPU path's field holds a STRUCTURED value (e.g. { arch, evidence_list }) whose
 * shape must survive intact to the NRAS submit, so we preserve it as JSON rather than decode.
 */
export async function collectJsonFieldViaHttp(
  urlTemplate: string,
  nonce: Uint8Array,
  field: string,
): Promise<Uint8Array> {
  const url = urlTemplate.replace(/\{nonce\}/g, Buffer.from(nonce).toString('hex'))
  const resp = await fetch(url)
  if (!resp.ok) {
    throw new Error(`http attestation endpoint returned HTTP ${resp.status}`)
  }
  const json: unknown = await resp.json()
  const value = pluck(json, field)
  if (value === undefined || value === null) {
    throw new Error(`http attestation response has no value at "${field}"`)
  }
  return new TextEncoder().encode(JSON.stringify(value))
}
