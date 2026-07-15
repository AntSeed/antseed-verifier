import { describe, it, expect, vi, afterEach } from 'vitest'
import { randomBytes } from 'node:crypto'
import { collectViaHttp } from './http.js'

const NONCE = randomBytes(32)
const HEX = Buffer.from(NONCE).toString('hex')

/** Stub fetch: capture the URL, return a JSON body. */
function stubFetch(body: unknown, ok = true, status = 200): { seenUrl: () => string } {
  let url = ''
  vi.stubGlobal('fetch', vi.fn(async (u: string) => {
    url = u
    return { ok, status, json: async () => body }
  }))
  return { seenUrl: () => url }
}

afterEach(() => vi.unstubAllGlobals())

describe('collectViaHttp', () => {
  it('substitutes {nonce} with the hex nonce and extracts a flat FIELD', async () => {
    const quote = randomBytes(96)
    const f = stubFetch({ quote: Buffer.from(quote).toString('base64') })
    const out = await collectViaHttp('https://x.example/att/{nonce}', NONCE, 'quote')
    expect(f.seenUrl()).toBe(`https://x.example/att/${HEX}`)
    expect(Buffer.from(out).equals(quote)).toBe(true)
  })

  it('extracts a nested dot-path FIELD', async () => {
    const quote = randomBytes(64)
    stubFetch({ data: { quote: Buffer.from(quote).toString('base64') } })
    const out = await collectViaHttp('https://x.example/att', NONCE, 'data.quote')
    expect(Buffer.from(out).equals(quote)).toBe(true)
  })

  it('throws on a non-2xx response', async () => {
    stubFetch({}, false, 503)
    await expect(collectViaHttp('https://x.example/att', NONCE, 'quote')).rejects.toThrow(/HTTP 503/)
  })

  it('throws when the FIELD is absent', async () => {
    stubFetch({ nope: 'x' })
    await expect(collectViaHttp('https://x.example/att', NONCE, 'quote')).rejects.toThrow(/no base64 quote at "quote"/)
  })
})
