#!/usr/bin/env node
/**
 * Chutes evidence adapter for @antseed/antseed-verifier.
 *
 * The verifier SDK is provider-neutral: it fetches provider evidence from ONE URL and plucks
 * fields by name. Chutes' evidence API doesn't fit that shape — it is Bearer-authed and returns
 * an ARRAY of instances. This adapter is the thin per-provider bridge: run it next to the seller
 * node; it adds auth, picks one instance, reshapes the GPU evidence, and serves the SDK's
 * evidence shape on localhost. No SDK code knows about Chutes — to support another provider,
 * write another adapter like this one.
 *
 * Run:
 *   CHUTES_API_KEY=... CHUTES_CHUTE=<chute id> node adapters/chutes/chutes-adapter.mjs
 * Point the seller at it:
 *   ANTSEED_VERIFIER_PROVIDER_EVIDENCE_URL='http://127.0.0.1:9099/evidence?nonce={nonce}'
 *
 * Env: CHUTES_API_KEY (required), CHUTES_CHUTE (required), CHUTES_API_BASE (default
 * https://api.chutes.ai), HOST (default 127.0.0.1), PORT (default 9099).
 */

import { createServer } from 'node:http'

const API_BASE = (process.env.CHUTES_API_BASE ?? 'https://api.chutes.ai').replace(/\/+$/, '')
const API_KEY = process.env.CHUTES_API_KEY
const CHUTE = process.env.CHUTES_CHUTE
const HOST = process.env.HOST ?? '127.0.0.1'
const PORT = Number(process.env.PORT ?? 9099)
const UPSTREAM_TIMEOUT_MS = 20_000

if (!API_KEY) { console.error('CHUTES_API_KEY is required'); process.exit(1) }
if (!CHUTE) { console.error('CHUTES_CHUTE is required'); process.exit(1) }

/** Reshape Chutes' flat GPU evidence [{arch, evidence, certificate}] → the SDK's {arch, evidence_list}. */
function reshapeGpu(gpu) {
  if (!gpu) return undefined
  if (Array.isArray(gpu)) {
    if (gpu.length === 0) return undefined
    return { arch: gpu[0].arch, evidence_list: gpu.map(({ evidence, certificate }) => ({ evidence, certificate })) }
  }
  return gpu // already in {arch, evidence_list} shape
}

/** Fetch Chutes' evidence array for this nonce and flatten one instance to the SDK's shape. */
async function evidenceForNonce(nonceHex) {
  const url = `${API_BASE}/chutes/${encodeURIComponent(CHUTE)}/evidence?nonce=${nonceHex}`
  const resp = await fetch(url, {
    headers: { authorization: `Bearer ${API_KEY}` },
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  })
  if (!resp.ok) throw new Error(`chutes evidence HTTP ${resp.status}`)
  const body = await resp.json()
  const instances = Array.isArray(body) ? body : [body]
  const inst = instances.find((i) => i && typeof i.quote === 'string' && i.quote.length > 0)
  if (!inst) throw new Error('no chutes instance returned a quote')
  const out = { quote: inst.quote, e2e_pubkey: inst.e2e_pubkey }
  const gpu = reshapeGpu(inst.gpu_evidence)
  if (gpu) out.gpu_evidence = gpu
  return out
}

const server = createServer(async (req, res) => {
  const send = (code, obj) => {
    res.writeHead(code, { 'content-type': 'application/json' })
    res.end(JSON.stringify(obj))
  }
  try {
    const u = new URL(req.url, `http://${HOST}:${PORT}`)
    if (req.method !== 'GET' || u.pathname !== '/evidence') return send(404, { error: 'not found' })
    const nonce = (u.searchParams.get('nonce') ?? '').toLowerCase()
    if (!/^[0-9a-f]+$/.test(nonce)) return send(400, { error: 'missing or invalid hex nonce' })
    send(200, await evidenceForNonce(nonce))
  } catch (err) {
    send(502, { error: err instanceof Error ? err.message : String(err) })
  }
})

server.listen(PORT, HOST, () => {
  console.log(`chutes adapter → ${API_BASE}/chutes/${CHUTE}/evidence  |  http://${HOST}:${PORT}/evidence?nonce={hex}`)
})
