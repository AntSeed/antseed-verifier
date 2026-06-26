import { mkdirSync, writeFileSync, readFileSync, rmdirSync } from 'node:fs'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'

/**
 * Linux configfs-TSM report interface (kernel >= 6.7). Present inside a real Intel
 * TDX guest (e.g. the GCP confidential VM used in the e2e); absent elsewhere.
 */
const TSM_REPORT_DIR = '/sys/kernel/config/tsm/report'

/**
 * Generate a raw Intel TDX quote bound to `reportData` (64 bytes) via configfs-TSM:
 *   1. mkdir a fresh report entry,
 *   2. write the 64-byte REPORTDATA to `inblob`,
 *   3. read the assembled quote from `outblob`,
 *   4. rmdir the entry.
 *
 * Only succeeds inside a genuine TDX guest with configfs-tsm mounted; throws
 * otherwise (which is fine — the live quote path runs on the TDX VM, not locally).
 */
export function generateTdxQuote(reportData: Uint8Array): Uint8Array {
  if (reportData.length !== 64) {
    throw new Error(`reportData must be 64 bytes, got ${reportData.length}`)
  }
  const entry = join(TSM_REPORT_DIR, `antseed-${randomBytes(8).toString('hex')}`)
  mkdirSync(entry)
  try {
    writeFileSync(join(entry, 'inblob'), Buffer.from(reportData))
    const quote = readFileSync(join(entry, 'outblob'))
    if (quote.length === 0) {
      throw new Error('configfs-tsm outblob was empty (quote generation produced no bytes)')
    }
    return new Uint8Array(quote)
  } finally {
    try {
      rmdirSync(entry)
    } catch {
      // best-effort cleanup; the entry is a one-shot configfs dir
    }
  }
}
