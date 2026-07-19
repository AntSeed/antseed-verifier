# GCP TDX end-to-end run

Full verification of `@refoundhq/antseed-verifier` on **real Intel TDX hardware**, run by
cloning the merged `main`, installing, and exercising the real SDK code paths on the VM.

- **Host:** GCP `c3-standard-4` confidential VM (Intel TDX), Ubuntu 24.04, Node v20.20.2
- **Run (UTC):** Sun Jul 19 22:29:10 UTC 2026
- **Commit under test:** `3b2eec7 Merge pull request #3 from refoundhq/fix/publish-readiness`

## Results (all PASS)

| Check | Result |
|-------|--------|
| Test suite (`npm test`) | **141 passed** ([05-test.log](05-test.log)) |
| Typecheck (`tsc --noEmit`) | exit 0 ([03-typecheck.log](03-typecheck.log)) |
| Build (`tsc`) | exit 0 ([04-build.log](04-build.log)) |
| `seller-node-tee-genuine` on hardware | **ok:true** — genuine TDX, TCB UpToDate, bound to this round (`antseed-rd-v1 {peerId}`), configfs mint + DCAP ([06-node-tee-hw.log](06-node-tee-hw.log)) |
| `seller-provider-tee-genuine` vs **live Chutes** | **ok:true** — genuine TDX, TCB UpToDate, bound to this round (`nonce-pubkey-sha256-v1`) ([07-chutes-provider.log](07-chutes-provider.log)) |

## What ran where
- **node-tee:** the SDK's real `nodeTeeCapability.collect` (configfs-tsm quote minting on the TDX VM) → `verifyTdxEvidence` (real Intel DCAP) → `nodeTeeCapability.verify`.
- **Chutes provider-tee:** a local shim joins Chutes' `/e2e/instances` + `/chutes/{id}/evidence` and feeds the SDK's real `providerTeeCapability.collect` → DCAP → `verify` with `nonce-pubkey-sha256-v1`.

Secrets (GitHub token, Chutes API key) were passed via env only and never written to these logs.
