# Running an AntSeed seller on Phala (dstack TDX CVM)

How to run an AntSeed seller inside a Phala Confidential VM and attest its node with
`antseed-verifier`. Phala CVMs are **dstack** guests: they have no `/sys/kernel/config/tsm`
(the configfs-tsm interface), and mint TDX quotes through the **dstack guest-agent socket**
instead. The SDK has a native `dstack` source for exactly this — **no shim required**.

## 1. Configure the seller

Set these on the seller process inside the CVM:

```bash
export ANTSEED_TEE_PEER_ID=<your peer id — EVM address, no 0x>
export ANTSEED_VERIFIER_SIGNING_KEY=<hex private key; its address MUST equal the peer id>

export ANTSEED_VERIFIER_NODE_TEE=dstack     # mint the node quote via the dstack guest agent
# export ANTSEED_VERIFIER_DSTACK_SOCKET=/custom/path.sock   # only if not /var/run/dstack.sock
```

Then start the seller with the verifier SDK enabled (`--verifiers antseed-verifier`). Mount the
dstack socket into the container so the process can reach it (default `/var/run/dstack.sock`,
also tried at `/run/dstack.sock`).

That's the whole integration. The SDK internally:

1. derives `report_data = antseed-rd-v1(nonce, peerId)` (64 bytes) — the same value the
   configfs path produces,
2. POSTs it to the guest agent (`POST /GetQuote {"report_data":"<hex>"}`, used **raw**),
3. decodes the returned hex quote to bytes.

So the quote is **byte-identical** to a bare-metal/GCP seller's, and the buyer verifies it with
no Phala-specific logic.

## 2. Verify (buyer)

A buyer running with `--require-verifier` fetches the reserved attest route, gets a fresh TDX
quote bound to its nonce + your peer id, DCAP-verifies it (`@phala/dcap-qvl`) **before payment**,
then routes the paid request. No collateral or parsing setup is needed on the verify path.

The two required caps that pass: `seller-node-tee-genuine` (genuine, round-bound Phala CVM) and
`seller-bound` (your identity key signed the whole bundle for this nonce).

## 3. Fronting an inference provider (optional)

If this seller also proxies to a downstream inference provider (e.g. a Chutes chute), add the
provider-evidence env from [CHUTES.md](./CHUTES.md) to also prove the provider's TEE/GPU. The
node-TEE config above is independent of it.

## 4. Ports (Phala port mapping)

Not an SDK concern, but for completeness: signaling (TCP) and DHT (UDP) **listen == announce**,
so the **public host ports must match the container ports** — the VM-layer ports Phala
auto-assigns don't matter. Align them in your `docker-compose` `ports:` and Phala port mapping.
(A CLI `--announce-port` / external-address flag to decouple these is a tracked request on the
node/CLI side, not this SDK.)

## Adapting other TEE platforms

The node quote source is selected by `ANTSEED_VERIFIER_NODE_TEE`:

| Value | Quoting interface | report_data |
|---|---|---|
| `configfs` (default) | `/sys/kernel/config/tsm/report` (bare-metal / GCP TDX, needs root) | derived by the SDK |
| `dstack` | dstack guest-agent socket (Phala & other dstack CVMs) | derived by the SDK |
| `http` | a local endpoint you run (`<id>.url`), `{nonce}`→hex | **you** must bind it |

For a platform with neither configfs-tsm nor dstack, run a tiny local endpoint and point the
node source at it with `ANTSEED_VERIFIER_NODE_TEE=http` — but note the `http` source fetches a
**pre-made** quote, so your endpoint must itself bind `report_data = antseed-rd-v1(nonce, peerId)`.
The cleanest long-term fix for a new platform is a native source (like `dstack`); PRs welcome.
