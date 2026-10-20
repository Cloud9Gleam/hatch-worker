# buyback-verifier

**On-chain verification of a token buyback program — as a runnable tool.**

A token project announces "we bought back X BNB of our token between date A
and date B, and we never sold." This tool checks that claim against the
chain itself and produces a publishable evidence report: every buy
(transaction, block, UTC time, amount spent, exact tokens received,
execution price), the totals, the average price, and whether the treasury
sent any of the token back into the pool.

It productizes a workflow that was previously done by hand for the FLAPJAX
"Receipt Relay" audit series on TaskMarket (Q23–Q35 — the same buyback
verification, re-issued 35+ times). What took a manual audit now takes one
command; the marginal cost of the next report is one run.

- **Read-only.** It never signs or sends a transaction.
- **No index figures.** A discovery transport only supplies *candidate tx
  hashes*; every number in the report is re-derived from raw chain data
  (`eth_getTransactionByHash`, `eth_getTransactionReceipt`,
  `eth_getBlockByNumber`) and is wei-exact.
- **Honest completeness.** The report states how the transactions were
  found and exactly which parts of the window could not be enumerated, if
  any. It never papers over a failed scan.

## Quickstart

```bash
python3 buyback_verifier.py \
  --chain bsc \
  --token    0x<token contract> \
  --treasury 0x<treasury address> \
  --pool     0x<pool / pair contract> \
  --from 2026-10-09 --to 2026-10-18 \
  --out-prefix report
```

Writes `report.md`, `report.html` (standalone page a project can publish
as-is — inline CSS, no external assets) and `report.json` (full
machine-readable evidence).

With a logs-capable RPC endpoint (your own node or a key'd provider),
window enumeration is fully automatic:

```bash
python3 buyback_verifier.py ... --rpc https://<your-endpoint> --discovery logs
```

If your project publishes its buy tx hashes (e.g. in buyback receipts), you
can also verify exactly those, from raw receipts:

```bash
python3 buyback_verifier.py ... --discovery seeds --seeds buys.txt
```

`--discovery auto` (the default) tries logs first, then seeds.

## Parameters

| Flag | Meaning |
|---|---|
| `--chain` | Chain preset. `bsc` (BNB Smart Chain) in v1. |
| `--token` | Token contract being bought back. Must be `token0` or `token1` of the pool (read via `eth_call`; the other side is the quote asset). |
| `--treasury` | Address that executes / receives the buybacks. |
| `--pool` | The pool/pair contract the buybacks trade against. |
| `--from`, `--to` | Window bounds, UTC. `YYYY-MM-DD` (inclusive whole days) or full ISO 8601. Converted to block bounds by binary search on block timestamps. |
| `--from-block`, `--to-block` | Alternative: explicit block bounds. |
| `--discovery` | `auto` \| `logs` \| `seeds` (see below). |
| `--seeds` | File of tx hashes, one per line (`#` comments allowed). |
| `--chunk` | Initial `eth_getLogs` chunk size in blocks (default 1000). |
| `--rpc` | Logs-discovery RPC endpoint (repeatable, overrides preset). |
| `--verify-rpc` | RPC endpoint for receipt verification (repeatable). |
| `--token-symbol`, `--quote-symbol` | Display overrides (normally read on-chain). |
| `--out-prefix` | Output path prefix (default `report`). |

Dependencies: **Python 3.9+ standard library only.**

## How it works

### Discovery (two transports)

**logs** — enumerates the window directly:
- Scan B: token `Transfer` logs `pool → treasury` = buy receipts.
- Scan A: token `Transfer` logs `treasury → *` = the sell check (any
  transfer into the pool is a sell; transfers elsewhere, e.g. payouts,
  are reported separately as non-sell outflows).

Public BSC endpoints reject `eth_getLogs` ranges above roughly 1,000
blocks (JSON-RPC error `-32005`), so the scanner walks the window in
**adaptive chunks**: a chunk that hits a limit error is halved (down to
50 blocks) and retried, cautiously growing back on success; a range that
still fails is recorded in `scan_stats.failed_ranges` and disclosed in
the report's completeness line. Before scanning, every candidate
endpoint is **preflighted** with a 1-block probe so a dead endpoint is
never mistaken for an empty window.

**seeds** — verifies a caller-supplied list of tx hashes (the method of
the manual FLAPJAX audits: the project's published receipt hashes).
Buys are fully verified; the sell check then covers the verified
transactions themselves, and the report says so explicitly.

### Verification kernel (transport-independent)

For every candidate transaction, from its receipt:
- **Token received** = sum of the token's `Transfer(pool → treasury)`
  logs — exact to the wei. Recipients are listed, so "bought but sent
  elsewhere" is visible.
- **Spent** = quote-token transfers into the pool in the same receipt;
  falls back to the transaction's native `value` when no wrapped-quote
  flow is present. The basis used is printed in the report.
- **Cross-check**: the pool's own swap event in the receipt is decoded
  generically (V2-style 4-word and V3-style ≥5-word shapes) and its
  signed token/quote deltas are stored in the JSON — accounting never
  depends on it, but a mismatch would be visible.
- Sell-in-buy check (any token `Transfer` out of the treasury inside a
  buy tx is flagged), status, initiator, gas fee — all recorded.

## Method limits (stated in every report too)

- Scope is the **single pool given as input**. Buys routed through other
  pools or aggregators, and direct non-swap transfers into the pool, are
  outside the report.
- Public BSC RPCs prune historical state (`eth_call` at old blocks →
  `missing trie node`); verification therefore reads receipts and logs
  of mined transactions only — which is all the accounting needs.
- Seeds mode cannot find buys that are not on the list, and cannot
  enumerate window-wide treasury outflows. Use logs mode with a capable
  endpoint for a fully independent enumeration.
- Venue quirks are handled by construction: accounting rests on ERC-20
  `Transfer` logs, not on any venue's swap event. (The FLAPJAX pool, for
  instance, emits a PancakeSwap-variant swap event with topic
  `0x19b47279…` and 7 data words — not the canonical Uniswap V3 `Swap`
  topic an earlier manual script assumed.)

## Self-test (FLAPJAX Q35, run 2026-10-20)

Reproduce:

```bash
python3 buyback_verifier.py --chain bsc \
  --token 0x90c8889f428f9Ebb77BB8f15CAD3a50a9aC680df \
  --treasury 0x7C34E9e21eE28A49Ff0b84B61774119E6633359f \
  --pool 0xcA93EC685b8623688E6B236f9068034B298c2150 \
  --from 2026-10-09 --to 2026-10-18 \
  --discovery auto --seeds examples/flapjax-q35.seeds.txt \
  --out-prefix selftest/report
```

Known answer (manual audit, `flapjax-q26-kit/q35/audit-q35.md`): **9 buys
of 0.01 BNB each, 0.09 BNB total → 214,002,792.664923 FLAPJAX received,
no sells.**

What actually happened in this sandbox, honestly:

1. **Discovery fell back to seeds — by design, and it says so in the
   report.** The `eth_getLogs` preflight failed on *every* configured
   endpoint: bsc-dataseed ×2 returned `-32005 "limit exceeded"` even for
   a **single-block** probe; BlastAPI and dRPC returned HTTP 429;
   PublicNode returned HTTP 403. (During development ~20 public BSC
   endpoints were probed from this VM: dataseed refuses `eth_getLogs`
   in all forms, several others are egress-unreachable, the BscScan V1
   API is shut down, and GeckoTerminal's trades endpoint returns only
   the latest few trades.) So window-wide log enumeration could not be
   exercised from this environment. Forcing `--discovery logs` exits 1
   with the preflight evidence instead of fabricating a scan. The
   chunked logs scanner is implemented (adaptive chunking + failed-range
   accounting) and will run as-is against any logs-capable endpoint
   (`--rpc`).
2. **All figures matched the known answer exactly.** With the 9 official
   receipt hashes as seeds (the same inputs the manual audit used), the
   verifier re-derived everything from raw receipts:
   - Window blocks reproduced exactly: **126,536,085 – 128,454,490**
     (binary search vs. the kit's recorded bounds).
   - Buys found: **9**; each `value` = 0.01 BNB; each quote inflow to the
     pool = exactly 0.01 WBNB; total spent **0.09** (90,000,000,000,000,000
     wei on both bases).
   - Total received: **214,002,792.664923** FLAPJAX at 6 dp — and the
     exact raw sum, 214002792664923451883644637 wei, is identical to the
     manual audit's per-tx data (`flapjax-q26-kit/q35/buys_verified.json`)
     **to the wei on all 9 buys**, as are blocks, recipients (treasury
     only), and per-buy prices.
   - Average price **4.205553e-10 WBNB/FLAPJAX** — matches.
   - **Sells: 0** — no treasury token outflow inside any verified
     transaction (the seeds-mode scope; the manual audit's window-wide
     statement rests on its own enumeration caveat, see its §2/§5.4).
   - Bonus cross-check: the pool's own swap-event deltas decoded by the
     verifier matched the Transfer accounting on all 9 buys.

Generated self-test outputs are kept in `selftest/` (`report.md`,
`report.html`, `report.json`).
