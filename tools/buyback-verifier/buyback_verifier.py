#!/usr/bin/env python3
"""buyback-verifier — on-chain verification of a token buyback program.

Given (chain, token contract, treasury address, pool address, date range),
produce an evidence report of the treasury's buyback activity in the window:

  * every buy: tx, block, UTC time, native/quote spent, tokens received
    (exact, from ERC-20 Transfer logs in the transaction receipt),
  * totals, average execution price,
  * whether the treasury sold any of the token back into the pool,
  * per-tx explorer links.

Discovery of the relevant transactions is pluggable:

  * "logs"  — chunked eth_getLogs enumeration against a logs-capable RPC
              endpoint (adaptive chunk size; BSC public nodes cap the range
              and return -32005, so ranges are split and every failed range
              is accounted for in the report — never silently skipped).
  * "seeds" — verify a caller-supplied list of tx hashes (e.g. the hashes a
              project published in its own buyback receipts) one by one
              against raw chain data. This mirrors the method used for the
              FLAPJAX Receipt Relay audits (Q23-Q35).
  * "auto"  — preflight every candidate endpoint with a 1-block getLogs
              probe; use "logs" if any endpoint answers, else "seeds"
              if a seeds file was given, else fail loudly.

Whichever discovery transport is used, every reported figure is re-derived
from raw chain data (eth_getTransactionByHash / eth_getTransactionReceipt /
eth_getBlockByNumber) — an index or a seed list is only ever a source of
candidate hashes, never of numbers.

Read-only: this tool never signs or sends a transaction.

Dependencies: Python 3.9+ standard library only.
"""

import argparse
import datetime
import html
import json
import sys
import time
import urllib.error
import urllib.request

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

CHAIN_PRESETS = {
    "bsc": {
        "name": "BNB Smart Chain",
        "native_symbol": "BNB",
        "explorer_tx": "https://bscscan.com/tx/",
        "explorer_addr": "https://bscscan.com/address/",
        # Point reads (receipts / blocks / eth_call) work well on the public
        # dataseed nodes. eth_getLogs on those same nodes currently refuses
        # every range with -32005 (see README), so discovery preflights them
        # and reports the refusal instead of pretending to scan.
        "verify_rpcs": [
            "https://bsc-dataseed.binance.org",
            "https://bsc-dataseed1.binance.org",
            "https://bsc-dataseed2.binance.org",
        ],
        "logs_rpcs": [
            "https://bsc-dataseed.binance.org",
            "https://bsc-dataseed1.binance.org",
            "https://bsc-mainnet.public.blastapi.io",
            "https://bsc-rpc.publicnode.com",
            "https://bsc.drpc.org",
        ],
        "default_chunk": 1000,
    },
}


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def pad_addr(addr):
    return "0x" + "0" * 24 + addr[2:].lower()


def topic_addr(topic):
    return "0x" + topic[-40:].lower()


def fmt_amount(raw, decimals, max_dp=None):
    """Exact decimal rendering of a raw integer token amount (no floats)."""
    raw = int(raw)
    sign = "-" if raw < 0 else ""
    raw = abs(raw)
    if decimals == 0:
        return sign + f"{raw:,}"
    whole, frac = divmod(raw, 10 ** decimals)
    frac_s = str(frac).rjust(decimals, "0")
    if max_dp is not None:
        frac_s = frac_s[:max_dp]
    frac_s = frac_s.rstrip("0")
    return sign + f"{whole:,}" + (f".{frac_s}" if frac_s else "")


def fmt_sci(x, sig=6):
    if x == 0:
        return "0"
    return f"{x:.{sig}e}"


def utc_str(ts):
    return datetime.datetime.fromtimestamp(
        ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class RpcError(Exception):
    pass


class RpcPool:
    """Rotating JSON-RPC client over several endpoints (stdlib urllib)."""

    def __init__(self, endpoints, timeout=40, label="rpc"):
        self.endpoints = list(endpoints)
        self.timeout = timeout
        self.label = label
        self._idx = 0
        self.calls = 0

    def _one(self, url, method, params):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": params}).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json",
                     "User-Agent": "buyback-verifier/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            d = json.loads(resp.read().decode())
        if d.get("error"):
            err = d["error"]
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            code = err.get("code") if isinstance(err, dict) else None
            raise RpcError(f"rpc-error code={code} {msg}")
        return d.get("result")

    def call(self, method, params, retries=3):
        """Return result, rotating endpoints; raise RpcError if all fail."""
        last = None
        for attempt in range(retries * len(self.endpoints)):
            url = self.endpoints[self._idx % len(self.endpoints)]
            self._idx += 1
            self.calls += 1
            try:
                return self._one(url, method, params)
            except Exception as e:  # noqa: BLE001 - report and rotate
                last = e
                time.sleep(min(1.0 * (attempt + 1), 4.0))
        raise RpcError(f"{self.label}: all endpoints failed for {method}: {last}")

    def probe(self, method, params):
        """Single pass over endpoints; return (result, None) or (None, err)."""
        last = None
        for url in self.endpoints:
            self.calls += 1
            try:
                return self._one(url, method, params), None
            except Exception as e:  # noqa: BLE001
                last = f"{url}: {e}"
        return None, last


# --------------------------------------------------------------------------
# verifier
# --------------------------------------------------------------------------

class Verifier:
    def __init__(self, cfg):
        self.cfg = cfg
        preset = CHAIN_PRESETS[cfg.chain]
        self.preset = preset
        self.verify = RpcPool(cfg.verify_rpcs or preset["verify_rpcs"],
                              label="verify-rpc")
        self.logs_rpc = RpcPool(cfg.logs_rpcs or preset["logs_rpcs"],
                                label="logs-rpc")
        self.token = cfg.token.lower()
        self.treasury = cfg.treasury.lower()
        self.pool = cfg.pool.lower()
        self._block_ts_cache = {}
        self.meta = {}
        self.window = {}
        self.preflight = []
        self.scan_stats = {"requests": 0, "failed_ranges": [], "min_chunk": None}
        self.buys = []
        self.sells = []
        self.outflows_other = []
        self.out_of_window = []
        self.discovery_used = None
        self.notes = []

    # -- chain reads -------------------------------------------------------

    def block_ts(self, blk):
        if blk not in self._block_ts_cache:
            b = self.verify.call("eth_getBlockByNumber", [hex(blk), False])
            self._block_ts_cache[blk] = int(b["timestamp"], 16)
        return self._block_ts_cache[blk]

    def eth_call(self, to, data, block="latest"):
        return self.verify.call("eth_call", [{"to": to, "data": data}, block])

    def call_addr(self, to, selector):
        r = self.eth_call(to, selector)
        return "0x" + r[-40:].lower() if r and len(r) >= 42 else None

    def call_uint(self, to, selector):
        r = self.eth_call(to, selector)
        return int(r, 16) if r else None

    def call_symbol(self, to):
        try:
            r = self.eth_call(to, "0x95d89b41")  # symbol()
        except RpcError:
            return None
        if not r or r == "0x":
            return None
        raw = bytes.fromhex(r[2:])
        try:
            if len(raw) >= 64:  # ABI dynamic string
                ln = int.from_bytes(raw[32:64], "big")
                return raw[64:64 + ln].decode("utf-8", "replace")
            return raw.rstrip(b"\x00").decode("utf-8", "replace")  # bytes32
        except Exception:  # noqa: BLE001
            return None

    # -- setup -------------------------------------------------------------

    def load_metadata(self):
        token0 = self.call_addr(self.pool, "0x0dfe1681")  # token0()
        token1 = self.call_addr(self.pool, "0xd21220a7")  # token1()
        if token0 is None or token1 is None:
            raise RpcError("pool token0()/token1() eth_call failed — "
                           "is --pool a V2/V3-style pair/pool contract?")
        if self.token == token0:
            self.meta["token_index"] = 0
            quote = token1
        elif self.token == token1:
            self.meta["token_index"] = 1
            quote = token0
        else:
            raise RpcError("token is neither token0 nor token1 of the pool")
        self.meta["quote_token"] = quote
        td = self.call_uint(self.token, "0x313ce567")     # decimals()
        qd = self.call_uint(quote, "0x313ce567")
        self.meta["token_decimals"] = 18 if td is None else td
        self.meta["quote_decimals"] = 18 if qd is None else qd
        self.meta["token_symbol"] = (self.cfg.token_symbol
                                     or self.call_symbol(self.token) or "TOKEN")
        self.meta["quote_symbol"] = (self.cfg.quote_symbol
                                     or self.call_symbol(quote)
                                     or self.preset["native_symbol"])
        self.meta["pool_token0"] = token0
        self.meta["pool_token1"] = token1

    def _first_block_at_or_after(self, target_ts, head):
        lo, hi = 0, head
        while lo < hi:
            mid = (lo + hi) // 2
            if self.block_ts(mid) >= target_ts:
                hi = mid
            else:
                lo = mid + 1
        return lo

    def resolve_window(self):
        head = int(self.verify.call("eth_blockNumber", []), 16)
        if self.cfg.from_block is not None and self.cfg.to_block is not None:
            start, end = self.cfg.from_block, self.cfg.to_block
        else:
            start = self._first_block_at_or_after(self.cfg.from_ts, head)
            end = self._first_block_at_or_after(self.cfg.to_ts + 1, head) - 1
        self.window = {
            "from_ts": self.block_ts(start),
            "to_ts": self.block_ts(end),
            "from_block": start,
            "to_block": end,
            "head_at_run": head,
        }

    # -- discovery ----------------------------------------------------------

    def preflight_logs(self):
        """Probe each logs endpoint with a 1-block query at the window start."""
        w = self.window
        probe = [{"fromBlock": hex(w["from_block"]),
                  "toBlock": hex(w["from_block"]),
                  "address": self.token,
                  "topics": [TRANSFER_TOPIC, pad_addr(self.pool),
                             pad_addr(self.treasury)]}]
        capable = []
        for url in self.logs_rpc.endpoints:
            pool1 = RpcPool([url], label="preflight")
            res, err = pool1.probe("eth_getLogs", probe)
            ok = isinstance(res, list)
            self.preflight.append({"endpoint": url, "getlogs_ok": ok,
                                   "error": None if ok else err})
            if ok:
                capable.append(url)
        return capable

    def _get_logs_chunked(self, address, topics, frm, to, chunk0):
        """Chunked eth_getLogs with adaptive shrinking and explicit failure
        accounting. Returns (logs, failed_ranges)."""
        logs, failed = [], []
        chunk = chunk0
        min_chunk = 50
        cur = frm
        while cur <= to:
            end = min(cur + chunk - 1, to)
            res, err = self.logs_rpc.probe(
                "eth_getLogs",
                [{"fromBlock": hex(cur), "toBlock": hex(end),
                  "address": address, "topics": topics}])
            self.scan_stats["requests"] += 1
            if isinstance(res, list):
                logs.extend(res)
                cur = end + 1
                if chunk < chunk0:  # cautiously grow back
                    chunk = min(chunk0, chunk * 2)
                time.sleep(0.15)
                continue
            low = (err or "").lower()
            limitish = ("-32005" in low or "limit" in low or "exceed" in low
                        or "429" in low or "too many" in low)
            if limitish and chunk > min_chunk:
                chunk = max(min_chunk, chunk // 2)
                self.scan_stats["min_chunk"] = chunk
                continue
            failed.append([cur, end])
            cur = end + 1
        return logs, failed

    def discover_logs(self, capable):
        self.logs_rpc = RpcPool(capable, label="logs-rpc")
        w = self.window
        chunk0 = self.cfg.chunk or self.preset["default_chunk"]
        # Scan B: token transfers pool -> treasury (buy receipts)
        buy_logs, f_b = self._get_logs_chunked(
            self.token, [TRANSFER_TOPIC, pad_addr(self.pool),
                         pad_addr(self.treasury)],
            w["from_block"], w["to_block"], chunk0)
        # Scan A: all token transfers out of the treasury (sell check)
        out_logs, f_a = self._get_logs_chunked(
            self.token, [TRANSFER_TOPIC, pad_addr(self.treasury)],
            w["from_block"], w["to_block"], chunk0)
        self.scan_stats["failed_ranges"] = f_a + f_b
        if self.scan_stats["min_chunk"] is None:
            self.scan_stats["min_chunk"] = chunk0
        buy_hashes = sorted({l["transactionHash"].lower() for l in buy_logs})
        sell_hashes = set()
        for l in out_logs:
            to = topic_addr(l["topics"][2])
            rec = {"tx": l["transactionHash"].lower(),
                   "block": int(l["blockNumber"], 16),
                   "to": to, "amount_raw": int(l["data"], 16)}
            if to == self.pool:
                self.sells.append(rec)
                sell_hashes.add(rec["tx"])
            else:
                self.outflows_other.append(rec)
        self.discovery_used = "logs"
        return buy_hashes

    def discover_seeds(self, path):
        hashes = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                h = line.split()[0].lower()
                if h.startswith("0x") and len(h) == 66:
                    hashes.append(h)
        self.discovery_used = "seeds"
        return sorted(set(hashes))

    # -- per-tx verification -------------------------------------------------

    def verify_tx(self, txh):
        tx = self.verify.call("eth_getTransactionByHash", [txh])
        rc = self.verify.call("eth_getTransactionReceipt", [txh])
        if not tx or not rc:
            return {"tx": txh, "error": "tx or receipt not fetchable"}
        blk = int(tx["blockNumber"], 16)
        ts = self.block_ts(blk)
        td = self.meta["token_decimals"]
        token_in = 0            # token pool -> treasury (buy amount)
        token_in_recipients = set()
        quote_into_pool = 0     # quote-token transfers into the pool
        treasury_out = []       # token transfers out of treasury in this tx
        pool_events = []
        for l in rc["logs"]:
            addr = l["address"].lower()
            topics = l["topics"]
            if len(topics) < 3 or topics[0].lower() != TRANSFER_TOPIC:
                if addr == self.pool:
                    pool_events.append(self._decode_pool_event(l))
                continue
            frm = topic_addr(topics[1])
            to = topic_addr(topics[2])
            val = int(l["data"], 16)
            if addr == self.token:
                if frm == self.pool:
                    token_in_recipients.add(to)
                    if to == self.treasury:
                        token_in += val
                if frm == self.treasury:
                    treasury_out.append({"to": to, "amount_raw": val})
            elif addr == self.meta["quote_token"] and to == self.pool:
                quote_into_pool += val
        gas_used = int(rc["gasUsed"], 16)
        gas_price = int(tx.get("gasPrice") or rc.get("effectiveGasPrice")
                        or "0x0", 16)
        rec = {
            "tx": txh,
            "block": blk,
            "time_utc": utc_str(ts),
            "timestamp": ts,
            "from": tx["from"].lower(),
            "to": (tx.get("to") or "").lower(),
            "status": rc["status"],
            "initiator_is_treasury": tx["from"].lower() == self.treasury,
            "value_native_raw": int(tx["value"], 16),
            "token_received_raw": token_in,
            "token_received": fmt_amount(token_in, td),
            "token_recipients": sorted(token_in_recipients),
            "quote_into_pool_raw": quote_into_pool,
            "treasury_token_out": treasury_out,
            "pool_events": [e for e in pool_events if e],
            "gas_used": gas_used,
            "fee_native_raw": gas_used * gas_price,
            "nonce": int(tx["nonce"], 16),
        }
        return rec

    def _decode_pool_event(self, log):
        """Generic swap cross-check: decode the pool's own event in the tx.
        V3-style events carry >=5 data words (signed amount0, amount1, ...);
        V2 Swap carries 4 unsigned words (in0, in1, out0, out1). We record
        the token-side / quote-side signed deltas from the pool's perspective
        when the shape is recognised; accounting never depends on this."""
        data = log["data"][2:]
        words = [int.from_bytes(bytes.fromhex(data[i:i + 64]), "big",
                                signed=True)
                 for i in range(0, len(data) - 63, 64)]
        if len(words) < 2:
            return None
        ti = self.meta["token_index"]
        if len(words) >= 5:
            amt_token = words[ti]
            amt_quote = words[1 - ti]
            shape = "v3-style"
        elif len(words) == 4:
            inn = [words[0], words[1]]
            out = [words[2], words[3]]
            amt_token = inn[ti] - out[ti]
            amt_quote = inn[1 - ti] - out[1 - ti]
            shape = "v2-style"
        else:
            return None
        return {"topic0": log["topics"][0],
                "shape": shape,
                "pool_delta_token_raw": amt_token,
                "pool_delta_quote_raw": amt_quote}

    # -- run -----------------------------------------------------------------

    def run(self):
        self.load_metadata()
        self.resolve_window()
        mode = self.cfg.discovery
        buy_hashes = None
        if mode in ("auto", "logs"):
            capable = self.preflight_logs()
            if capable:
                buy_hashes = self.discover_logs(capable)
            elif mode == "logs":
                raise RpcError("discovery=logs but no endpoint passed the "
                               "eth_getLogs preflight (see preflight log)")
            elif self.cfg.seeds:
                self.notes.append(
                    "eth_getLogs preflight failed on every configured "
                    "endpoint; fell back to seeds discovery.")
                buy_hashes = self.discover_seeds(self.cfg.seeds)
            else:
                raise RpcError(
                    "no logs-capable endpoint and no --seeds file given; "
                    "cannot enumerate the window. Preflight: "
                    + json.dumps(self.preflight))
        elif mode == "seeds":
            buy_hashes = self.discover_seeds(self.cfg.seeds)
        w = self.window
        for h in buy_hashes:
            rec = self.verify_tx(h)
            if "error" in rec:
                self.out_of_window.append(rec)
                continue
            if not (w["from_block"] <= rec["block"] <= w["to_block"]):
                rec["flag"] = "outside requested window"
                self.out_of_window.append(rec)
                continue
            if rec["token_received_raw"] > 0:
                self.buys.append(rec)
            else:
                rec["flag"] = "no token received by treasury in this tx"
                self.out_of_window.append(rec)
        self.buys.sort(key=lambda r: r["block"])
        # sells discovered via logs-mode scan A arrive as bare transfer
        # records; enrich the ones inside buy txs from verification data
        if self.discovery_used == "seeds":
            for b in self.buys:
                for o in b["treasury_token_out"]:
                    if o["to"] == self.pool:
                        self.sells.append({"tx": b["tx"], "block": b["block"],
                                           "to": o["to"],
                                           "amount_raw": o["amount_raw"],
                                           "scope": "inside a verified seed tx"})
        return self.results()

    def results(self):
        td = self.meta["token_decimals"]
        qd = self.meta["quote_decimals"]
        tot_token = sum(b["token_received_raw"] for b in self.buys)
        tot_value = sum(b["value_native_raw"] for b in self.buys)
        tot_quote = sum(b["quote_into_pool_raw"] for b in self.buys)
        tot_fees = sum(b["fee_native_raw"] for b in self.buys)
        # headline "spent": quote-token that actually entered the pool when
        # observed for every buy; otherwise native tx value (valid when the
        # quote asset is the wrapped native token).
        if self.buys and all(b["quote_into_pool_raw"] > 0 for b in self.buys):
            spent_raw, spent_unit = tot_quote, self.meta["quote_symbol"]
            spent_basis = "quote-token transfers into the pool (receipts)"
        else:
            spent_raw, spent_unit = tot_value, self.preset["native_symbol"]
            spent_basis = "sum of tx.value (native) of the buy transactions"
        avg_price = None
        if tot_token and spent_raw:
            avg_price = (spent_raw / 10 ** qd) / (tot_token / 10 ** td)
        totals = {
            "buy_count": len(self.buys),
            "token_received_raw": tot_token,
            "token_received": fmt_amount(tot_token, td),
            "spent_raw": spent_raw,
            "spent": fmt_amount(spent_raw, qd),
            "spent_unit": spent_unit,
            "spent_basis": spent_basis,
            "native_value_raw": tot_value,
            "fees_native_raw": tot_fees,
            "fees_native": fmt_amount(tot_fees, 18),
            "avg_price_quote_per_token": avg_price,
            "sell_count": len(self.sells),
            "sell_token_raw": sum(s["amount_raw"] for s in self.sells),
            "other_outflow_count": len(self.outflows_other),
        }
        return {
            "tool": "buyback-verifier 1.0",
            "generated_utc": utc_str(int(time.time())),
            "chain": self.cfg.chain,
            "params": {"token": self.token, "treasury": self.treasury,
                       "pool": self.pool},
            "metadata": self.meta,
            "window": self.window,
            "discovery": {"used": self.discovery_used,
                          "preflight": self.preflight,
                          "scan_stats": self.scan_stats,
                          "notes": self.notes},
            "buys": self.buys,
            "sells": self.sells,
            "other_outflows": self.outflows_other,
            "excluded": self.out_of_window,
            "totals": totals,
        }


# --------------------------------------------------------------------------
# report rendering
# --------------------------------------------------------------------------

def _completeness_line(res):
    d = res["discovery"]
    if d["used"] == "logs":
        failed = d["scan_stats"]["failed_ranges"]
        if failed:
            return (f"PARTIAL — log enumeration completed with "
                    f"{len(failed)} failed block range(s): {failed}")
        return ("COMPLETE — the full window was enumerated by chunked "
                "eth_getLogs; no failed ranges.")
    return ("SEED-BASED — every listed buy was verified from raw chain "
            "receipts, but the window was NOT independently enumerated "
            "(no logs-capable endpoint); completeness rests on the seed "
            "list supplied by the caller.")


def render_markdown(res):
    m = res["metadata"]
    t = res["totals"]
    w = res["window"]
    p = res["params"]
    ex = res["chain"]
    pres = CHAIN_PRESETS[ex]
    tsym, qsym = m["token_symbol"], m["quote_symbol"]
    td, qd = m["token_decimals"], m["quote_decimals"]
    L = []
    L.append(f"# Buyback verification — {tsym} ({pres['name']})")
    L.append("")
    L.append(f"Generated {res['generated_utc']} UTC by {res['tool']} "
             f"(read-only chain audit; no explorer index figures used).")
    L.append("")
    L.append("## Scope")
    L.append("")
    L.append(f"- Token: `{p['token']}` ({tsym}, {td} decimals)")
    L.append(f"- Treasury: `{p['treasury']}`")
    L.append(f"- Pool: `{p['pool']}` (quote asset {qsym})")
    L.append(f"- Window: {utc_str(w['from_ts'])} → {utc_str(w['to_ts'])} UTC "
             f"(blocks {w['from_block']:,}–{w['to_block']:,})")
    L.append(f"- Discovery transport: **{res['discovery']['used']}** — "
             + _completeness_line(res))
    L.append("")
    L.append("## Result")
    L.append("")
    L.append(f"- **Buys: {t['buy_count']}**")
    L.append(f"- **Total spent: {t['spent']} {t['spent_unit']}** "
             f"(basis: {t['spent_basis']})")
    L.append(f"- **Total received: {t['token_received']} {tsym}**")
    if t["avg_price_quote_per_token"]:
        L.append(f"- **Average price: "
                 f"{fmt_sci(t['avg_price_quote_per_token'])} "
                 f"{qsym} per {tsym}**")
    L.append(f"- **Sells by treasury into the pool: {t['sell_count']}**")
    L.append(f"- Gas fees paid by treasury for the buys: "
             f"{t['fees_native']} {pres['native_symbol']}")
    L.append("")
    L.append("## Buys (each verified from its transaction receipt)")
    L.append("")
    L.append(f"| # | UTC time | Block | Tx | Spent ({qsym}) | "
             f"Received ({tsym}) | Price ({qsym}/{tsym}) | Recipient |")
    L.append("|---|---|---|---|---|---|---|---|")
    for i, b in enumerate(res["buys"], 1):
        spent = (b["quote_into_pool_raw"] or b["value_native_raw"])
        price = ""
        if b["token_received_raw"] and spent:
            price = fmt_sci((spent / 10 ** qd)
                            / (b["token_received_raw"] / 10 ** td))
        recip = ", ".join(r[:10] + "…" for r in b["token_recipients"]) or "-"
        L.append(f"| {i} | {b['time_utc']} | {b['block']:,} | "
                 f"[{b['tx'][:14]}…]({pres['explorer_tx']}{b['tx']}) | "
                 f"{fmt_amount(spent, qd)} | "
                 f"{fmt_amount(b['token_received_raw'], td)} | {price} | "
                 f"{recip} |")
    L.append("")
    L.append("## Sells")
    L.append("")
    if res["sells"]:
        L.append(f"{len(res['sells'])} treasury→pool token transfer(s) found:")
        L.append("")
        for s in res["sells"]:
            L.append(f"- block {s['block']:,} — "
                     f"[{s['tx'][:14]}…]({pres['explorer_tx']}{s['tx']}) — "
                     f"{fmt_amount(s['amount_raw'], td)} {tsym}")
    else:
        scope = ("in the enumerated window" if res["discovery"]["used"] == "logs"
                 else "inside any of the verified transactions (window-wide "
                      "outflow enumeration unavailable — see Method & limits)")
        L.append(f"**No sells found** {scope}: the treasury sent no {tsym} "
                 f"to the pool.")
    if res["other_outflows"]:
        L.append("")
        L.append(f"Note: {len(res['other_outflows'])} treasury {tsym} "
                 f"outflow(s) to addresses other than the pool were observed "
                 f"(e.g. payouts/distributions); they are not sells and are "
                 f"listed in the JSON output.")
    L.append("")
    L.append("## Method & limits")
    L.append("")
    L.append("- Candidate transactions come from the discovery transport "
             "named above; **every figure is then re-derived from raw chain "
             "data** — `eth_getTransactionByHash`, "
             "`eth_getTransactionReceipt`, `eth_getBlockByNumber` — via "
             "public BSC RPC. Token amounts are the exact ERC-20 `Transfer` "
             "log values (wei-exact), not index data.")
    L.append("- A buy is a transaction in which the pool sends the token "
             "to the treasury; the amount received is the sum of the "
             "receipt's pool→treasury `Transfer` logs for the token. "
             "Quote spent is measured from quote-token transfers into the "
             "pool in the same receipt, falling back to the transaction's "
             "native value.")
    L.append("- Log enumeration is chunked: public BSC endpoints reject "
             "`eth_getLogs` ranges above roughly 1,000 blocks (error "
             "-32005), so the scan walks the window in adaptive chunks and "
             "records any range it could not fetch.")
    if res["discovery"]["used"] == "seeds":
        L.append("- **This run used seeds discovery**: the seed hashes are "
                 "the caller's list (e.g. a project's published buyback "
                 "receipts). Buys not on the list cannot be found by this "
                 "run, and the sell check covers the verified transactions "
                 "themselves; a window-wide treasury outflow scan requires "
                 "a logs-capable endpoint (preflight results are in the "
                 "JSON output).")
    L.append("- Public BSC RPCs prune historical state (`eth_call` at old "
             "blocks returns 'missing trie node'), so all verification "
             "reads receipts/logs of mined transactions, never historical "
             "state.")
    L.append("- Scope is the single pool given as input: buys routed "
             "through other pools/aggregators, and direct (non-swap) "
             "token transfers into the pool, are outside this report.")
    if res["excluded"]:
        L.append("")
        L.append(f"## Excluded ({len(res['excluded'])})")
        L.append("")
        for e in res["excluded"]:
            L.append(f"- `{e.get('tx')}` — "
                     f"{e.get('flag') or e.get('error') or 'excluded'}")
    L.append("")
    return "\n".join(L)


def render_html(res):
    m = res["metadata"]
    t = res["totals"]
    w = res["window"]
    p = res["params"]
    pres = CHAIN_PRESETS[res["chain"]]
    tsym, qsym = m["token_symbol"], m["quote_symbol"]
    td, qd = m["token_decimals"], m["quote_decimals"]
    E = html.escape
    rows = []
    for i, b in enumerate(res["buys"], 1):
        spent = (b["quote_into_pool_raw"] or b["value_native_raw"])
        price = ""
        if b["token_received_raw"] and spent:
            price = fmt_sci((spent / 10 ** qd)
                            / (b["token_received_raw"] / 10 ** td))
        recip = ", ".join(E(r) for r in b["token_recipients"]) or "-"
        rows.append(
            f"<tr><td>{i}</td><td>{E(b['time_utc'])}</td>"
            f"<td>{b['block']:,}</td>"
            f"<td><a href=\"{pres['explorer_tx']}{b['tx']}\">"
            f"{E(b['tx'][:14])}…</a></td>"
            f"<td class=\"n\">{fmt_amount(spent, qd)}</td>"
            f"<td class=\"n\">{fmt_amount(b['token_received_raw'], td)}</td>"
            f"<td class=\"n\">{price}</td><td class=\"mono\">{recip}</td></tr>")
    if res["sells"]:
        sells_html = "".join(
            f"<li>block {s['block']:,} — <a href=\"{pres['explorer_tx']}"
            f"{s['tx']}\">{E(s['tx'][:14])}…</a> — "
            f"{fmt_amount(s['amount_raw'], td)} {E(tsym)}</li>"
            for s in res["sells"])
        sells_html = f"<p>{len(res['sells'])} sell transfer(s) found:</p>" \
                     f"<ul>{sells_html}</ul>"
    else:
        scope = ("in the enumerated window"
                 if res["discovery"]["used"] == "logs"
                 else "inside any verified transaction (see method note)")
        sells_html = (f"<p class=\"ok\"><strong>No sells.</strong> The "
                      f"treasury sent no {E(tsym)} to the pool {scope}.</p>")
    avg = (f"<div class=\"card\"><div class=\"k\">Average price</div>"
           f"<div class=\"v\">{fmt_sci(t['avg_price_quote_per_token'])} "
           f"{E(qsym)}/{E(tsym)}</div></div>"
           if t["avg_price_quote_per_token"] else "")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{E(tsym)} buyback verification — {utc_str(w['from_ts'])} to {utc_str(w['to_ts'])}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         margin: 0; background: #f7f8fa; color: #1c2330; }}
  .wrap {{ max-width: 980px; margin: 0 auto; padding: 32px 20px 48px; }}
  h1 {{ font-size: 26px; margin: 0 0 4px; }}
  h2 {{ font-size: 18px; margin: 28px 0 10px; }}
  .sub {{ color: #5a6577; font-size: 13px; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
           font-size: 12px; word-break: break-all; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0 4px; }}
  .card {{ background: #fff; border: 1px solid #e2e6ee; border-radius: 10px;
           padding: 14px 16px; min-width: 170px; flex: 1; }}
  .card .k {{ font-size: 12px; color: #5a6577; text-transform: uppercase;
              letter-spacing: .04em; }}
  .card .v {{ font-size: 20px; font-weight: 650; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border: 1px solid #e2e6ee; border-radius: 10px; overflow: hidden; }}
  th, td {{ padding: 8px 10px; border-bottom: 1px solid #eef1f6;
            text-align: left; font-size: 13px; }}
  th {{ background: #f0f2f7; font-weight: 600; }}
  td.n {{ text-align: right; font-variant-numeric: tabular-nums; }}
  a {{ color: #2456c8; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .ok {{ background: #e9f7ee; border: 1px solid #bfe6cc; border-radius: 8px;
         padding: 10px 14px; }}
  .note {{ background: #fff; border: 1px solid #e2e6ee; border-radius: 10px;
           padding: 14px 18px; font-size: 13.5px; line-height: 1.55; }}
  .note li {{ margin: 5px 0; }}
  footer {{ margin-top: 28px; color: #8593a9; font-size: 12px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>{E(tsym)} buyback verification</h1>
  <div class="sub">{E(pres['name'])} · window {utc_str(w['from_ts'])} → {utc_str(w['to_ts'])} UTC
  · blocks {w['from_block']:,}–{w['to_block']:,}</div>
  <div class="sub">Token <span class="mono">{E(p['token'])}</span> ·
  Treasury <span class="mono">{E(p['treasury'])}</span> ·
  Pool <span class="mono">{E(p['pool'])}</span></div>

  <div class="cards">
    <div class="card"><div class="k">Buys</div><div class="v">{t['buy_count']}</div></div>
    <div class="card"><div class="k">Total spent</div><div class="v">{t['spent']} {E(t['spent_unit'])}</div></div>
    <div class="card"><div class="k">Total received</div><div class="v">{t['token_received']} {E(tsym)}</div></div>
    {avg}
    <div class="card"><div class="k">Sells to pool</div><div class="v">{t['sell_count']}</div></div>
  </div>

  <h2>Buys — each verified from its transaction receipt</h2>
  <table>
    <tr><th>#</th><th>UTC time</th><th>Block</th><th>Transaction</th>
    <th style="text-align:right">Spent ({E(qsym)})</th>
    <th style="text-align:right">Received ({E(tsym)})</th>
    <th style="text-align:right">Price</th><th>Recipient</th></tr>
    {''.join(rows)}
  </table>

  <h2>Sells</h2>
  {sells_html}

  <h2>Method &amp; limits</h2>
  <div class="note">
    <ul>
      <li>Discovery transport: <strong>{E(res['discovery']['used'])}</strong> — {E(_completeness_line(res))}</li>
      <li>Every figure is re-derived from raw chain data
      (<span class="mono">eth_getTransactionByHash</span>,
      <span class="mono">eth_getTransactionReceipt</span>,
      <span class="mono">eth_getBlockByNumber</span>) via public BSC RPC.
      Token amounts are the exact ERC-20 <span class="mono">Transfer</span>
      log values (wei-exact), never explorer/index figures.</li>
      <li>Log enumeration is chunked: public BSC endpoints reject
      <span class="mono">eth_getLogs</span> ranges above roughly 1,000 blocks
      (error -32005), so scans walk the window in adaptive chunks and record
      any range that could not be fetched.</li>
      <li>Scope is the single pool above: buys routed through other pools
      or aggregators, and direct non-swap transfers into the pool, are
      outside this report. Gas fees paid by the treasury for these buys:
      {t['fees_native']} {E(pres['native_symbol'])}.</li>
    </ul>
  </div>

  <footer>Generated {E(res['generated_utc'])} UTC by {E(res['tool'])} ·
  read-only audit — figures can be re-checked against any BSC node or
  block explorer.</footer>
</div>
</body>
</html>
"""


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_ts(s, end_of_day=False):
    s = s.strip()
    try:
        if len(s) == 10:
            dt = datetime.datetime.strptime(s, "%Y-%m-%d").replace(
                tzinfo=datetime.timezone.utc)
            if end_of_day:
                dt += datetime.timedelta(hours=23, minutes=59, seconds=59)
            return int(dt.timestamp())
        dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        raise SystemExit(f"unparseable date/time: {s!r} "
                         f"(use YYYY-MM-DD or ISO 8601)")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Verify a token buyback program from raw chain data.")
    ap.add_argument("--chain", default="bsc", choices=sorted(CHAIN_PRESETS))
    ap.add_argument("--token", required=True, help="token contract address")
    ap.add_argument("--treasury", required=True, help="treasury address")
    ap.add_argument("--pool", required=True, help="pool/pair contract address")
    ap.add_argument("--from", dest="from_date", help="window start (UTC date)")
    ap.add_argument("--to", dest="to_date", help="window end (UTC date)")
    ap.add_argument("--from-block", type=int)
    ap.add_argument("--to-block", type=int)
    ap.add_argument("--discovery", default="auto",
                    choices=["auto", "logs", "seeds"])
    ap.add_argument("--seeds", help="file of tx hashes (one per line)")
    ap.add_argument("--chunk", type=int, default=None,
                    help="initial eth_getLogs chunk size in blocks")
    ap.add_argument("--rpc", action="append", dest="logs_rpcs",
                    help="logs-capable RPC endpoint (repeatable)")
    ap.add_argument("--verify-rpc", action="append", dest="verify_rpcs",
                    help="RPC endpoint for receipt verification (repeatable)")
    ap.add_argument("--token-symbol")
    ap.add_argument("--quote-symbol")
    ap.add_argument("--out-prefix", default="report",
                    help="output path prefix (writes .md, .html, .json)")
    cfg = ap.parse_args(argv)
    if cfg.discovery == "seeds" and not cfg.seeds:
        ap.error("--discovery seeds requires --seeds")
    if (cfg.from_block is None) != (cfg.to_block is None):
        ap.error("--from-block and --to-block must be given together")
    if cfg.from_block is None and not (cfg.from_date and cfg.to_date):
        ap.error("give --from/--to dates or --from-block/--to-block")
    cfg.from_ts = parse_ts(cfg.from_date) if cfg.from_date else None
    cfg.to_ts = parse_ts(cfg.to_date, end_of_day=True) if cfg.to_date else None
    for a in ("token", "treasury", "pool"):
        v = getattr(cfg, a)
        if not (v.startswith("0x") and len(v) == 42):
            ap.error(f"--{a} must be a 0x address, got {v!r}")

    v = Verifier(cfg)
    try:
        res = v.run()
    except RpcError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    prefix = cfg.out_prefix
    with open(prefix + ".json", "w") as f:
        json.dump(res, f, indent=2)
    with open(prefix + ".md", "w") as f:
        f.write(render_markdown(res))
    with open(prefix + ".html", "w") as f:
        f.write(render_html(res))
    t = res["totals"]
    print(f"discovery={res['discovery']['used']} buys={t['buy_count']} "
          f"spent={t['spent']} {t['spent_unit']} "
          f"received={t['token_received']} {res['metadata']['token_symbol']} "
          f"sells={t['sell_count']}")
    print(f"wrote {prefix}.md / .html / .json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
