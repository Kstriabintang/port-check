# Port Check

A free-proxy scanner that does more than a port check: it verifies whether each
proxy can **actually carry SMTP traffic**, measures connection **speed**, resolves
the **exit ISP/ASN**, and writes clean, ready-to-use result files.

## Requirements

- Python 3.9+
- Optional: `dnspython` for faster/more reliable MX lookups
  (`pip install dnspython`). Without it the scanner falls back to `nslookup`.

## Usage

```bash
# scan every proxy in Proxy.txt
python port_check.py

# scan specific proxies
python port_check.py 1.2.3.4:1080 http://5.6.7.8:3128

# test whether a provider gateway blocks SMTP (reads provider.txt, or pass inline)
python port_check.py --provider
python port_check.py --provider socks5://user:pass@gateway.example.com:1080

# rebuild result files from a backup after a run was stopped early
python port_check.py --recover
```

Press `Ctrl+C` any time to stop; the result files are still written from
whatever was collected. If a run is killed hard, `--recover` rebuilds the
final files from `results/.progress.txt`.

### Work-queue mode (resumable scans)

When reading from `Proxy.txt`, each checked proxy is **removed from the file**.
The file is rewritten every `QUEUE_FLUSH_EVERY` proxies (default 500) and once
when the run ends or is stopped. So `Proxy.txt` always holds only what's left to
check — stop any time and run again to continue where you left off. When the
file is empty, every proxy has been checked.

This mode is **off** when you pass proxies as CLI arguments (those aren't from
the file, so the file is never touched).

## Input files

| File | Purpose |
|------|---------|
| `Proxy.txt` | One proxy per line: `ip:port`, `scheme://ip:port`, or with `user:pass@`. Lines starting with `#` are ignored. |
| `provider.txt` | (Provider mode only) one gateway line, e.g. `socks5://user:pass@gw.example.com:1080`. |

File names are matched case-insensitively, so `Proxy.txt` and `proxy.txt` both work.

## How a proxy is checked

1. **Port open?** Quick TCP connect. If closed → `down`.
2. **Type + service.** Detect `SOCKS5 / SOCKS4 / HTTP / HTTPS`; guess the service
   from banners or the port number (`?` = guess only).
3. **Active + exit ISP.** Open `ip-api.com` through the proxy to get the real
   **exit IP** and its ISP/ASN, and measure latency.
4. **SMTP capability** (no email is ever sent — we always stop before `DATA`):
   - Try to relay to the target domain's MX on port 25 (`EHLO`/`MAIL FROM`/`RCPT TO`).
   - If port 25 is blocked, try submission ports (587/465) on common relays.
   The successful path is recorded as `MX-25`, `SUBMIT-587`, or `SUBMIT-465`.
5. **Speed grade** from latency: `FAST` ≤ 1s, `MEDIUM` ≤ 3s, `SLOW` ≤ 6s,
   `BAD` > 6s. `BAD` proxies are dropped from the ready lists.

SMTP routes are ranked by quality: `MX-25` (real relay to the target domain) >
`SUBMIT-587` (standard submission) > `SUBMIT-465` (implicit-TLS fallback). Result
lists and the summary put the best route first. Note: outbound port 25 is almost
always blocked on free proxies, so `SUBMIT-587` is the realistic best case.

The SMTP target domain and all thresholds live in `portcheck/config.py`.

The scanner shows only the useful extremes in the live feed — `OK` (green) and
`DOWN` (red). `OPEN` proxies (port open but not a working proxy) and catch-all
hosts are counted but hidden to keep the feed readable.

### Catch-all / honeypot skip

Some hosts accept connections on *every* port but are never a working proxy.
After `CATCHALL_SKIP_AFTER` (default 3) such hits on one IP, its remaining ports
are skipped — this keeps `down` counts honest and greatly speeds up the scan.

### Subnet flooding

Free-proxy lists are often padded with a single host exposed on dozens of
ports. The scanner groups results by /24 and flags a block as `FLOOD` when it
has many entries (`FLOOD_MIN_ENTRIES`) and either exposes few IPs over many
ports (`FLOOD_PORTS_PER_IP`) or is mostly dead (`FLOOD_USABLE_RATIO`). Flagged
blocks are reported in `subnet_report.txt` and summarized in the terminal so you
can prune them from `Proxy.txt`. To stop any single block from dominating the
ready lists, at most `READY_PER_SUBNET_CAP` healthy proxies per /24 are exported
(set to 0 to disable). All knobs live in `portcheck/config.py`.

## Output files (`results/`)

| File | What it contains |
|------|------------------|
| `all_proxies.txt` | Every proxy as an aligned table (see columns below). |
| `smtp_proxies.txt` | Only proxies that passed SMTP **and** have a good connection, grouped by provider (ASN). Duplicate IPs on multiple ports are annotated. |
| `country_report.txt` | Per-country quality rollup (healthy count, fast count, SMTP count, average latency). |
| `subnet_report.txt` | Per-/24 breakdown. Blocks that pad the list with many entries but few usable proxies are flagged `FLOOD`. |
| `healthy_proxies.json` | Full structured data for healthy proxies — convenient for your own API/product. |
| `ready/fast.txt` | Healthy proxies graded `FAST`, as `scheme://ip:port`. |
| `ready/socks5.txt` | Healthy SOCKS5 proxies. |
| `ready/http.txt` | Healthy HTTP proxies. |
| `ready/smtp.txt` | Proxies that passed the SMTP test. |

### Column meanings (`all_proxies.txt`)

| Column | Meaning |
|--------|---------|
| `PROXY` | `host:port`. |
| `TYPE` | Proxy protocol: `SOCKS5 / SOCKS4 / HTTP / HTTPS / ?`. |
| `STATUS` | `active` (usable), `open` (port open but not a working proxy), `down`. |
| `SPEED` | `FAST / MEDIUM / SLOW / BAD` from latency. |
| `LATENCY` | Time to fetch exit info through the proxy. |
| `SMTP` | `yes` if the proxy can carry SMTP to the target. |
| `ROUTE` | Which path worked: `MX-25 / SUBMIT-587 / SUBMIT-465`. |
| `COUNTRY` | Country of the **exit IP**. |
| `NETWORK` | `Datacenter / Residential / Mobile`. |

## Free hosting setup (no VPS)

- **`.github/workflows/scan.yml`** — GitHub Actions re-scans every 2 hours and
  commits `results/` back to the repo. Trigger manually via Actions → "Run workflow".
- **`worker/worker.js` + `wrangler.toml`** — Cloudflare Worker serving the same
  API at the edge (landing page as static assets, ready lists read from this
  repo, live single-proxy checks via raw TCP sockets). Note: Workers block
  outbound port 25, so live SMTP tests stay in the scheduled scan.
- Deploy: `npx wrangler deploy` (needs a Cloudflare API token with Workers edit
  permission; optionally create the KV namespace for rate limiting — see
  `wrangler.toml`).

## Web API (optional)

A small FastAPI service wraps the scanner (`api.py` + `static/index.html`):

```bash
pip install -r requirements.txt
uvicorn api:app --port 8000
```

| Endpoint | What it does |
|----------|--------------|
| `GET /` | Landing page with a live single-proxy check form. |
| `GET /api/check?proxy=...` | Full live check of one proxy (free quota: `FREE_CHECKS_PER_DAY`, default 10/day per IP). |
| `GET /api/ready/{fast\|socks5\|http\|smtp}` | Latest ready list as plain text. |
| `GET /api/stats` | Rollup of the last scan (healthy count, SMTP-capable, per-country). |

## Project layout

```
port_check.py            thin entry point
portcheck/
  config.py              all constants (files, timeouts, thresholds, colors)
  parsing.py             read/clean the proxy list, case-insensitive file lookup
  network.py             socket helpers + SOCKS/HTTP tunneling
  detect.py              proxy type + service detection
  geoip.py               ip-api lookups + ISP/ASN helpers
  smtp_test.py           MX resolution + SMTP-through-proxy test
  speed.py               speed grading
  subnet.py              /24 flooding detection + per-subnet cap
  queue.py               Proxy.txt work-queue (remove checked, resume on restart)
  checker.py             full check for one proxy
  display.py             live terminal UI (spinner/progress)
  report.py              write TXT/JSON + terminal summary
  provider_mode.py       --provider gateway SMTP test
  runner.py              main(): orchestration
socksnode_check.py       standalone SocksNode account/pricing checker
```

## Notes on responsible use

- The SMTP check **never sends an email** — it verifies capability and quits.
- Free proxies are volatile (up/down within minutes) and often shared or
  blacklisted. Treat the results as a point-in-time snapshot.
- A sound way to build a service on top of this is selling **verification /
  intelligence** (e.g. per-country health reports), not reselling third-party
  proxies. Do not use these proxies for bulk/unsolicited email.
