"""Rebuild the final result files from a `.progress.txt` backup.

Used when a scan was stopped (Ctrl+C) before the final files were written.
The backup has terse lines like:
    socks5://1.2.3.4:1080    active  FAST    155ms  smtp=MX-25
We reconstruct enough of each result record for the report writers. GeoIP/ISP
detail is not in the backup, so provider/country grouping falls back to the
IP's /24 block (this is expected and noted).
"""
import re

from . import config, report
from .checker import blank_result
from .speed import grade

C = config
_LINE = re.compile(
    r"^(?P<scheme>\w+)://(?P<host>[^:]+):(?P<port>\d+)\s+"
    r"(?P<status>\w+)\s+(?P<speed>\S+)\s+(?:(?P<ms>\d+)ms)?\s*(?:smtp=(?P<route>\S+))?\s*$"
)
SCHEME_TYPE = {"socks5": "SOCKS5", "socks4": "SOCKS4", "http": "HTTP", "https": "HTTPS"}


def _parse_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _LINE.match(line)
    if not m:
        return None
    g = m.groupdict()
    host, port = g["host"], int(g["port"])
    r = blank_result(host, port)
    r["type"] = SCHEME_TYPE.get(g["scheme"], "?")
    status = g["status"]
    r["open"] = status in ("active", "open")
    r["active"] = status == "active"
    r["ms"] = int(g["ms"]) if g["ms"] else None
    # Trust the recorded speed label, but recompute "bad" from the ms threshold.
    r["speed"] = g["speed"] if g["speed"] != "-" else "-"
    _, r["bad"] = grade(r["ms"])
    if g["route"]:
        r["smtp_ok"] = True
        r["smtp_route"] = g["route"]
        r["smtp_ms"] = r["ms"]
        r["smtp_code"] = "220"
    return r


def run(path=None):
    path = path or config.PROGRESS_FILE
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        print(f"{C.RED}Cannot read {path}: {e}{C.RESET}")
        return

    results = [r for r in (_parse_line(ln) for ln in lines) if r]
    if not results:
        print(f"{C.YELLOW}No usable records found in {path}.{C.RESET}")
        return

    print(f"{C.BOLD}Recovering from {path}{C.RESET}  "
          f"{C.GRAY}({len(results)} records){C.RESET}")
    print(f"{C.GRAY}Note: ISP/country detail isn't in the backup, so grouping "
          f"falls back to /24 blocks.{C.RESET}\n")

    stats = report.write_all(results)
    report.print_summary(results, len(results))
    print(f"\n{C.BOLD}Recovered result files:{C.RESET}")
    print(f"  {config.ALL_PROXIES_FILE}")
    if stats["smtp"]:
        print(f"  {C.GREEN}{config.SMTP_PROXIES_FILE}  ({stats['smtp']} SMTP-capable){C.RESET}")
    print(f"  {config.READY_DIR}/  (fast / socks5 / http / smtp)")
