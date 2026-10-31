"""Write clean TXT/JSON result files and print the terminal summary.

Column meanings are documented once in README.md, not repeated in each file.
"""
import json
import os
import threading

from . import config
from .geoip import kind_of, provider_name, asn_of
from . import subnet

C = config
SCHEME = {"SOCKS5": "socks5", "SOCKS4": "socks4", "HTTP": "http", "HTTPS": "https"}


def proxy_uri(r):
    return f"{SCHEME.get(r['type'], 'socks5')}://{r['host']}:{r['port']}"


# SMTP route quality: lower rank = better. MX-25 is a real relay to the target
# domain; SUBMIT-587 is the standard submission port; 465 is implicit-TLS fallback.
ROUTE_RANK = {"MX-25": 0, "SUBMIT-587": 1, "SUBMIT-465": 2}


def smtp_rank(r):
    """Sort key for SMTP-capable proxies: best route first, then fastest."""
    return (ROUTE_RANK.get(r["smtp_route"], 9), r["smtp_ms"] if r["smtp_ms"] is not None else 10**9)


# ---- selections ----
def smtp_passed(results):
    """Proxies that passed the SMTP test AND have a good connection."""
    return [r for r in results if r["smtp_ok"] and not r["bad"]]


def healthy(results):
    """Active + good-speed proxies, de-duplicated by host:port, fastest first."""
    good = [r for r in results if r["active"] and not r["bad"]]
    seen, unique = set(), []
    for r in sorted(good, key=lambda r: r["ms"] or 10**9):
        key = (r["host"], r["port"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def annotate_duplicates(subset):
    """Mark proxies whose IP appears on several ports (so the tool/user understands it)."""
    by_ip = {}
    for r in subset:
        by_ip.setdefault(r["host"], []).append(r)
    for rows in by_ip.values():
        rows.sort(key=lambda r: r["smtp_ms"] if r["smtp_ms"] is not None else 10**9)
        for i, r in enumerate(rows):
            if len(rows) > 1:
                r["_note"] = (f"duplicate IP ({len(rows)} ports, fastest)" if i == 0
                              else f"duplicate IP ({len(rows)} ports)")
            else:
                r["_note"] = ""


# ---- live backup (so Ctrl+C mid-scan still leaves something) ----
class ProgressWriter:
    """Appends one terse line per finished proxy; removed when the run completes."""

    def __init__(self):
        os.makedirs(config.RESULTS_DIR, exist_ok=True)
        self.f = open(config.PROGRESS_FILE, "w", encoding="utf-8")
        self.lock = threading.Lock()
        self.f.write("# live backup; replaced by final result files when the run finishes\n")
        self.f.flush()

    def write(self, r):
        status = "active" if r["active"] else ("open" if r["open"] else "down")
        smtp = f" smtp={r['smtp_route']}" if r["smtp_ok"] else ""
        with self.lock:
            self.f.write(f"{proxy_uri(r):<34} {status:<7} {r['speed']:<7}"
                         f"{(' ' + str(r['ms']) + 'ms') if r['ms'] else '':>8}{smtp}\n")
            self.f.flush()

    def close(self, keep=False):
        with self.lock:
            self.f.close()
        if not keep:
            try:
                os.remove(config.PROGRESS_FILE)
            except OSError:
                pass


# ---- final TXT/JSON files ----
def _table(headers, widths, rows):
    head = "".join(f"{h:<{w}}" for h, w in zip(headers, widths))
    out = [head, "-" * sum(widths)]
    for row in rows:
        out.append("".join(f"{str(c):<{w}}" for c, w in zip(row, widths)))
    return "\n".join(out) + "\n"


def write_all_proxies(results):
    """Active proxies only (the usable ones), SMTP-capable first, then by speed.

    Open/down counts are summarized in a footer instead of listing junk rows.
    """
    active = [r for r in results if r["active"]]
    active.sort(key=lambda r: (not r["smtp_ok"], smtp_rank(r)[0], r["ms"] or 10**9))
    rows = []
    for r in active:
        d = r["info"] or {}
        rows.append([f"{r['host']}:{r['port']}", r["type"], r["speed"],
                     (str(r["ms"]) + "ms") if r["ms"] else "-",
                     "yes" if r["smtp_ok"] else "no", r["smtp_route"],
                     d.get("country", "-") or "-", kind_of(d)])
    text = _table(
        ["PROXY", "TYPE", "SPEED", "LATENCY", "SMTP", "ROUTE", "COUNTRY", "NETWORK"],
        [24, 8, 8, 9, 6, 13, 16, 12], rows)
    open_only = sum(1 for r in results if r["open"] and not r["active"])
    down = sum(1 for r in results if not r["open"])
    footer = (f"\n# {len(active)} active proxies listed. "
              f"Not shown: {open_only} open (port open, not a working proxy), {down} down.\n")
    with open(config.ALL_PROXIES_FILE, "w", encoding="utf-8") as f:
        f.write(text + footer)


def write_smtp_proxies(passed):
    annotate_duplicates(passed)
    groups = {}
    for r in passed:
        groups.setdefault(provider_name(r), []).append(r)

    def group_sort_key(kv):
        # best provider first: best route available, then most proxies
        best = min(ROUTE_RANK.get(r["smtp_route"], 9) for r in kv[1])
        return (best, -len(kv[1]))

    lines = []
    for provider, rows in sorted(groups.items(), key=group_sort_key):
        lines.append(f"{provider}  ({len(rows)} proxies)")
        for r in sorted(rows, key=smtp_rank):
            note = f"   {r['_note']}" if r["_note"] else ""
            lines.append(f"  {proxy_uri(r):<34} {r['smtp_route']:<12} "
                         f"{r['speed']:<7} {str(r['smtp_ms']) + 'ms':>7}{note}")
        lines.append("")
    with open(config.SMTP_PROXIES_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) if lines else "No proxies passed the SMTP test.\n")


def write_ready_lists(results):
    os.makedirs(config.READY_DIR, exist_ok=True)
    good = healthy(results)
    passed = sorted(smtp_passed(results), key=smtp_rank)  # best SMTP route first

    # Cap per /24 so one cooperative block can't dominate the ready lists.
    good, dropped_good = subnet.cap_per_subnet(good, config.READY_PER_SUBNET_CAP)
    passed, dropped_smtp = subnet.cap_per_subnet(passed, config.READY_PER_SUBNET_CAP)

    def dump(name, rows):
        with open(os.path.join(config.READY_DIR, name), "w", encoding="utf-8") as f:
            f.write("".join(proxy_uri(r) + "\n" for r in rows))

    dump("fast.txt", [r for r in good if r["speed"] == "FAST"])
    dump("socks5.txt", [r for r in good if r["type"] == "SOCKS5"])
    dump("http.txt", [r for r in good if r["type"] == "HTTP"])
    dump("smtp.txt", passed)
    return dropped_good + dropped_smtp


def write_subnet_report(results):
    """Report /24 blocks, flagging those that flood the list with junk entries."""
    stats = subnet.analyze(results)
    rows = []
    for d in stats:
        flag = "FLOOD" if d["flooding"] else ""
        rows.append([d["subnet"], d["entries"], d["unique_ips"],
                     d["ports_per_ip"], d["usable"], d["smtp"], flag])
    text = _table(["SUBNET", "ENTRIES", "IPS", "PORTS/IP", "USABLE", "SMTP", "FLAG"],
                  [20, 9, 6, 10, 8, 6, 7], rows)
    floods = subnet.flooding_blocks(stats)
    header = ""
    if floods:
        junk = sum(d["entries"] for d in floods)
        header = (f"# {len(floods)} subnet(s) flagged FLOOD: {junk} padded entries "
                  f"with few usable proxies.\n"
                  f"# Consider pruning these ranges from Proxy.txt.\n\n")
    with open(config.SUBNET_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(header + text)
    return floods


def write_healthy_json(results):
    data = []
    for r in healthy(results):
        d = r["info"] or {}
        data.append({
            "proxy": proxy_uri(r), "host": r["host"], "port": r["port"], "type": r["type"],
            "latency_ms": r["ms"], "speed": r["speed"],
            "smtp_ok": r["smtp_ok"], "smtp_ms": r["smtp_ms"], "smtp_route": r["smtp_route"],
            "country": d.get("country"), "city": d.get("city"),
            "isp": d.get("isp"), "asn": asn_of(r), "network": kind_of(d),
            "exit_ip": d.get("query"),
        })
    with open(config.HEALTHY_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return len(data)


def write_country_report(results):
    good = healthy(results)
    by_country = {}
    for r in good:
        country = (r["info"] or {}).get("country") or "-"
        g = by_country.setdefault(country, {"count": 0, "fast": 0, "smtp": 0, "ms": []})
        g["count"] += 1
        if r["speed"] == "FAST":
            g["fast"] += 1
        if r["smtp_ok"]:
            g["smtp"] += 1
        if r["ms"] is not None:
            g["ms"].append(r["ms"])
    rows = []
    for country, g in sorted(by_country.items(), key=lambda kv: -kv[1]["count"]):
        avg = int(sum(g["ms"]) / len(g["ms"])) if g["ms"] else 0
        rows.append([country, g["count"], g["fast"], g["smtp"], f"{avg}ms"])
    text = _table(["COUNTRY", "HEALTHY", "FAST", "SMTP", "AVG_LATENCY"],
                  [20, 9, 7, 7, 12], rows)
    with open(config.COUNTRY_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(text)
    return len(by_country)


def write_all(results):
    """Write every final file. Returns a small stats dict for the summary."""
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    passed = smtp_passed(results)
    write_all_proxies(results)
    write_smtp_proxies(passed)
    capped = write_ready_lists(results)
    healthy_count = write_healthy_json(results)
    countries = write_country_report(results)
    floods = write_subnet_report(results)
    return {"smtp": len(passed), "healthy": healthy_count, "countries": countries,
            "floods": floods, "capped": capped}


# ---- terminal summary ----
def print_summary(results, total):
    active = sorted((r for r in results if r["active"]), key=lambda r: r["ms"] or 0)
    open_only = [r for r in results if r["open"] and not r["active"]]
    print(f"\n{C.BOLD}===== RESULTS ====={C.RESET}")
    print(f"{C.GREEN}ACTIVE : {len(active)}{C.RESET}")
    print(f"{C.YELLOW}OPEN   : {len(open_only)} (port open but not usable as a proxy){C.RESET}")
    print(f"{C.RED}DOWN   : {len(results) - len(active) - len(open_only)}{C.RESET}")
    if len(results) < total:
        print(f"{C.GRAY}Not checked: {total - len(results)} (stopped early){C.RESET}")

    passed = smtp_passed(results)
    if passed:
        groups = {}
        for r in passed:
            groups.setdefault(provider_name(r), []).append(r)
        unique_ips = len({r["host"] for r in passed})
        best = sorted(passed, key=smtp_rank)[0]
        n_mx = sum(1 for r in passed if r["smtp_route"] == "MX-25")
        n_587 = sum(1 for r in passed if r["smtp_route"] == "SUBMIT-587")
        n_465 = sum(1 for r in passed if r["smtp_route"] == "SUBMIT-465")
        print(f"\n{C.BOLD}===== SMTP-CAPABLE PROXIES (target {config.TARGET_EMAIL}) ====={C.RESET}")
        print(f"{C.GREEN}{len(passed)} proxies{C.RESET} ({unique_ips} unique IPs) "
              f"across {len(groups)} providers  "
              f"{C.GRAY}| best {best['host']}:{best['port']} "
              f"({best['smtp_route']}, {best['smtp_ms']}ms){C.RESET}")
        print(f"{C.GRAY}Routes: {C.GREEN}MX-25: {n_mx}{C.GRAY} | "
              f"{C.GREEN}587: {n_587}{C.GRAY} | 465: {n_465}{C.RESET}\n")
        print(f"{C.BOLD}{'PROVIDER':<40}{'CNT':>4}{'BEST-ROUTE':>12}{'AVG':>7}{C.RESET}")
        print("-" * 64)

        def group_sort_key(kv):
            return (min(ROUTE_RANK.get(r["smtp_route"], 9) for r in kv[1]), -len(kv[1]))

        for provider, rows in sorted(groups.items(), key=group_sort_key):
            best_route = min(rows, key=smtp_rank)["smtp_route"]
            ms = [r["smtp_ms"] for r in rows if r["smtp_ms"] is not None]
            avg = int(sum(ms) / len(ms)) if ms else 0
            name = provider if len(provider) <= 39 else provider[:36] + "..."
            print(f"{C.GREEN}{name:<40}{len(rows):>4}{best_route:>12}{avg:>7}{C.RESET}")
    else:
        active_no_smtp = sum(1 for r in results if r["active"] and not r["smtp_ok"])
        print(f"\n{C.YELLOW}No proxy passed the SMTP test to {config.TARGET_EMAIL}.{C.RESET}")
        if active_no_smtp:
            print(f"{C.GRAY}({active_no_smtp} active proxies but SMTP rejected/blocked/timed out){C.RESET}")
