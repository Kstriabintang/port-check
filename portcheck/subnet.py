"""Detect /24 blocks that flood the list with many entries but few usable proxies.

Free-proxy lists are often padded with a single cooperative host exposed on
dozens of ports. This module measures that so the results stay honest.
"""
from . import config


def subnet_of(host):
    """Return the /24 label for an IPv4 host, or the host itself otherwise."""
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{'.'.join(parts[:3])}.0/24"
    return host


def analyze(results):
    """Group results by /24 and compute usefulness stats.

    Returns a list of dicts sorted by entry count (biggest first):
      subnet, entries, usable (active), smtp, unique_ips, flooding (bool)
    """
    blocks = {}
    for r in results:
        key = subnet_of(r["host"])
        g = blocks.setdefault(key, {"subnet": key, "entries": 0, "usable": 0,
                                    "smtp": 0, "ips": set()})
        g["entries"] += 1
        g["ips"].add(r["host"])
        if r["active"]:
            g["usable"] += 1
        if r["smtp_ok"]:
            g["smtp"] += 1

    out = []
    for g in blocks.values():
        entries = g["entries"]
        ips = len(g["ips"])
        usable_ratio = g["usable"] / entries if entries else 0
        ports_per_ip = entries / ips if ips else 0
        # Flooding: enough entries AND (few IPs spread over many ports OR mostly dead).
        flooding = entries >= config.FLOOD_MIN_ENTRIES and (
            ports_per_ip >= config.FLOOD_PORTS_PER_IP
            or usable_ratio < config.FLOOD_USABLE_RATIO)
        out.append({"subnet": g["subnet"], "entries": entries,
                    "usable": g["usable"], "smtp": g["smtp"],
                    "unique_ips": ips, "ports_per_ip": round(ports_per_ip, 1),
                    "flooding": flooding})
    out.sort(key=lambda d: -d["entries"])
    return out


def flooding_blocks(stats):
    return [d for d in stats if d["flooding"]]


def cap_per_subnet(rows, cap):
    """Keep at most `cap` rows per /24 (rows should already be sorted best-first).

    cap <= 0 disables the limit. Returns (kept_rows, dropped_count).
    """
    if cap <= 0:
        return rows, 0
    seen, kept, dropped = {}, [], 0
    for r in rows:
        key = subnet_of(r["host"])
        if seen.get(key, 0) < cap:
            seen[key] = seen.get(key, 0) + 1
            kept.append(r)
        else:
            dropped += 1
    return kept, dropped
