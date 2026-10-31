"""GeoIP / ISP lookups via ip-api.com — through the proxy (exit IP) and batch fallback."""
import json
import socket
import time
import urllib.request

from . import config
from .network import recv_all, info_host_header, open_tunnel


def _parse_info(data):
    if b"\r\n\r\n" in data:
        data = data.split(b"\r\n\r\n", 1)[1]
    text = data.decode("utf-8", "ignore")
    a, b = text.find("{"), text.rfind("}")
    if a == -1 or b == -1:
        return None
    try:
        d = json.loads(text[a:b + 1])
    except ValueError:
        return None
    if isinstance(d, dict) and d.get("status") == "success" and d.get("query"):
        return d
    return None


def exit_info(host, port, kind):
    """Open ip-api.com through the proxy and return the exit IP's ISP info, or None."""
    try:
        with socket.create_connection((host, port), timeout=config.TIMEOUT) as s:
            s.settimeout(config.TIMEOUT_EXIT)
            if kind == "HTTP":
                req = (f"GET http://{info_host_header()}{config.INFO_PATH} HTTP/1.0\r\n"
                       f"Host: {info_host_header()}\r\nConnection: close\r\n\r\n")
            else:
                if not open_tunnel(s, kind, config.INFO_HOST, config.INFO_PORT):
                    return None
                req = (f"GET {config.INFO_PATH} HTTP/1.0\r\n"
                       f"Host: {info_host_header()}\r\nConnection: close\r\n\r\n")
            s.sendall(req.encode())
            return _parse_info(recv_all(s))
    except OSError:
        return None


def batch_lookup(ip_list, log=print):
    """Fallback: look up incoming IPs via a direct connection (max 100 per request)."""
    info = {}
    ips = list(dict.fromkeys(ip_list))
    for i in range(0, len(ips), 100):
        if i:
            time.sleep(4.5)  # ip-api limit: 15 batches/minute
        try:
            req = urllib.request.Request(
                f"http://{info_host_header()}/batch?fields={config.INFO_FIELDS}",
                data=json.dumps(ips[i:i + 100]).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as r:
                rows = json.load(r)
            if not isinstance(rows, list):
                continue
            for row in rows:
                if isinstance(row, dict) and row.get("status") == "success" and row.get("query"):
                    info[row["query"]] = row
        except Exception as e:
            log(f"{config.GRAY}Fallback ISP lookup failed ({e}).{config.RESET}")
            break
    return info


# ---- small helpers used by reports ----
def kind_of(d):
    """Classify the exit network: Mobile / Datacenter / Residential."""
    if not d:
        return "-"
    if d.get("mobile"):
        return "Mobile"
    return "Datacenter" if d.get("hosting") else "Residential"


def isp_text(d):
    isp = d.get("isp") or d.get("org") or "-"
    asn = (d.get("as") or "").split(" ")[0]
    return f"{isp} ({asn})" if asn else isp


def asn_of(result):
    """ASN like 'AS45102' from the exit info; fall back to the proxy IP's /24 block."""
    d = result.get("info") or {}
    asn = (d.get("as") or "").split(" ")[0]
    if asn.startswith("AS"):
        return asn
    parts = result["host"].split(".")
    if len(parts) == 4:
        return f"{'.'.join(parts[:3])}.0/24"
    return result["host"]


def provider_name(result):
    """Display name '<ISP> (<ASN>)'. Grouping stays ASN-based so ISP name variants merge."""
    d = result.get("info") or {}
    isp = d.get("isp") or d.get("org") or ""
    asn = asn_of(result)
    return f"{isp} ({asn})" if isp else asn
