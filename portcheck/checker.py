"""Orchestrate the full check for a single proxy."""
import threading
import time

from . import config
from .network import port_open
from .detect import detect_type
from .geoip import exit_info
from .smtp_test import resolve_mx, test_through_proxy
from .speed import grade

# Thread-safe tracker of catch-all hosts (open on many ports, never a proxy).
_catchall_hits = {}
_catchall_skipped = set()
_catchall_lock = threading.Lock()


def reset_catchall_tracker():
    """Clear tracker state (call once at the start of a scan)."""
    with _catchall_lock:
        _catchall_hits.clear()
        _catchall_skipped.clear()


def catchall_skipped_count():
    with _catchall_lock:
        return len(_catchall_skipped)


def _is_catchall(host):
    with _catchall_lock:
        return host in _catchall_skipped


def _note_open_not_proxy(host):
    with _catchall_lock:
        _catchall_hits[host] = _catchall_hits.get(host, 0) + 1
        if _catchall_hits[host] >= config.CATCHALL_SKIP_AFTER:
            _catchall_skipped.add(host)


def blank_result(host, port):
    """The result record every proxy produces. Keys stay stable for reports."""
    return {
        "host": host, "port": port,
        "open": False, "type": "-", "service": "-",
        "active": False, "info": None, "info_source": "-", "ms": None,
        # SMTP through the proxy:
        "smtp_ok": False, "smtp_ms": None, "smtp_code": "",
        "smtp_message": "-", "smtp_route": "-",
        # speed:
        "speed": "-", "bad": True,
        # annotations filled in later:
        "_note": "", "skipped": False,
    }


def check_proxy(item, target_domain):
    """Run the full pipeline for one (host, port) and return a result record."""
    host, port = item
    r = blank_result(host, port)
    # Skip hosts already identified as catch-all / honeypot.
    if _is_catchall(host):
        r["skipped"] = True
        return r
    try:
        if not port_open(host, port, config.TIMEOUT_PORT):
            return r
        r["open"] = True
        r["type"], r["service"] = detect_type(host, port)
        if r["type"] in ("SOCKS5", "SOCKS4", "HTTP"):
            start = time.perf_counter()
            d = exit_info(host, port, r["type"])
            if d:
                r.update(active=True, info=d, info_source="exit",
                         ms=int((time.perf_counter() - start) * 1000))
                r["speed"], r["bad"] = grade(r["ms"])
                mx = resolve_mx(target_domain)
                smtp = test_through_proxy(host, port, r["type"], mx)
                r.update(smtp_ok=smtp["ok"], smtp_ms=smtp["ms"], smtp_code=smtp["code"],
                         smtp_message=smtp["message"], smtp_route=smtp["route"])
            else:
                _note_open_not_proxy(host)  # open but tunnel failed
        else:
            _note_open_not_proxy(host)       # open but not a usable proxy type
    except Exception:
        pass
    return r
