"""Verify whether a proxy can actually carry SMTP traffic.

Two stages, no email is ever sent (we always stop before DATA):
  1. Relay to the target domain's MX on port 25: EHLO / MAIL FROM / RCPT TO.
  2. If port 25 is blocked, try submission ports (587/465) on common relays —
     reaching the 220 greeting proves the proxy can be used to send mail.
"""
import socket
import subprocess
import threading
import time

from . import config
from .network import open_tunnel

_mx_cache = {}
_mx_lock = threading.Lock()


def resolve_mx(domain):
    """Return MX hosts for `domain`, sorted by priority (cached).

    Uses dnspython when available, else falls back to `nslookup`, else the
    domain itself (many domains accept mail on their A record).
    """
    with _mx_lock:
        if domain in _mx_cache:
            return _mx_cache[domain]
    mx = []
    try:
        import dns.resolver  # type: ignore
        answer = dns.resolver.resolve(domain, "MX")
        mx = [str(r.exchange).rstrip(".") for r in sorted(answer, key=lambda r: r.preference)]
    except Exception:
        try:
            out = subprocess.run(["nslookup", "-type=MX", domain],
                                 capture_output=True, text=True, timeout=8).stdout
            pairs = []
            for line in out.splitlines():
                if "mail exchanger" in line:
                    parts = line.split("mail exchanger = ")[-1].split()
                    if len(parts) == 2 and parts[0].rstrip(".").isdigit():
                        pairs.append((int(parts[0]), parts[1].rstrip(".")))
            mx = [h for _, h in sorted(pairs)]
        except Exception:
            mx = []
    if not mx:
        mx = [domain]
    with _mx_lock:
        _mx_cache[domain] = mx
    return mx


def _read_reply(sock):
    """Read one (possibly multi-line) SMTP reply; return (code, last_line)."""
    buf = b""
    while len(buf) < 8192:
        try:
            chunk = sock.recv(1024)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        lines = buf.split(b"\r\n")
        if any(len(x) >= 4 and x[3:4] == b" " for x in lines if x):
            break
    text = buf.decode("latin-1", "ignore")
    code = text[:3] if text[:3].isdigit() else ""
    return code, text.strip().split("\r\n")[-1][:80]


def _blank_result():
    return {"ok": False, "ms": None, "code": "", "message": "-", "route": "-"}


def test_through_proxy(host, port, kind, mx_list):
    """Return a dict: ok, ms, code, message, route (MX-25 / SUBMIT-587 / SUBMIT-465 / -)."""
    result = _blank_result()
    if kind not in ("SOCKS5", "SOCKS4", "HTTP"):
        result["message"] = "type cannot tunnel"
        return result

    # Stage 1: MX on port 25 (true relay check).
    for mx in mx_list[:2]:
        start = time.perf_counter()
        try:
            s = socket.create_connection((host, port), timeout=config.TIMEOUT)
        except OSError:
            result["message"] = "cannot connect to proxy"
            continue
        try:
            with s:
                s.settimeout(config.TIMEOUT_SMTP_PROXY)
                if not open_tunnel(s, kind, mx, 25):
                    result["message"] = f"port 25 blocked (to {mx})"
                    continue
                code, _ = _read_reply(s)
                if code != "220":
                    result.update(code=code, message=f"MX not 220 ({code or 'silent'})")
                    continue
                s.sendall(b"EHLO ksatriabintangsamudra.com\r\n"); _read_reply(s)
                s.sendall(f"MAIL FROM:<{config.FROM_EMAIL}>\r\n".encode()); _read_reply(s)
                s.sendall(f"RCPT TO:<{config.TARGET_EMAIL}>\r\n".encode())
                code, message = _read_reply(s)
                ms = int((time.perf_counter() - start) * 1000)
                try:
                    s.sendall(b"QUIT\r\n")
                except OSError:
                    pass
                if code.startswith("2"):
                    result.update(ok=True, ms=ms, code=code,
                                  message="RCPT accepted", route="MX-25")
                    return result
                result.update(ms=ms, code=code, message=f"RCPT rejected ({code})")
        except socket.timeout:
            result["message"] = "timeout MX:25"
        except OSError as e:
            result["message"] = e.__class__.__name__

    # Stage 2: submission ports on common relays (220 greeting is enough).
    for dest, dest_port in config.SUBMISSION_TARGETS:
        start = time.perf_counter()
        try:
            s = socket.create_connection((host, port), timeout=config.TIMEOUT)
        except OSError:
            continue
        try:
            with s:
                s.settimeout(config.TIMEOUT_SMTP_PROXY)
                if not open_tunnel(s, kind, dest, dest_port):
                    continue
                if dest_port == 465:  # implicit TLS: a successful tunnel is the proof
                    ms = int((time.perf_counter() - start) * 1000)
                    result.update(ok=True, ms=ms, code="220",
                                  message=f"submission OK ({dest}:{dest_port})",
                                  route="SUBMIT-465")
                    return result
                code, _ = _read_reply(s)
                if code == "220":
                    ms = int((time.perf_counter() - start) * 1000)
                    result.update(ok=True, ms=ms, code="220",
                                  message=f"submission OK ({dest}:{dest_port})",
                                  route=f"SUBMIT-{dest_port}")
                    return result
        except (socket.timeout, OSError):
            continue
    return result
