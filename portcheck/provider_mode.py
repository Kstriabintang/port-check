"""`--provider` mode: test whether a provider gateway blocks SMTP ports.

Opens a connection to several SMTP servers through the gateway, reads only the
220 greeting, then QUITs. No email is sent.
"""
import base64
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from . import config
from .network import recv_exact
from .parsing import find_file

C = config


class GatewayError(Exception):
    def __init__(self, status, detail):
        super().__init__(detail)
        self.status = status
        self.detail = detail


SOCKS5_CODES = {
    1: ("ERROR", "general gateway failure"),
    2: ("BLOCKED", "denied by gateway ruleset"),
    3: ("ERROR", "network unreachable"),
    4: ("ERROR", "host unreachable"),
    5: ("REFUSED", "connection refused by destination"),
    6: ("TIMEOUT", "TTL expired"),
    7: ("ERROR", "command not supported"),
    8: ("ERROR", "address type not supported"),
}


def parse_provider(text):
    text = text.strip().strip("'\" ")
    scheme = "socks5"
    if "://" in text:
        scheme, text = text.split("://", 1)
        scheme = scheme.lower()
    if scheme not in ("socks5", "socks5h", "http", "https"):
        sys.exit(f"Scheme '{scheme}' not supported for provider (use socks5 or http).")
    user = pw = None
    if "@" in text:
        cred, text = text.rsplit("@", 1)
        user, _, pw = cred.partition(":")
    host, _, port = text.strip("/").rpartition(":")
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        sys.exit("Bad provider format. Example: socks5://user:pass@gateway.provider.com:1080")
    return {"scheme": "socks5" if scheme.startswith("socks5") else "http",
            "host": host, "port": int(port), "user": user or None, "pw": pw or ""}


def provider_label(p):
    account = f"{p['user']}:***@" if p["user"] else ""
    return f"{p['scheme']}://{account}{p['host']}:{p['port']}"


def _tunnel_socks5_auth(s, dest, port, user, pw):
    s.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
    reply = recv_exact(s, 2)
    if len(reply) < 2 or reply[0] != 5:
        raise GatewayError("GATEWAY", "gateway is not SOCKS5")
    if reply[1] == 2:
        if not user:
            raise GatewayError("LOGIN", "gateway requires login")
        u, p = user.encode(), pw.encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        r = recv_exact(s, 2)
        if len(r) < 2 or r[1] != 0:
            raise GatewayError("LOGIN", "username/password rejected by gateway")
    elif reply[1] != 0:
        raise GatewayError("LOGIN", "login method not supported")
    name = dest.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
    head = recv_exact(s, 4)
    if len(head) < 4:
        raise GatewayError("BLOCKED", "gateway closed connection on request")
    if head[1] != 0:
        status, detail = SOCKS5_CODES.get(head[1], ("ERROR", f"SOCKS5 code {head[1]}"))
        raise GatewayError(status, detail)
    atyp = head[3]
    if atyp == 3:
        length = recv_exact(s, 1)
        rest = (length[0] if length else 0) + 2
    else:
        rest = {1: 4, 4: 16}.get(atyp, 4) + 2
    recv_exact(s, rest)
    return b""


def _tunnel_http_connect(s, dest, port, user, pw):
    req = f"CONNECT {dest}:{port} HTTP/1.1\r\nHost: {dest}:{port}\r\n"
    if user:
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        req += f"Proxy-Authorization: Basic {token}\r\n"
    s.sendall((req + "\r\n").encode())
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 8192:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk
    line = data.split(b"\r\n", 1)[0].decode("latin-1")
    parts = line.split()
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    if code == 407:
        raise GatewayError("LOGIN", "credentials rejected by gateway (407)")
    if code == 403:
        raise GatewayError("BLOCKED", "CONNECT denied by gateway (403)")
    if code != 200:
        raise GatewayError("ERROR", f"CONNECT failed: {line[:60] or 'no response'}")
    return data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""


def _test_target(prov, dest, port):
    r = {"time": datetime.now().strftime("%H:%M:%S"), "dest": dest, "port": port,
         "status": "ERROR", "ms": None, "detail": ""}
    import time
    start = time.perf_counter()
    try:
        s = socket.create_connection((prov["host"], prov["port"]), timeout=config.TIMEOUT)
    except OSError as e:
        r.update(status="GATEWAY", detail=f"cannot connect to gateway ({e.__class__.__name__})")
        return r
    try:
        with s:
            s.settimeout(config.TIMEOUT_SMTP_GREETING)
            if prov["scheme"] == "socks5":
                data = _tunnel_socks5_auth(s, dest, port, prov["user"], prov["pw"])
            else:
                data = _tunnel_http_connect(s, dest, port, prov["user"], prov["pw"])
            while b"\n" not in data and len(data) < 1024:
                chunk = s.recv(512)
                if not chunk:
                    break
                data += chunk
            r["ms"] = int((time.perf_counter() - start) * 1000)
            greeting = data.split(b"\n", 1)[0].decode("latin-1").strip()
            if greeting.startswith("220"):
                r.update(status="OPEN", detail=greeting[:80])
            elif greeting:
                r.update(status="NOT-220", detail=greeting[:80])
            else:
                r.update(status="SILENT", detail="connected but no greeting (likely filtered)")
            try:
                s.sendall(b"QUIT\r\n")
            except OSError:
                pass
    except GatewayError as e:
        r.update(status=e.status, detail=e.detail)
    except socket.timeout:
        r.update(status="TIMEOUT", detail="no response before timeout")
    except OSError as e:
        r.update(status="ERROR", detail=e.__class__.__name__)
    return r


def _status_color(status):
    if status == "OPEN":
        return C.GREEN
    if status in ("BLOCKED", "TIMEOUT", "SILENT", "REFUSED"):
        return C.RED
    return C.YELLOW


def run(value):
    if not value:
        path = find_file(config.PROVIDER_FILE)
        if not path:
            sys.exit(f"{config.PROVIDER_FILE} not found. Put one line, e.g.:\n"
                     f"  socks5://user:password@gateway.provider.com:1080")
        with open(path) as f:
            lines = [ln.split("#")[0].strip() for ln in f.read().splitlines()]
        lines = [ln for ln in lines if ln]
        if not lines:
            sys.exit(f"{config.PROVIDER_FILE} is empty.")
        value = lines[0]
    prov = parse_provider(value)

    print(f"{C.BOLD}SMTP test via provider{C.RESET}  {provider_label(prov)}")
    print(f"{C.GRAY}Reads only the 220 greeting then QUITs. No email is sent.{C.RESET}\n")

    results = []
    ex = ThreadPoolExecutor(max_workers=len(config.PROVIDER_SMTP_TARGETS))
    futures = [ex.submit(_test_target, prov, h, p) for h, p in config.PROVIDER_SMTP_TARGETS]
    try:
        for f in as_completed(futures):
            r = f.result()
            results.append(r)
            ms = f"{r['ms']}ms" if r["ms"] else "-"
            print(f"{_status_color(r['status'])}{r['status']:<10}"
                  f"{r['dest'] + ':' + str(r['port']):<46}{ms:>7}  {r['detail']}{C.RESET}")
    except KeyboardInterrupt:
        for f in futures:
            f.cancel()
        print(f"{C.YELLOW}Stopped.{C.RESET}")
    finally:
        ex.shutdown(wait=False)

    print(f"\n{C.BOLD}===== CONCLUSION ====={C.RESET}")
    if not results:
        print("No results.")
        return
    access_issues = [r for r in results if r["status"] in ("GATEWAY", "LOGIN")]
    open_ok = [r for r in results if r["status"] == "OPEN"]
    if access_issues:
        print(f"{C.YELLOW}Gateway/login problem ({access_issues[0]['detail']}). "
              f"Cannot conclude about SMTP yet.{C.RESET}")
    elif len(open_ok) == len(results):
        print(f"{C.GREEN}Provider does NOT block SMTP: all targets replied 220.{C.RESET}")
    elif not open_ok:
        print(f"{C.RED}Provider LIKELY blocks SMTP: no target replied 220.{C.RESET}")
    else:
        listing = ", ".join(f"{r['dest']}:{r['port']}" for r in open_ok)
        print(f"{C.YELLOW}Partially open ({len(open_ok)}/{len(results)}): {listing}{C.RESET}")
    print(f"{C.GRAY}Note: TIMEOUT/SILENT may also come from the destination, not only the provider.{C.RESET}")
