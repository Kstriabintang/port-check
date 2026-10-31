"""Detect proxy type (SOCKS5/SOCKS4/HTTP/HTTPS) and guess the service behind a port."""
import socket

from . import config
from .network import is_tls_port

# Service guess from port number (only used when there is no banner).
PORT_SERVICE = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP-submission",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 3128: "Squid", 3306: "MySQL",
    3389: "RDP", 4145: "SOCKS4", 5432: "PostgreSQL", 8000: "HTTP-alt",
    8080: "HTTP-alt", 8081: "HTTP-alt", 8118: "Privoxy", 8443: "HTTPS-alt",
    8888: "HTTP-alt", 9050: "Tor SOCKS", 9150: "Tor SOCKS",
}

# Keywords found in a banner/header -> service name.
BANNER_KEYWORDS = (
    ("squid", "Squid"), ("tinyproxy", "Tinyproxy"), ("3proxy", "3proxy"),
    ("privoxy", "Privoxy"), ("haproxy", "HAProxy"), ("mitmproxy", "mitmproxy"),
    ("mikrotik", "MikroTik"), ("cloudflare", "Cloudflare"), ("nginx", "nginx"),
    ("apache", "Apache"), ("microsoft-iis", "IIS"), ("lighttpd", "lighttpd"),
)


def _https_complaint(text):
    """A real HTTP response complaining that plain HTTP was sent to an HTTPS port."""
    t = text.lower()
    return any(k in t for k in ("plain http request was sent to https",
                                "speaking plain http to an ssl-enabled",
                                "ssl-enabled server port"))


def guess_service(port, kind, text):
    t = (text or "").lower()
    for keyword, name in BANNER_KEYWORDS:
        if keyword in t:
            return name
    if t.startswith("ssh-"):
        return "SSH"
    if t.startswith("220"):
        return "FTP/SMTP"
    if t.startswith("+ok"):
        return "POP3"
    if t.startswith("* ok"):
        return "IMAP"
    if t.startswith("rfb"):
        return "VNC"
    guess = PORT_SERVICE.get(port)
    if guess:
        return f"{guess}?"
    if kind in ("SOCKS5", "SOCKS4"):
        return "SOCKS proxy"
    return "-"


def detect_type(host, port):
    """Return (type, service). type is SOCKS5, SOCKS4, HTTP, HTTPS, or '?'."""
    # SOCKS5 handshake
    try:
        with socket.create_connection((host, port), timeout=config.TIMEOUT) as s:
            s.settimeout(config.TIMEOUT)
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) == b"\x05\x00":
                return "SOCKS5", guess_service(port, "SOCKS5", "")
    except OSError:
        pass
    # SOCKS4 handshake
    try:
        with socket.create_connection((host, port), timeout=config.TIMEOUT) as s:
            s.settimeout(config.TIMEOUT)
            ip = socket.inet_aton(socket.gethostbyname(config.INFO_HOST))
            s.sendall(b"\x04\x01" + config.INFO_PORT.to_bytes(2, "big") + ip + b"\x00")
            r = s.recv(8)
            if len(r) >= 2 and r[0] == 0 and r[1] in (0x5A, 0x5B, 0x5C, 0x5D):
                return "SOCKS4", guess_service(port, "SOCKS4", "")
    except OSError:
        pass
    # A TLS port is not a plain HTTP proxy
    if is_tls_port(host, port):
        return "HTTPS", guess_service(port, "HTTPS", "")
    # HTTP proxy probe
    try:
        with socket.create_connection((host, port), timeout=config.TIMEOUT) as s:
            s.settimeout(config.TIMEOUT)
            s.sendall(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
                      b"Connection: close\r\n\r\n")
            text = s.recv(1024).decode("latin-1")
            if text.startswith("HTTP/"):
                if _https_complaint(text):
                    return "HTTPS", guess_service(port, "HTTPS", text)
                return "HTTP", guess_service(port, "HTTP", text)
    except OSError:
        pass
    # Unknown: listen for a passive banner (SSH/FTP/SMTP greet first)
    banner = ""
    try:
        with socket.create_connection((host, port), timeout=config.TIMEOUT) as s:
            s.settimeout(config.TIMEOUT_BANNER)
            banner = s.recv(128).decode("latin-1")
    except OSError:
        pass
    return "?", guess_service(port, "?", banner)
