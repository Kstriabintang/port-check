"""Low-level socket helpers and proxy tunneling (SOCKS5 / SOCKS4 / HTTP CONNECT)."""
import socket
import ssl

from . import config


def port_open(host, port, timeout=config.TIMEOUT):
    """True if a TCP connection to host:port succeeds within `timeout`."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def recv_exact(sock, n):
    """Read exactly n bytes (or until the peer closes)."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def recv_all(sock, cap=65536):
    """Read until the peer closes or `cap` bytes are collected."""
    data = b""
    while len(data) < cap:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    return data


def info_host_header():
    """Host header value for ip-api requests (omit :80)."""
    return config.INFO_HOST if config.INFO_PORT == 80 else f"{config.INFO_HOST}:{config.INFO_PORT}"


def is_tls_port(host, port):
    """True if the port completes a TLS handshake (i.e. HTTPS/TLS, not plain HTTP)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=config.TIMEOUT) as s:
            s.settimeout(config.TIMEOUT)
            with ctx.wrap_socket(s):
                return True
    except (OSError, ValueError):
        return False


# ---- Tunnel to an arbitrary destination through the proxy (no auth) ----
def open_tunnel(sock, kind, dest_host, dest_port):
    """Open a tunnel to dest_host:dest_port through an already-connected proxy socket.

    `kind` is "SOCKS5", "SOCKS4", or "HTTP". Returns True on success.
    """
    if kind == "SOCKS5":
        return _tunnel_socks5(sock, dest_host, dest_port)
    if kind == "SOCKS4":
        return _tunnel_socks4(sock, dest_host, dest_port)
    if kind == "HTTP":
        return _tunnel_http(sock, dest_host, dest_port)
    return False


def _tunnel_socks5(sock, dest_host, dest_port):
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        return False
    name = dest_host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + dest_port.to_bytes(2, "big"))
    head = recv_exact(sock, 4)
    if len(head) < 4 or head[1] != 0:
        return False
    atyp = head[3]
    if atyp == 3:
        length = recv_exact(sock, 1)
        rest = (length[0] if length else 0) + 2
    else:
        rest = {1: 4, 4: 16}.get(atyp, 4) + 2
    recv_exact(sock, rest)
    return True


def _tunnel_socks4(sock, dest_host, dest_port):
    try:
        ip = socket.inet_aton(socket.gethostbyname(dest_host))
    except OSError:
        return False
    sock.sendall(b"\x04\x01" + dest_port.to_bytes(2, "big") + ip + b"\x00")
    reply = recv_exact(sock, 8)
    return len(reply) == 8 and reply[1] == 0x5A


def _tunnel_http(sock, dest_host, dest_port):
    sock.sendall(f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\n"
                 f"Host: {dest_host}:{dest_port}\r\n\r\n".encode())
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 4096:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    status_line = data.split(b"\r\n", 1)[0].decode("latin-1")
    return " 200 " in status_line or status_line.endswith(" 200")
