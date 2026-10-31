#!/usr/bin/env python3
"""Send an email DIRECTLY to the recipient's MX server, through a proxy.

Unlike send_test.py (which relays via Resend), this speaks SMTP straight to the
recipient's mail server (e.g. Hotmail's MX) *through the proxy*. The recipient
therefore sees the email as coming from the proxy's IP, not from Resend/SES.

No relay account or API key is needed. Deliverability depends entirely on the
PROXY IP's reputation (PTR/reverse DNS, blacklists). Pick a proxy whose SMTP
route was MX-25 in your scan results for the best chance.

Config is read from .env (git-ignored) or CLI flags:
  MAIL_FROM=support@cekpos.my.id
  MAIL_FROM_NAME=Cek Pos Support
  MAIL_TO=omelak@hotmail.com
  TEST_PROXY=socks5://1.2.3.4:1080

Run:
  python send_direct.py
  python send_direct.py --proxy socks5://1.2.3.4:1080 --to omelak@hotmail.com
"""
import argparse
import os
import socket
import ssl
import sys
import uuid
from datetime import datetime, timezone
from email.utils import formatdate, formataddr

from portcheck.network import open_tunnel
from portcheck.smtp_test import resolve_mx


def load_dotenv(path=".env"):
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def parse_proxy(text):
    text = text.strip()
    scheme = "socks5"
    if "://" in text:
        scheme, text = text.split("://", 1)
    text = text.split("@")[-1].strip("/")
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        sys.exit(f"Bad proxy: {text!r}. Use scheme://host:port")
    kind = {"socks5": "SOCKS5", "socks5h": "SOCKS5", "socks4": "SOCKS4",
            "http": "HTTP", "https": "HTTP"}.get(scheme.lower())
    if not kind:
        sys.exit(f"Unsupported proxy scheme: {scheme}")
    return kind, host, int(port)


def _paragraphs(text):
    parts, buf = [], []
    for line in text.splitlines():
        if line.strip():
            buf.append(line.strip())
        elif buf:
            parts.append(" ".join(buf)); buf = []
    if buf:
        parts.append(" ".join(buf))
    return parts or [text.strip()]


def build_message(mail_from, from_name, to_addr, subject, text_body):
    """Build a complete RFC-5322 message with realistic custom headers.

    Everything the sending client controls is set here. Server-added headers
    (Received, source IP) are NOT ours to set and must not be forged.
    """
    domain = mail_from.split("@")[-1]
    boundary = "=_" + uuid.uuid4().hex
    msg_id = f"<{uuid.uuid4().hex}@{domain}>"
    date = formatdate(localtime=True)

    html = ("<!DOCTYPE html><html><head>"
            "<meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "</head><body style=\"margin:0;padding:0;background:#f4f4f4\">"
            "<div style=\"max-width:600px;margin:0 auto;padding:24px;"
            "font-family:Arial,Helvetica,sans-serif;font-size:15px;color:#222;"
            "line-height:1.6;background:#ffffff\">"
            + "".join(f"<p>{p}</p>" for p in _paragraphs(text_body))
            + "<hr style=\"border:none;border-top:1px solid #eee;margin:24px 0\">"
            + f"<p style=\"font-size:12px;color:#888\">{from_name} &middot; "
            + f"{domain}</p>"
            "</div></body></html>")

    headers = [
        f"From: {formataddr((from_name, mail_from))}",
        f"To: {to_addr}",
        f"Subject: {subject}",
        f"Reply-To: {mail_from}",
        f"Date: {date}",
        f"Message-ID: {msg_id}",
        "MIME-Version: 1.0",
        f"List-Unsubscribe: <mailto:{mail_from}?subject=unsubscribe>",
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click",
        "X-Mailer: CekPos Mailer 1.0",
        "X-Priority: 3",
        "Precedence: bulk",
        f"Content-Type: multipart/alternative; boundary=\"{boundary}\"",
    ]
    body = (
        f"--{boundary}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: 7bit\r\n\r\n"
        f"{text_body}\r\n\r\n"
        f"--{boundary}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Transfer-Encoding: 7bit\r\n\r\n"
        f"{html}\r\n\r\n"
        f"--{boundary}--\r\n"
    )
    return "\r\n".join(headers) + "\r\n\r\n" + body, msg_id


def smtp_line(sock):
    """Read one SMTP reply; return (code, text)."""
    buf = b""
    while len(buf) < 8192:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
        lines = buf.split(b"\r\n")
        if any(len(x) >= 4 and x[3:4] == b" " for x in lines if x):
            break
    text = buf.decode("latin-1", "ignore").strip()
    code = text[:3] if text[:3].isdigit() else "000"
    return int(code) if code.isdigit() else 0, text


def send_command(sock, cmd, expect):
    sock.sendall((cmd + "\r\n").encode())
    code, text = smtp_line(sock)
    if code not in expect:
        raise RuntimeError(f"{cmd.split()[0] if cmd else 'DATA'} -> {code} {text[:120]}")
    return code, text


def send(args):
    kind, phost, pport = parse_proxy(args.proxy)
    to_addr = args.to
    to_domain = to_addr.split("@")[-1]
    mail_from = args.mail_from
    from_name = args.from_name or "Support"
    helo_name = mail_from.split("@")[-1]  # HELO with our domain

    mx_list = resolve_mx(to_domain)
    print(f"Proxy  : {args.proxy}  ({kind})")
    print(f"From   : {formataddr((from_name, mail_from))}")
    print(f"To     : {to_addr}")
    print(f"MX     : {mx_list[:3]}\n")

    message, msg_id = build_message(mail_from, from_name, to_addr, args.subject,
                                    _load_body(args))

    last_err = None
    for mx in mx_list[:3]:
        print(f"--> trying MX {mx}:25 through proxy ...")
        try:
            s = socket.create_connection((phost, pport), timeout=args.timeout)
            s.settimeout(args.timeout)
        except OSError as e:
            last_err = f"cannot reach proxy ({e.__class__.__name__})"
            continue
        try:
            with s:
                if not open_tunnel(s, kind, mx, 25):
                    last_err = f"proxy could not tunnel to {mx}:25 (port 25 blocked)"
                    print(f"    {last_err}")
                    continue
                code, text = smtp_line(s)                       # 220 greeting
                if code != 220:
                    last_err = f"no 220 greeting ({code} {text[:60]})"
                    print(f"    {last_err}")
                    continue
                send_command(s, f"EHLO {helo_name}", {250})
                # Opportunistic STARTTLS if the MX offers it (Outlook does).
                if "STARTTLS" in text.upper() or True:
                    try:
                        send_command(s, "STARTTLS", {220})
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        s = ctx.wrap_socket(s, server_hostname=mx)
                        send_command(s, f"EHLO {helo_name}", {250})
                    except Exception:
                        pass  # some MX may not support it; continue plaintext
                send_command(s, f"MAIL FROM:<{mail_from}>", {250})
                send_command(s, f"RCPT TO:<{to_addr}>", {250, 251})
                send_command(s, "DATA", {354})
                s.sendall(message.replace("\r\n.\r\n", "\r\n..\r\n").encode() + b"\r\n.\r\n")
                code, text = smtp_line(s)
                if code in (250,):
                    print(f"\nSUCCESS: {mx} accepted the message ({code} {text[:80]})")
                    print(f"Message-ID: {msg_id}")
                    print(f"Check {to_addr} (inbox AND junk).")
                    try:
                        send_command(s, "QUIT", {221})
                    except Exception:
                        pass
                    return
                last_err = f"MX rejected after DATA ({code} {text[:80]})"
                print(f"    {last_err}")
        except (socket.timeout, OSError, RuntimeError) as e:
            last_err = str(e)
            print(f"    failed: {last_err}")
    sys.exit(f"\nFAILED on all MX hosts. Last error: {last_err}")


def _load_body(args):
    if args.body_file:
        with open(args.body_file, encoding="utf-8") as f:
            return f.read()
    if args.body:
        return args.body
    name = args.from_name or "Support"
    return (f"Hi,\n\n"
            f"Thanks for getting in touch. I'm writing to confirm we received "
            f"your request and it's being handled now.\n\n"
            f"If you need anything else, just reply to this email.\n\n"
            f"Best regards,\n{name}")


def main():
    load_dotenv()
    p = argparse.ArgumentParser(description="Send email directly to recipient MX via a proxy.")
    p.add_argument("--proxy", default=os.environ.get("TEST_PROXY"),
                   help="scheme://host:port (or TEST_PROXY in .env)")
    p.add_argument("--to", default=os.environ.get("MAIL_TO"),
                   help="recipient (or MAIL_TO in .env)")
    p.add_argument("--from", dest="mail_from",
                   default=os.environ.get("MAIL_FROM", "support@cekpos.my.id"),
                   help="sender address (or MAIL_FROM in .env)")
    p.add_argument("--from-name", default=os.environ.get("MAIL_FROM_NAME", "Cek Pos Support"))
    p.add_argument("--subject", default="Your request has been received")
    p.add_argument("--body")
    p.add_argument("--body-file")
    p.add_argument("--timeout", type=float, default=25)
    args = p.parse_args()
    if not args.proxy:
        sys.exit("Missing proxy. Set TEST_PROXY in .env or pass --proxy.")
    if not args.to:
        sys.exit("Missing recipient. Set MAIL_TO in .env or pass --to.")
    send(args)


if __name__ == "__main__":
    main()
