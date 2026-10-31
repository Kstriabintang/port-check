#!/usr/bin/env python3
"""Send ONE test email through a proxy using an SMTP relay (default: Resend).

The proxy is only the network path; the relay (Resend) actually sends the mail
using your credentials. No credentials are hard-coded — they come from the
environment (or --api-key). Only a single message is sent.

Setup (Resend):
  export RESEND_API_KEY="re_xxxxxxxx"          # from https://resend.com/api-keys
  # 'from' must be an address on a domain you verified in Resend:
  export MAIL_FROM="test@ksatriabintangsamudra.com"

Run:
  python send_test.py --proxy socks5://1.2.3.4:1080 --to omelak@hotmail.com

Pick a proxy that passed the SMTP test, e.g. a line from results/ready/smtp.txt.
"""
import argparse
import os
import smtplib
import socket
import ssl
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, formataddr

from portcheck.network import open_tunnel


def load_dotenv(path=".env"):
    """Load KEY=VALUE lines from a local .env file into the environment.

    Keeps secrets out of the code and out of git (.env is git-ignored).
    Existing environment variables are not overwritten.
    """
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)

RELAYS = {
    "resend": {"host": "smtp.resend.com", "user": "resend"},
    "brevo":  {"host": "smtp-relay.brevo.com", "user": None},  # user = your Brevo login
}


def _paragraphs(text):
    """Split plain text into paragraphs (blank-line separated) for the HTML part."""
    parts, buf = [], []
    for line in text.splitlines():
        if line.strip():
            buf.append(line.strip())
        elif buf:
            parts.append(" ".join(buf)); buf = []
    if buf:
        parts.append(" ".join(buf))
    return parts or [text.strip()]


def parse_proxy(text):
    """Parse scheme://host:port into (kind, host, port)."""
    text = text.strip()
    scheme = "socks5"
    if "://" in text:
        scheme, text = text.split("://", 1)
    text = text.split("@")[-1].strip("/")
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        sys.exit(f"Bad proxy format: {text!r}. Use scheme://host:port")
    kind = {"socks5": "SOCKS5", "socks5h": "SOCKS5", "socks4": "SOCKS4",
            "http": "HTTP", "https": "HTTP"}.get(scheme.lower())
    if not kind:
        sys.exit(f"Unsupported proxy scheme: {scheme}")
    return kind, host, int(port)


def tunneled_socket(proxy_kind, proxy_host, proxy_port, dest_host, dest_port, timeout):
    """Return a raw socket already tunneled through the proxy to dest_host:dest_port."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.settimeout(timeout)
    if not open_tunnel(s, proxy_kind, dest_host, dest_port):
        s.close()
        raise RuntimeError(f"proxy could not tunnel to {dest_host}:{dest_port} "
                           f"(port likely blocked)")
    return s


def send(args):
    relay = RELAYS[args.relay]
    smtp_host = args.smtp_host or relay["host"]
    smtp_port = args.smtp_port

    # Credentials
    if args.relay == "resend":
        user = "resend"
        password = args.api_key or os.environ.get("RESEND_API_KEY")
        if not password:
            sys.exit("Missing Resend API key. Set RESEND_API_KEY or pass --api-key.")
    else:
        user = args.user or os.environ.get("SMTP_USER")
        password = args.api_key or os.environ.get("SMTP_PASS")
        if not (user and password):
            sys.exit("Missing SMTP_USER / SMTP_PASS for this relay.")

    mail_from = args.mail_from or os.environ.get("MAIL_FROM")
    if not mail_from:
        sys.exit("Missing 'from' address. Set MAIL_FROM (a domain verified in Resend) "
                 "or pass --from.")

    use_proxy = not args.no_proxy
    if use_proxy:
        proxy_kind, proxy_host, proxy_port = parse_proxy(args.proxy)
        print(f"Proxy : {args.proxy}  ({proxy_kind})")
    else:
        print("Proxy : (none — direct connection to relay)")
    print(f"Relay : {smtp_host}:{smtp_port}  (user={user})")
    print(f"From  : {mail_from}")
    print(f"To    : {args.to}\n")

    # 1) Connect to the relay — directly or through the proxy — and get a
    #    ready SMTP session object either way.
    if use_proxy:
        print("[1/5] Opening tunnel through proxy ...")
        try:
            raw = tunneled_socket(proxy_kind, proxy_host, proxy_port,
                                  smtp_host, smtp_port, args.timeout)
        except Exception as e:
            sys.exit(f"FAILED to tunnel: {e}")
        print("[2/5] Starting SMTP session ...")
        smtp = smtplib.SMTP(timeout=args.timeout)
        smtp._host = smtp_host       # needed by starttls() for TLS SNI/hostname
        smtp.sock = raw
        smtp.file = smtp.sock.makefile("rb")
        code, msg = smtp.getreply()
        if code != 220:
            sys.exit(f"FAILED: relay greeting was {code} {msg!r}")
    else:
        print("[1/5] Connecting directly to relay ...")
        print("[2/5] Starting SMTP session ...")
        try:
            smtp = smtplib.SMTP(smtp_host, smtp_port, timeout=args.timeout)
        except OSError as e:
            sys.exit(f"FAILED to connect: {e}")

    try:
        smtp.ehlo()

        # 3) STARTTLS (587) / implicit TLS (465) / plaintext (--no-tls).
        if args.no_tls:
            print("[3/5] WARNING: --no-tls set; Resend requires TLS and will "
                  "likely reject AUTH. Continuing without encryption ...")
        elif smtp_port != 465:
            print("[3/5] Upgrading to TLS (STARTTLS) ...")
            ctx = ssl.create_default_context()
            smtp.starttls(context=ctx)
            smtp.ehlo()
        else:
            print("[3/5] Port 465: wrapping implicit TLS ...")
            ctx = ssl.create_default_context()
            smtp.sock = ctx.wrap_socket(smtp.sock, server_hostname=smtp_host)
            smtp.file = smtp.sock.makefile("rb")
            smtp.ehlo()

        # 4) Authenticate.
        print("[4/5] Logging in ...")
        smtp.login(user, password)

        # 5) Build and send one real-looking message.
        print("[5/5] Sending email ...")
        domain = mail_from.split("@")[-1]
        # Sender with a human display name: "Name <addr>"
        from_name = args.from_name or os.environ.get("MAIL_FROM_NAME") or "Cek Pos"
        from_header = formataddr((from_name, mail_from))

        # Body: plain text + an HTML alternative (real mail is almost never
        # plain-only 7bit — a multipart/alternative looks far more legitimate).
        if args.body_file:
            with open(args.body_file, encoding="utf-8") as bf:
                text_body = bf.read()
        elif args.body:
            text_body = args.body
        else:
            text_body = (
                f"Hi,\n\n"
                f"Thanks for getting in touch. I'm confirming that we received "
                f"your message and everything is in order on our end.\n\n"
                f"If you have any questions, just reply to this email and I'll "
                f"get back to you.\n\n"
                f"Best regards,\n{from_name}\n{domain}\n"
            )
        html_body = (
            "<!DOCTYPE html><html><body style=\"font-family:Arial,Helvetica,"
            "sans-serif;font-size:15px;color:#222;line-height:1.5\">"
            + "".join(f"<p>{line}</p>" for line in _paragraphs(text_body))
            + "</body></html>"
        )

        em = EmailMessage()
        em["From"] = from_header
        em["To"] = args.to
        em["Subject"] = args.subject
        em["Reply-To"] = mail_from
        em["Date"] = formatdate(localtime=True)
        em["Message-ID"] = make_msgid(domain=domain)
        # A valid unsubscribe header lowers spam score for legitimate senders.
        em["List-Unsubscribe"] = f"<mailto:{mail_from}?subject=unsubscribe>"
        em["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
        em.set_content(text_body)
        em.add_alternative(html_body, subtype="html")
        smtp.send_message(em)
        print(f"\nSUCCESS: message handed to {smtp_host}. Check {args.to} "
              f"(including spam).")
    except smtplib.SMTPAuthenticationError as e:
        sys.exit(f"FAILED auth: {e}")
    except smtplib.SMTPException as e:
        sys.exit(f"FAILED SMTP: {e}")
    finally:
        try:
            smtp.quit()
        except Exception:
            try:
                raw.close()
            except Exception:
                pass


def main():
    load_dotenv()  # pull RESEND_API_KEY / MAIL_FROM / MAIL_TO from .env if present
    p = argparse.ArgumentParser(description="Send one test email through a proxy.")
    p.add_argument("--proxy", default=os.environ.get("TEST_PROXY"),
                   help="scheme://host:port (or set TEST_PROXY in .env)")
    p.add_argument("--no-proxy", action="store_true",
                   help="connect directly to the relay (no proxy)")
    p.add_argument("--to", default=os.environ.get("MAIL_TO"),
                   help="recipient address (or set MAIL_TO in .env)")
    p.add_argument("--relay", choices=list(RELAYS), default="resend")
    p.add_argument("--from", dest="mail_from", help="sender (verified domain in relay)")
    p.add_argument("--api-key", help="relay API key / password (prefer env var)")
    p.add_argument("--user", help="SMTP username (non-Resend relays)")
    p.add_argument("--smtp-host", help="override relay host")
    p.add_argument("--smtp-port", type=int, default=587, help="587 (STARTTLS) or 465 (TLS)")
    p.add_argument("--from-name", help="sender display name (or MAIL_FROM_NAME in .env)")
    p.add_argument("--subject", default="Re: your enquiry", help="email subject")
    p.add_argument("--body", help="plain-text body (overrides the default)")
    p.add_argument("--body-file", help="read the plain-text body from a file")
    p.add_argument("--no-tls", action="store_true",
                   help="skip TLS (not recommended; Resend will likely reject auth)")
    p.add_argument("--timeout", type=float, default=20, help="socket timeout (s)")
    args = p.parse_args()
    if not args.no_proxy and not args.proxy:
        sys.exit("Missing proxy. Set TEST_PROXY in .env, pass --proxy, or use --no-proxy.")
    if not args.to:
        sys.exit("Missing recipient. Set MAIL_TO in .env or pass --to you@example.com")
    send(args)


if __name__ == "__main__":
    main()
