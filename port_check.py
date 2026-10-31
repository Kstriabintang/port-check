#!/usr/bin/env python3
"""Port Check — free-proxy scanner with real SMTP verification and speed grading.

Usage:
  python port_check.py                      scan every proxy in Proxy.txt
  python port_check.py 1.2.3.4:1080 ...     scan specific proxies
  python port_check.py --provider           test if a provider gateway blocks SMTP
  python port_check.py --provider socks5://user:pass@gw.example.com:1080

Results are written to the results/ folder as plain text (+ one JSON).
See README.md for what each file and column means.
"""
from portcheck.runner import main

if __name__ == "__main__":
    main()
