#!/usr/bin/env python3
"""SocksNode API checker — account balance and datacenter pricing.

The API key is read from the SOCKSNODE_API_KEY environment variable so it is
never hard-coded in the repository:

    export SOCKSNODE_API_KEY="sk_..."
    python socksnode_check.py

(You may also pass --key sk_... but the environment variable is preferred.)
"""
import argparse
import json
import os
import sys

import requests

BASE_URL = "https://socksnode.com/api/v1"
TIMEOUT = 20

STATUS_HINTS = {
    401: "API key is invalid or revoked.",
    402: "Insufficient balance or bandwidth.",
    403: "API key lacks the required permission.",
    404: "Endpoint not found.",
    429: "API rate limit reached.",
}


def get_api_key(cli_key=None):
    key = cli_key or os.environ.get("SOCKSNODE_API_KEY")
    if not key:
        sys.exit("Missing API key. Set SOCKSNODE_API_KEY or pass --key.")
    return key


def check_endpoint(session, name, path, params=None):
    print(f"\n{'=' * 45}\n {name}\n{'=' * 45}")
    try:
        response = session.get(f"{BASE_URL}{path}", params=params, timeout=TIMEOUT)
    except requests.Timeout:
        print("Request timed out: the server took too long to respond.")
        return
    except requests.ConnectionError:
        print("Failed to connect to the SocksNode server.")
        return
    except requests.RequestException as error:
        print("Request failed:", error)
        return

    print("HTTP status:", response.status_code)
    try:
        print(json.dumps(response.json(), indent=2, ensure_ascii=False))
    except ValueError:
        print(response.text[:1000])

    hint = STATUS_HINTS.get(response.status_code)
    if hint:
        print("\n" + hint)


def build_session(api_key):
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    })
    return session


def main():
    parser = argparse.ArgumentParser(description="Check SocksNode account and pricing.")
    parser.add_argument("--key", help="API key (overrides SOCKSNODE_API_KEY).")
    parser.add_argument("--gb", type=int, default=5, help="GB amount for the pricing query.")
    args = parser.parse_args()

    session = build_session(get_api_key(args.key))

    print("=" * 45)
    print("          SOCKSNODE API CHECKER")
    print("=" * 45)

    check_endpoint(session, "ACCOUNT & BALANCE", "/account")
    check_endpoint(session, "DATACENTER PRICING", "/pricing",
                   {"product": "datacenter", "gb": args.gb})

    print("\nDone.")


if __name__ == "__main__":
    main()
