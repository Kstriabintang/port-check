#!/usr/bin/env python3
"""Port Check API — wrap the scanner as a small web service.

Endpoints:
  GET  /                      landing page (static/index.html)
  GET  /api/check?proxy=...   full live check of one proxy (rate-limited)
  GET  /api/ready/{kind}      latest ready list: fast | socks5 | http | smtp
  GET  /api/stats             rollup from the last scan (results/)

Run:
  .venv/bin/uvicorn api:app --host 0.0.0.0 --port 8000
"""
import json
import os
import time
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.concurrency import run_in_threadpool

from portcheck import config
from portcheck.checker import check_proxy
from portcheck.parsing import _normalize

app = FastAPI(title="Port Check API", version="0.1.0")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# ---- Tiny in-memory freemium gate: N free live checks per IP per day ----
FREE_CHECKS_PER_DAY = int(os.environ.get("FREE_CHECKS_PER_DAY", "100"))
_usage = defaultdict(list)  # ip -> [timestamps]


def _take_quota(ip):
    now = time.time()
    day_ago = now - 86400
    recent = [t for t in _usage[ip] if t > day_ago]
    _usage[ip] = recent
    if len(recent) >= FREE_CHECKS_PER_DAY:
        return False
    recent.append(now)
    return True


def _live_check(proxy):
    parsed = _normalize(proxy)
    if not parsed:
        raise HTTPException(400, f"Bad proxy {proxy!r}. Use ip:port or scheme://ip:port")
    target_domain = config.TARGET_EMAIL.split("@")[-1]
    r = check_proxy(parsed, target_domain)
    info = r.get("info") or {}
    return {
        "proxy": f"{r['host']}:{r['port']}",
        "status": "active" if r["active"] else ("open" if r["open"] else "down"),
        "type": r["type"],
        "speed": r["speed"],
        "latency_ms": r["ms"],
        "smtp": {"ok": r["smtp_ok"], "route": r["smtp_route"]},
        "exit": {
            "ip": info.get("query"),
            "country": info.get("country"),
            "isp": info.get("isp"),
            "asn": info.get("as"),
        },
    }


@app.get("/", include_in_schema=False)
def landing():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/check")
async def check(request: Request, proxy: str = Query(..., description="ip:port or scheme://ip:port")):
    ip = request.client.host if request.client else "unknown"
    if not _take_quota(ip):
        raise HTTPException(429, f"Free limit reached ({FREE_CHECKS_PER_DAY} checks/day).")
    return await run_in_threadpool(_live_check, proxy)


@app.get("/api/ready/{kind}", response_class=PlainTextResponse)
def ready(kind: str):
    if kind not in ("fast", "socks5", "http", "smtp"):
        raise HTTPException(404, "kind must be one of: fast, socks5, http, smtp")
    path = os.path.join(config.READY_DIR, f"{kind}.txt")
    if not os.path.exists(path):
        raise HTTPException(404, "No list yet — run a scan first.")
    with open(path) as f:
        return f.read()


@app.get("/api/stats")
def stats():
    if not os.path.exists(config.HEALTHY_JSON_FILE):
        raise HTTPException(404, "No scan results yet.")
    with open(config.HEALTHY_JSON_FILE) as f:
        healthy = json.load(f)
    countries = defaultdict(int)
    smtp_ok = 0
    for p in healthy:
        c = p.get("country") or "?"
        countries[c] += 1
        smtp_ok += bool(p.get("smtp_ok"))
    return {
        "healthy_total": len(healthy),
        "smtp_capable": smtp_ok,
        "by_country": dict(sorted(countries.items(), key=lambda kv: -kv[1])),
    }
