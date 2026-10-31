// PortCheck Worker — free-tier Cloudflare version of api.py.
//
// Routes:
//   GET /                    landing page (served from static assets)
//   GET /api/check?proxy=..  live check via raw TCP (cloudflare:sockets)
//   GET /api/ready/:kind     proxy lists from the GitHub repo (cached 10 min)
//   GET /api/stats           rollup of the latest scan (cached 10 min)
//
// Note: Workers block outbound port 25, so SMTP/MX-25 live tests are not
// possible here. SMTP data still comes from the scheduled GitHub Actions scan.

import { connect } from "cloudflare:sockets";

const REPO_RAW = "https://raw.githubusercontent.com/Kstriabintang/port-check/main";
const FREE_CHECKS_PER_DAY = 100;
const BULK_MAX = 25;               // max proxies per bulk request (free tier)

const JSON_HEADERS = { "content-type": "application/json" };
const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...SECURITY_HEADERS },
  });
}

function parseProxy(text) {
  let t = (text || "").trim();
  let scheme = "socks5";
  if (t.includes("://")) [scheme, t] = t.split("://", 2);
  t = t.split("@").pop().replace(/\/+$/, "");
  const i = t.lastIndexOf(":");
  if (i < 1) return null;
  const host = t.slice(0, i);
  const port = parseInt(t.slice(i + 1), 10);
  if (!host || !port || port < 1 || port > 65535) return null;
  if (!/^[a-zA-Z0-9.\-]+$/.test(host)) return null;   // block weird targets
  return { scheme: scheme.toLowerCase(), host, port };
}

function withTimeout(promise, ms, onTimeout) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms)),
  ]).catch((e) => onTimeout(e));
}

// ---- Live check via raw TCP ---------------------------------------------
// Workers can open raw TCP sockets (except port 25). We measure connect
// latency, then identify the proxy type with a minimal handshake.

async function trySocks5(socket, host, port) {
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  try {
    // greeting: version 5, 1 method, no-auth
    await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
    const hello = await withTimeout(reader.read(), 5000, () => null);
    if (!hello || !hello.value || hello.value[0] !== 0x05 || hello.value[1] === 0xff) return false;

    // CONNECT host:port (domain form)
    const h = new TextEncoder().encode(host);
    const req = new Uint8Array(7 + h.length);
    req.set([0x05, 0x01, 0x00, 0x03, h.length], 0);
    req.set(h, 5);
    req[5 + h.length] = port >> 8;
    req[6 + h.length] = port & 0xff;
    await writer.write(req);
    const resp = await withTimeout(reader.read(), 8000, () => null);
    return !!(resp && resp.value && resp.value[1] === 0x00);
  } catch {
    return false;
  }
}

async function tryHttpConnect(socket, host, port) {
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  try {
    await writer.write(new TextEncoder().encode(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
    const resp = await withTimeout(reader.read(), 8000, () => null);
    if (!resp || !resp.value) return false;
    const head = new TextDecoder().decode(resp.value);
    return /^HTTP\/1\.[01] 200/.test(head);
  } catch {
    return false;
  }
}

async function checkOne(p) {
  const out = { proxy: `${p.host}:${p.port}`, status: "down", type: "-", latency_ms: null };
  const started = Date.now();
  let socket;
  try {
    socket = connect({ hostname: p.host, port: p.port });
    await withTimeout(socket.opened, 8000, () => { throw new Error("timeout"); });
  } catch {
    return out;
  }
  out.latency_ms = Date.now() - started;

  const target = { host: "ip-api.com", port: 80 };
  let ok = false, type = "-";
  if (p.scheme.startsWith("socks")) {
    ok = await trySocks5(socket, target.host, target.port);
    type = "SOCKS5";
  } else {
    ok = await tryHttpConnect(socket, target.host, target.port);
    type = "HTTP";
  }
  try { socket.close(); } catch {}

  out.type = ok ? type : "?";
  out.status = ok ? "active" : "open";
  out.speed = out.latency_ms <= 1000 ? "FAST" : out.latency_ms <= 3000 ? "MEDIUM" : out.latency_ms <= 6000 ? "SLOW" : "BAD";
  return out;
}

async function liveCheck(proxyParam) {
  const p = parseProxy(proxyParam);
  if (!p) return json({ error: "Bad proxy. Use ip:port or scheme://ip:port" }, 400);
  if (p.port === 25) return json({ error: "Port 25 egress is blocked on Cloudflare Workers" }, 400);
  const out = await checkOne(p);
  out.note = "SMTP live test not available on Workers (port 25 blocked). See /api/stats for scanned SMTP data.";
  return json(out);
}

// POST /api/check-bulk  body: raw text (one proxy per line) or {"proxies": [...]}
// Checks up to BULK_MAX proxies in parallel; each proxy counts as 1 quota.
async function bulkCheck(request, env) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  let lines = [];
  const ct = request.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    const body = await request.json().catch(() => null);
    if (body && Array.isArray(body.proxies)) lines = body.proxies;
  } else {
    lines = (await request.text()).split(/\r?\n/);
  }
  const parsed = [], invalid = [];
  for (const line of lines) {
    const t = (line || "").trim();
    if (!t || t.startsWith("#")) continue;
    const p = parseProxy(t);
    if (p) {
      if (p.port === 25) invalid.push(t + " (port 25 blocked)");
      else if (!parsed.some((x) => x.host === p.host && x.port === p.port)) parsed.push(p);
    } else invalid.push(t);
    if (parsed.length >= BULK_MAX) break;
  }
  if (!parsed.length) return json({ error: "No valid proxies in request body" }, 400);
  if (!(await takeQuota(env, ip, parsed.length))) {
    return json({ error: `Free limit reached (${FREE_CHECKS_PER_DAY} checks/day)` }, 429);
  }
  const results = await Promise.all(parsed.map(checkOne));
  results.sort((a, b) => (a.latency_ms ?? 1e9) - (b.latency_ms ?? 1e9));
  return json({ checked: results.length, invalid, results });
}

// ---- Rate limit (KV if bound; otherwise allow) ---------------------------

async function takeQuota(env, ip, n = 1) {
  if (!env.QUOTA) return true;
  const key = `q:${ip}:${new Date().toISOString().slice(0, 10)}`;
  const used = parseInt((await env.QUOTA.get(key)) || "0", 10);
  if (used + n > FREE_CHECKS_PER_DAY) return false;
  await env.QUOTA.put(key, String(used + n), { expirationTtl: 90000 });
  return true;
}

// ---- Data endpoint (from the scheduled scan in the repo) -----------------

async function proxyFetch(path) {
  const url = `${REPO_RAW}/${path}`;
  const r = await fetch(url, {
    cf: { cacheTtlByStatus: { "200-299": 600 }, cacheEverything: true },
  });
  if (!r.ok) {
    // never keep a cached failure (e.g. 404 before the first scan ran)
    try { await caches.default.delete(new Request(url)); } catch {}
  }
  return r;
}

async function stats() {
  const r = await proxyFetch("results/healthy_proxies.json");
  if (!r.ok) return json({ error: `No scan results yet (upstream HTTP ${r.status})` }, 404);
  const healthy = await r.json();
  const byCountry = {};
  let smtp = 0;
  for (const p of healthy) {
    byCountry[p.country || "?"] = (byCountry[p.country || "?"] || 0) + 1;
    if (p.smtp_ok) smtp++;
  }
  return json({
    healthy_total: healthy.length,
    smtp_capable: smtp,
    by_country: Object.fromEntries(Object.entries(byCountry).sort((a, b) => b[1] - a[1])),
  });
}

// ---- Router ---------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/check") {
      const ip = request.headers.get("cf-connecting-ip") || "unknown";
      if (!(await takeQuota(env, ip))) {
        return json({ error: `Free limit reached (${FREE_CHECKS_PER_DAY} checks/day)` }, 429);
      }
      return liveCheck(url.searchParams.get("proxy"));
    }
    if (url.pathname === "/api/check-bulk" && request.method === "POST") {
      return bulkCheck(request, env);
    }
    if (url.pathname === "/api/stats") return stats();

    // everything else -> static assets (landing page)
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response("PortCheck Worker OK", { headers: { "content-type": "text/plain" } });
  },
};
