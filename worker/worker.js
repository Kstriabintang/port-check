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
const BULK_MAX_PAID = 200;         // per bulk request with a valid API key
const KEY_PREFIX = "key:";         // KV entries: key:<token> -> {"tier": "supporter"|"reseller"}

// Return the caller's tier if X-API-Key matches a KV entry, else null.
async function apiKeyTier(env, request) {
  const key = request.headers.get("x-api-key");
  if (!key || !env.QUOTA) return null;
  try {
    const v = await env.QUOTA.get(KEY_PREFIX + key);
    return v ? (JSON.parse(v).tier || "supporter") : null;
  } catch {
    return null;
  }
}

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

// After a proxy tunnel is established, fetch ip-api through it to learn the
// exit IP + country. Returns {country, exit_ip} or null.
async function _exitInfo(writer, reader) {
  try {
    await writer.write(new TextEncoder().encode(
      "GET /json?fields=status,country,countryCode,query HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n"
    ));
    let buf = new Uint8Array(0);
    const deadline = Date.now() + 6000;
    while (Date.now() < deadline && buf.length < 8192) {
      const chunk = await withTimeout(reader.read(), 5000, () => null);
      if (!chunk || !chunk.value) break;
      const merged = new Uint8Array(buf.length + chunk.value.length);
      merged.set(buf); merged.set(chunk.value, buf.length);
      buf = merged;
      const txt = new TextDecoder().decode(buf);
      const idx = txt.indexOf("\r\n\r\n");
      if (idx !== -1) {
        try {
          const j = JSON.parse(txt.slice(idx + 4).trim());
          if (j && j.status === "success") return { country: j.country, exit_ip: j.query };
          return null;
        } catch { /* body incomplete — keep reading */ }
      }
    }
  } catch {}
  return null;
}

async function trySocks5(socket, host, port) {
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  try {
    // greeting: version 5, 1 method, no-auth
    await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
    const hello = await withTimeout(reader.read(), 5000, () => null);
    if (!hello || !hello.value || hello.value[0] !== 0x05 || hello.value[1] === 0xff) return null;

    // CONNECT host:port (domain form)
    const h = new TextEncoder().encode(host);
    const req = new Uint8Array(7 + h.length);
    req.set([0x05, 0x01, 0x00, 0x03, h.length], 0);
    req.set(h, 5);
    req[5 + h.length] = port >> 8;
    req[6 + h.length] = port & 0xff;
    await writer.write(req);
    const resp = await withTimeout(reader.read(), 8000, () => null);
    if (!(resp && resp.value && resp.value[1] === 0x00)) return null;
    return (await _exitInfo(writer, reader)) || {};
  } catch {
    return null;
  }
}

async function trySocks4(socket, host, port) {
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  try {
    // SOCKS4a CONNECT: VN=4, CD=1, port, IP=0.0.0.1, empty user, domain
    const h = new TextEncoder().encode(host);
    const req = new Uint8Array(10 + h.length);
    req.set([0x04, 0x01, port >> 8, port & 0xff, 0, 0, 0, 1, 0], 0);
    req.set(h, 9);
    req[9 + h.length] = 0;
    await writer.write(req);
    const resp = await withTimeout(reader.read(), 8000, () => null);
    if (!(resp && resp.value && resp.value.length >= 8 && resp.value[1] === 0x5a)) return null;
    return (await _exitInfo(writer, reader)) || {};
  } catch {
    return null;
  }
}

async function tryHttpConnect(socket, host, port) {
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  try {
    await writer.write(new TextEncoder().encode(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
    const resp = await withTimeout(reader.read(), 8000, () => null);
    if (!resp || !resp.value) return null;
    const head = new TextDecoder().decode(resp.value);
    if (!/^HTTP\/1\.[01] 200/.test(head)) return null;
    return (await _exitInfo(writer, reader)) || {};
  } catch {
    return null;
  }
}

// Port-based service guess for open ports that turn out not to be proxies.
const SERVICE_BY_PORT = {
  21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http-web", 110: "pop3",
  143: "imap", 443: "https-web", 465: "smtps", 587: "smtp-submit", 993: "imaps",
  995: "pop3s", 3128: "squid", 3306: "mysql", 5432: "postgres", 6379: "redis",
  8000: "http-alt", 8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
  1080: "socks?", 1433: "mssql", 3389: "rdp", 27017: "mongodb",
};

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
  try { socket.close(); } catch {}

  // Probe every protocol (like the Python scanner does), not just the hinted
  // scheme — a bare "ip:port" could be SOCKS5, SOCKS4, or HTTP CONNECT.
  const target = { host: "ip-api.com", port: 80 };
  const probes = [
    ["SOCKS5", trySocks5],
    ["HTTP", tryHttpConnect],
    ["SOCKS4", trySocks4],
  ];
  // If the user hinted a scheme, try that one first.
  if (p.scheme.startsWith("socks4")) probes.sort((a) => (a[0] === "SOCKS4" ? -1 : 1));
  else if (p.scheme.startsWith("http")) probes.sort((a) => (a[0] === "HTTP" ? -1 : 1));

  for (const [type, probe] of probes) {
    let s;
    try {
      s = connect({ hostname: p.host, port: p.port });
      await withTimeout(s.opened, 8000, () => { throw new Error("timeout"); });
    } catch {
      continue;
    }
    const geo = await probe(s, target.host, target.port);
    try { s.close(); } catch {}
    if (geo) {
      out.type = type;
      out.status = "active";
      if (geo.country) { out.country = geo.country; out.exit_ip = geo.exit_ip; }
      break;
    }
    out.status = "open";
  }
  if (out.status === "open") out.service = SERVICE_BY_PORT[p.port] || "tcp";
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
// Valid X-API-Key: unlimited quota + larger batches.
async function bulkCheck(request, env) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const tier = await apiKeyTier(env, request);
  const bulkMax = tier ? BULK_MAX_PAID : BULK_MAX;
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
    if (parsed.length >= bulkMax) break;
  }
  if (!parsed.length) return json({ error: "No valid proxies in request body" }, 400);
  if (!tier && !(await takeQuota(env, ip, parsed.length))) {
    return json({ error: `Free limit reached (${FREE_CHECKS_PER_DAY} checks/day)` }, 429);
  }
  const results = await Promise.all(parsed.map(checkOne));
  const rank = { active: 0, open: 1, down: 2 };
  results.sort((a, b) => (rank[a.status] - rank[b.status]) || ((a.latency_ms ?? 1e9) - (b.latency_ms ?? 1e9)));
  return json({ checked: results.length, invalid, tier: tier || "free", results });
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
      const tier = await apiKeyTier(env, request);
      if (!tier) {
        const ip = request.headers.get("cf-connecting-ip") || "unknown";
        if (!(await takeQuota(env, ip))) {
          return json({ error: `Free limit reached (${FREE_CHECKS_PER_DAY} checks/day)` }, 429);
        }
      }
      return liveCheck(url.searchParams.get("proxy"));
    }
    if (url.pathname === "/api/check-bulk" && request.method === "POST") {
      return bulkCheck(request, env);
    }
    if (url.pathname === "/api/stats") return stats();

    if (url.pathname.startsWith("/api/")) {
      return json({ error: "Unknown endpoint. See / for available routes." }, 404);
    }

    // everything else -> static assets (landing page)
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response("PortCheck Worker OK", { headers: { "content-type": "text/plain" } });
  },
};
