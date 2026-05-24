"use strict";
const { httpRequest, parseJSON } = require("./http");
const dns = require("dns").promises;

// ─────────────────────────────────────────────────────────────────────────────
// Shodan — IP host info
// GET /shodan/host/{ip}?key=...
// ─────────────────────────────────────────────────────────────────────────────
async function shodanHost(ip, apiKey) {
  if (!apiKey) return { ok: false, error: "Shodan API key no configurada" };
  try {
    const r = await httpRequest(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${apiKey}`, { timeout: 15000 });
    if (r.status === 401) return { ok: false, error: "Shodan API key inválida" };
    if (r.status === 404) return { ok: false, error: "Host no encontrado en Shodan" };
    if (r.status !== 200) return { ok: false, error: `Shodan HTTP ${r.status}` };
    const d = parseJSON(r.data);
    return {
      ok: true,
      ip:           d.ip_str,
      org:          d.org,
      isp:          d.isp,
      country:      d.country_name,
      country_code: d.country_code,
      city:         d.city,
      region:       d.region_code,
      os:           d.os,
      ports:        d.ports || [],
      hostnames:    d.hostnames || [],
      domains:      d.domains || [],
      tags:         d.tags || [],
      vulns:        Object.keys(d.vulns || {}),
      services: (d.data || []).slice(0, 20).map(s => ({
        port:      s.port,
        transport: s.transport,
        product:   s.product,
        version:   s.version,
        banner:    (s.banner || "").slice(0, 200),
        http_title: s.http?.title,
        cpe:       s.cpe ? (Array.isArray(s.cpe) ? s.cpe[0] : s.cpe) : null,
      })),
      last_update: d.last_update,
      asn:         d.asn,
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shodan — DNS resolve (domain → IPs)
// GET /dns/resolve?hostnames=...&key=...
// ─────────────────────────────────────────────────────────────────────────────
async function shodanDnsResolve(hostnames, apiKey) {
  if (!apiKey) return { ok: false, error: "Shodan API key no configurada" };
  const qs = encodeURIComponent(Array.isArray(hostnames) ? hostnames.join(",") : hostnames);
  try {
    const r = await httpRequest(`https://api.shodan.io/dns/resolve?hostnames=${qs}&key=${apiKey}`, { timeout: 10000 });
    if (r.status !== 200) return { ok: false, error: `Shodan HTTP ${r.status}` };
    return { ok: true, data: parseJSON(r.data) || {} };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shodan — DNS reverse (IP → hostnames)
// GET /dns/reverse?ips=...&key=...
// ─────────────────────────────────────────────────────────────────────────────
async function shodanDnsReverse(ips, apiKey) {
  if (!apiKey) return { ok: false, error: "Shodan API key no configurada" };
  const qs = encodeURIComponent(Array.isArray(ips) ? ips.join(",") : ips);
  try {
    const r = await httpRequest(`https://api.shodan.io/dns/reverse?ips=${qs}&key=${apiKey}`, { timeout: 10000 });
    if (r.status !== 200) return { ok: false, error: `Shodan HTTP ${r.status}` };
    return { ok: true, data: parseJSON(r.data) || {} };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shodan — Account info (validate key + check credits)
// ─────────────────────────────────────────────────────────────────────────────
async function shodanAccountInfo(apiKey) {
  if (!apiKey) return { ok: false, error: "No configurada" };
  try {
    const r = await httpRequest(`https://api.shodan.io/api-info?key=${apiKey}`, { timeout: 10000 });
    if (r.status === 401) return { ok: false, error: "API key inválida" };
    if (r.status !== 200) return { ok: false, error: `HTTP ${r.status}` };
    const d = parseJSON(r.data);
    return { ok: true, plan: d.plan, query_credits: d.query_credits, scan_credits: d.scan_credits, unlocked: d.unlocked };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// RDAP — Domain registration info (free, no key needed)
// ─────────────────────────────────────────────────────────────────────────────
async function rdapDomain(domain) {
  try {
    const r = await httpRequest(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { timeout: 12000 });
    if (r.status !== 200) return { ok: false, error: `RDAP HTTP ${r.status}` };
    const d = parseJSON(r.data);
    if (!d) return { ok: false, error: "Respuesta inválida" };

    const getEventDate = (action) => d.events?.find(e => e.eventAction === action)?.eventDate || null;
    const registrant  = d.entities?.find(e => e.roles?.includes("registrant"));
    const registrar   = d.entities?.find(e => e.roles?.includes("registrar"));
    const getName     = (ent) => {
      if (!ent) return null;
      return ent.vcardArray?.[1]?.find(v => v[0] === "fn")?.[3] || ent.handle || null;
    };
    const getOrg = (ent) => {
      if (!ent) return null;
      return ent.vcardArray?.[1]?.find(v => v[0] === "org")?.[3] || null;
    };
    const getEmail = (ent) => {
      if (!ent) return null;
      return ent.vcardArray?.[1]?.find(v => v[0] === "email")?.[3] || null;
    };

    const registered = getEventDate("registration");
    const expires    = getEventDate("expiration");
    const updated    = getEventDate("last changed");
    const ageDays    = registered ? Math.floor((Date.now() - new Date(registered).getTime()) / 86400000) : null;

    return {
      ok: true,
      domain:         d.ldhName || domain,
      status:         d.status || [],
      registered,
      expires,
      updated,
      age_days:       ageDays,
      registrant:     getName(registrant),
      registrant_org: getOrg(registrant),
      registrant_email: getEmail(registrant),
      registrar:      getName(registrar) || registrar?.handle,
      nameservers:    (d.nameservers || []).map(n => n.ldhName).filter(Boolean),
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// crt.sh — Certificate transparency (subdomain enumeration, free)
// ─────────────────────────────────────────────────────────────────────────────
async function crtshSubdomains(domain) {
  try {
    const r = await httpRequest(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { headers: { "Accept": "application/json" }, timeout: 20000 }
    );
    if (r.status !== 200) return { ok: false, error: `crt.sh HTTP ${r.status}` };
    const entries = parseJSON(r.data);
    if (!Array.isArray(entries)) return { ok: false, error: "Sin datos" };

    // Dedup and filter
    const subs = new Set();
    for (const e of entries) {
      const names = (e.name_value || "").split("\n");
      for (const n of names) {
        const cleaned = n.trim().toLowerCase().replace(/^\*\./, "");
        if (cleaned && cleaned.endsWith(domain.toLowerCase())) subs.add(cleaned);
      }
    }
    // Sort: apex first, then alphabetical
    const sorted = [...subs].sort((a, b) => {
      if (a === domain) return -1;
      if (b === domain) return 1;
      return a.localeCompare(b);
    });

    return { ok: true, subdomains: sorted.slice(0, 200), total: subs.size };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS — Live lookup (A, MX, NS, TXT) using Node.js dns module
// ─────────────────────────────────────────────────────────────────────────────
async function dnsLookup(domain) {
  const result = {};

  await Promise.allSettled([
    dns.resolve4(domain).then(r  => { result.a  = r; }).catch(() => {}),
    dns.resolve6(domain).then(r  => { result.aaaa = r; }).catch(() => {}),
    dns.resolveMx(domain).then(r => { result.mx = r.sort((a,b) => a.priority - b.priority); }).catch(() => {}),
    dns.resolveNs(domain).then(r => { result.ns = r; }).catch(() => {}),
    dns.resolveTxt(domain).then(r => { result.txt = r.map(a => a.join(" ")); }).catch(() => {}),
    dns.resolveCname(domain).then(r => { result.cname = r; }).catch(() => {}),
  ]);

  return { ok: true, ...result };
}

// ─────────────────────────────────────────────────────────────────────────────
// Main query dispatcher
// target: IP address or domain/hostname
// ─────────────────────────────────────────────────────────────────────────────
const IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

async function queryTarget(target, apiKeys = {}) {
  const isIP   = IP_RE.test(target.trim());
  const domain = target.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];

  if (isIP) {
    // IP query: Shodan host info + reverse DNS
    const [shodanResult, reverseResult] = await Promise.allSettled([
      shodanHost(target.trim(), apiKeys.shodan),
      shodanDnsReverse(target.trim(), apiKeys.shodan),
    ]);
    return {
      type:    "ip",
      target:  target.trim(),
      shodan:  shodanResult.status === "fulfilled" ? shodanResult.value : { ok: false, error: shodanResult.reason?.message },
      reverse: reverseResult.status === "fulfilled" ? reverseResult.value : { ok: false, error: reverseResult.reason?.message },
    };
  } else {
    // Domain query: RDAP + crt.sh + DNS + Shodan DNS resolve
    const [rdapResult, crtResult, dnsResult, resolveResult] = await Promise.allSettled([
      rdapDomain(domain),
      crtshSubdomains(domain),
      dnsLookup(domain),
      apiKeys.shodan ? shodanDnsResolve(domain, apiKeys.shodan) : Promise.resolve({ ok: false, error: "Shodan no configurado" }),
    ]);

    const resolved = resolveResult.status === "fulfilled" ? resolveResult.value : null;
    // If Shodan resolved an IP, also fetch host info
    let hostResults = [];
    if (resolved?.ok && resolved.data?.[domain]) {
      const ip = resolved.data[domain];
      const hostR = await shodanHost(ip, apiKeys.shodan).catch(e => ({ ok: false, error: e.message }));
      if (hostR.ok) hostResults.push(hostR);
    }
    // Also try from DNS A records if we got them and Shodan isn't configured
    if (hostResults.length === 0 && dnsResult.status === "fulfilled" && dnsResult.value?.a?.length > 0 && apiKeys.shodan) {
      const firstIP = dnsResult.value.a[0];
      const hostR = await shodanHost(firstIP, apiKeys.shodan).catch(e => ({ ok: false, error: e.message }));
      if (hostR.ok) hostResults.push(hostR);
    }

    return {
      type:    "domain",
      target:  domain,
      rdap:    rdapResult.status === "fulfilled"   ? rdapResult.value   : { ok: false, error: rdapResult.reason?.message },
      crt:     crtResult.status === "fulfilled"    ? crtResult.value    : { ok: false, error: crtResult.reason?.message },
      dns:     dnsResult.status === "fulfilled"    ? dnsResult.value    : { ok: false, error: dnsResult.reason?.message },
      resolve: resolved,
      hosts:   hostResults,
    };
  }
}

module.exports = { queryTarget, shodanHost, shodanDnsResolve, shodanDnsReverse, shodanAccountInfo, rdapDomain, crtshSubdomains, dnsLookup };
