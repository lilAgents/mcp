// Shared network layer for the lilAgents MCP tools.
// Every outbound fetch is SSRF-guarded, redirect-manual, and time-boxed, ported
// verbatim from the lilAgents tool fleet (stack-fetch.mjs) so behavior matches
// the live tools at lilagents.com.

export const UA =
  'Mozilla/5.0 (compatible; lilAgents-MCP/1.0; +https://lilagents.com/mcp)';
export const MAX_HOPS = 5;
export const TIMEOUT_MS = 9000;
export const MAX_BYTES = 700000;

// Block localhost, link-local, and private/CGNAT ranges so a tool can never be
// pointed at an internal address. Hostname-pattern guard, matching the fleet.
export function isBlockedHost(hostname) {
  const h = (hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 0 || a === 127 || a === 10) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  return false;
}

export function normalizeUrl(raw) {
  const s = String(raw || '').trim();
  if (!s) throw new Error('Enter a URL.');
  const start = /^https?:\/\//i.test(s) ? s : 'https://' + s;
  let u;
  try { u = new URL(start); } catch { throw new Error('That does not look like a valid URL.'); }
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http and https URLs can be fetched.');
  if (isBlockedHost(u.hostname)) throw new Error('For safety, local and private addresses cannot be fetched.');
  return u;
}

// Fetch following redirects manually, guarding each hop, with a total timeout.
// Returns { finalUrl, status, headers (plain object), response, hops }.
export async function safeFetch(rawUrl, opts = {}) {
  const { method = 'GET', accept = 'text/html,application/xhtml+xml,*/*;q=0.8', timeoutMs = TIMEOUT_MS, maxHops = MAX_HOPS } = opts;
  let current = normalizeUrl(rawUrl).toString();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const hops = [];
  try {
    for (let i = 0; i < maxHops; i++) {
      const host = new URL(current).hostname;
      if (isBlockedHost(host)) throw new Error('For safety, local and private addresses cannot be fetched.');
      let r;
      try {
        r = await fetch(current, {
          method,
          redirect: 'manual',
          signal: controller.signal,
          headers: { 'user-agent': UA, accept },
        });
      } catch (e) {
        if (e && e.name === 'AbortError') throw new Error('The request timed out.');
        throw new Error('Could not reach that URL.');
      }
      const loc = r.headers.get('location');
      hops.push({ url: current, status: r.status, location: loc || null });
      if (r.status >= 300 && r.status < 400 && loc) {
        try { current = new URL(loc, current).toString(); } catch { current = loc; }
        continue;
      }
      const headers = {};
      r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
      return { finalUrl: current, status: r.status, headers, response: r, hops };
    }
    throw new Error('Too many redirects.');
  } finally {
    clearTimeout(timer);
  }
}

export async function readBody(response) {
  try { return (await response.text()).slice(0, MAX_BYTES); } catch { return ''; }
}

// DNS-over-HTTPS (Cloudflare) so DNS lookups need no local resolver.
const RR = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT', 28: 'AAAA', 257: 'CAA' };
export async function doh(name, type) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 7000);
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
      { headers: { accept: 'application/dns-json' }, signal: ac.signal }
    );
    if (!r.ok) return [];
    const d = await r.json();
    return (d.Answer || []).map((a) => ({ type: RR[a.type] || String(a.type), value: a.data, ttl: a.TTL }));
  } catch {
    return [];
  } finally {
    clearTimeout(t);
  }
}
