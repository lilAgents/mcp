// The lilAgents MCP tool set. Each tool returns a compact object with a one-line
// `summary` plus structured fields. `stack_detect` proxies the canonical
// lilagents.com service so it stays in exact parity with the live lilStack tool;
// the rest run self-contained over the shared SSRF-guarded fetch layer.

import { z } from 'zod';
import { safeFetch, readBody, normalizeUrl, doh } from './lib/net.js';

const STACK_ENDPOINT = 'https://lilagents.com/.netlify/functions/stack-fetch';

function hostOf(domain) {
  return String(domain || '').trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/^www\./i, '');
}

/* ---------- robots parsing ---------- */
function parseRobots(txt) {
  const groups = [];
  let cur = null;
  let sawRule = false;
  for (const line of String(txt).split(/\r?\n/)) {
    const s = line.replace(/#.*$/, '').trim();
    if (!s) continue;
    const i = s.indexOf(':');
    if (i < 0) continue;
    const field = s.slice(0, i).trim().toLowerCase();
    const val = s.slice(i + 1).trim();
    if (field === 'user-agent') {
      if (cur && sawRule) cur = null;
      if (!cur) { cur = { agents: [], rules: [] }; groups.push(cur); sawRule = false; }
      cur.agents.push(val.toLowerCase());
    } else if (field === 'disallow' || field === 'allow') {
      if (!cur) { cur = { agents: ['*'], rules: [] }; groups.push(cur); }
      cur.rules.push({ type: field, path: val });
      sawRule = true;
    }
  }
  return groups;
}
function isAllowed(groups, uaLower, path = '/') {
  let g = groups.find((gr) => gr.agents.includes(uaLower));
  if (!g) g = groups.find((gr) => gr.agents.includes('*'));
  if (!g) return true;
  let allow = true;
  let best = -1;
  for (const r of g.rules) {
    if (!r.path) continue; // empty Disallow means allow all
    if (path.startsWith(r.path)) {
      if (r.path.length > best || (r.path.length === best && r.type === 'allow')) {
        best = r.path.length;
        allow = r.type === 'allow';
      }
    }
  }
  return allow;
}

const AI_BOTS = [
  { ua: 'GPTBot', name: 'GPTBot', operator: 'OpenAI, trains and powers ChatGPT browsing' },
  { ua: 'OAI-SearchBot', name: 'OAI-SearchBot', operator: 'OpenAI, ChatGPT search' },
  { ua: 'ClaudeBot', name: 'ClaudeBot', operator: 'Anthropic, Claude' },
  { ua: 'PerplexityBot', name: 'PerplexityBot', operator: 'Perplexity answers engine' },
  { ua: 'Google-Extended', name: 'Google-Extended', operator: 'Google, Gemini and AI Overviews' },
  { ua: 'CCBot', name: 'CCBot', operator: 'Common Crawl, feeds many AI datasets' },
  { ua: 'Bytespider', name: 'Bytespider', operator: 'ByteDance and TikTok' },
  { ua: 'Applebot-Extended', name: 'Applebot-Extended', operator: 'Apple Intelligence' },
];

const SEC_HEADERS = [
  { key: 'strict-transport-security', label: 'HSTS' },
  { key: 'content-security-policy', label: 'Content-Security-Policy' },
  { key: 'x-frame-options', label: 'X-Frame-Options' },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options' },
  { key: 'referrer-policy', label: 'Referrer-Policy' },
  { key: 'permissions-policy', label: 'Permissions-Policy' },
];

export const TOOLS = [
  {
    name: 'stack_detect',
    title: 'Detect a site tech stack',
    description:
      'Fingerprint the CMS, framework, hosting, backend, marketing tech, and AI website builder behind any URL, plus its domain registration (RDAP) and Ahrefs Domain Rating. Proxies the canonical lilAgents lilStack service.',
    input: { url: z.string().describe('The site URL or domain, e.g. stripe.com or https://stripe.com/') },
    async run({ url }) {
      const target = normalizeUrl(url).toString();
      const r = await fetch(`${STACK_ENDPOINT}?url=${encodeURIComponent(target)}`, { headers: { accept: 'application/json' } });
      if (!r.ok) throw new Error(`Stack service returned HTTP ${r.status}.`);
      const d = await r.json();
      if (d.error) throw new Error(d.error);
      const names = (d.detections || []).map((x) => x.name);
      return {
        url: d.url,
        detections: d.detections || [],
        domain: d.domain || null,
        domain_rating: d.dr || null,
        summary: names.length ? `${d.url} looks built with ${names.join(', ')}.` : `No common fingerprints found for ${d.url}.`,
      };
    },
  },
  {
    name: 'trace_redirects',
    title: 'Trace the redirect chain',
    description: 'Follow every redirect hop a URL takes and report each status code and Location, so you can spot broken or sneaky redirect chains.',
    input: { url: z.string().describe('The URL to trace, e.g. bit.ly/xyz or http://example.com') },
    async run({ url }) {
      const start = normalizeUrl(url).toString();
      const res = await safeFetch(url, { maxHops: 10 });
      return {
        start,
        final_url: res.finalUrl,
        final_status: res.status,
        hops: res.hops.length,
        chain: res.hops,
        summary: `${res.hops.length} hop${res.hops.length === 1 ? '' : 's'} from ${start} to ${res.finalUrl} (HTTP ${res.status}).`,
      };
    },
  },
  {
    name: 'dns_snapshot',
    title: 'Snapshot DNS records',
    description: 'Pull a full DNS snapshot for a domain (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA) via DNS-over-HTTPS. Useful for migrations, deliverability, and handoffs.',
    input: { domain: z.string().describe('The domain, e.g. example.com') },
    async run({ domain }) {
      const host = hostOf(domain);
      if (!host) throw new Error('Enter a domain, e.g. example.com.');
      const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA'];
      const records = {};
      const unresolved = [];
      let nxdomain = false;
      await Promise.all(types.map(async (t) => {
        const res = await doh(host, t);
        records[t] = res.records;
        if (!res.ok) unresolved.push(t);
        if (res.status === 'NXDOMAIN') nxdomain = true;
      }));
      const present = types.filter((t) => records[t].length);
      // resolved:false means the lookups failed, which is NOT the same as the
      // domain genuinely having no records. Say which, so the agent never reads
      // a resolver hiccup as an empty result.
      const resolved = unresolved.length === 0;
      let summary;
      if (!resolved) {
        summary = `${host}: DNS lookup failed for ${unresolved.join(', ')} (could not resolve, not necessarily empty).`;
      } else if (nxdomain && !present.length) {
        summary = `${host}: domain does not exist (NXDOMAIN).`;
      } else {
        summary = `${host}: ${present.map((t) => `${records[t].length} ${t}`).join(', ') || 'resolved with no records'}.`;
      }
      return { domain: host, resolved, unresolved, records, summary };
    },
  },
  {
    name: 'check_headers',
    title: 'Audit security headers',
    description: 'Fetch a URL and report which baseline security headers are present or missing (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).',
    input: { url: z.string().describe('The URL to audit, e.g. example.com') },
    async run({ url }) {
      const res = await safeFetch(url);
      const headers = SEC_HEADERS.map((h) => ({ header: h.label, present: res.headers[h.key] != null, value: res.headers[h.key] || null }));
      const missing = headers.filter((h) => !h.present).map((h) => h.header);
      return {
        url: res.finalUrl,
        status: res.status,
        headers,
        missing,
        summary: missing.length ? `${res.finalUrl} is missing ${missing.length} of ${SEC_HEADERS.length} baseline headers: ${missing.join(', ')}.` : `${res.finalUrl} sets all ${SEC_HEADERS.length} baseline security headers.`,
      };
    },
  },
  {
    name: 'check_robots',
    title: 'Check robots.txt and AI crawlers',
    description: 'Read a site robots.txt and report which major AI crawlers (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, CCBot, Bytespider, Applebot-Extended, OAI-SearchBot) are allowed or blocked, plus whether an llms.txt exists.',
    input: { url: z.string().describe('The site URL or domain, e.g. example.com') },
    async run({ url }) {
      const origin = normalizeUrl(url).origin;
      const res = await safeFetch(origin + '/robots.txt', { accept: 'text/plain, */*' });
      const found = res.status < 400;
      const txt = found ? await readBody(res.response) : '';
      const groups = parseRobots(txt);
      const crawlers = AI_BOTS.map((b) => ({ name: b.name, operator: b.operator, allowed: isAllowed(groups, b.ua.toLowerCase()) }));
      // true = present, false = checked and absent, null = could not check.
      let llms = false;
      try { const l = await safeFetch(origin + '/llms.txt', { accept: 'text/plain, */*' }); llms = l.status < 400; } catch { llms = null; }
      const blocked = crawlers.filter((c) => !c.allowed).map((c) => c.name);
      const llmsLabel = llms === null ? 'unknown' : llms ? 'present' : 'absent';
      return {
        url: origin,
        robots_txt_found: found,
        ai_crawlers: crawlers,
        llms_txt: llms,
        summary: `${origin}: ${blocked.length ? 'blocks ' + blocked.join(', ') : 'allows all major AI crawlers'}; llms.txt ${llmsLabel}.`,
      };
    },
  },
  {
    name: 'check_indexability',
    title: 'Check page indexability',
    description: 'Fetch a page and report whether it is indexable, reading its canonical link, meta robots tag, and X-Robots-Tag header.',
    input: { url: z.string().describe('The page URL, e.g. https://example.com/page') },
    async run({ url }) {
      const res = await safeFetch(url);
      const html = await readBody(res.response);
      const canonicalTag = (html.match(/<link[^>]+rel=["']?canonical["']?[^>]*>/i) || [])[0] || '';
      const canonical = (canonicalTag.match(/href=["']([^"']+)["']/i) || [])[1] || null;
      const metaTag = (html.match(/<meta[^>]+name=["']?robots["']?[^>]*>/i) || [])[0] || '';
      const metaRobots = (metaTag.match(/content=["']([^"']+)["']/i) || [])[1] || null;
      const xRobots = res.headers['x-robots-tag'] || null;
      const signals = `${metaRobots || ''} ${xRobots || ''}`.toLowerCase();
      const indexable = res.status < 400 && !/noindex/.test(signals);
      return {
        url: res.finalUrl,
        status: res.status,
        indexable,
        canonical,
        meta_robots: metaRobots,
        x_robots_tag: xRobots,
        summary: `${res.finalUrl} is ${indexable ? 'indexable' : 'NOT indexable'}${/noindex/.test(signals) ? ' (noindex set)' : ''}.`,
      };
    },
  },
  {
    name: 'validate_schema',
    title: 'Extract and validate JSON-LD',
    description: 'Fetch a page, extract every JSON-LD structured-data block, validate that each parses, and list the schema.org types found.',
    input: { url: z.string().describe('The page URL, e.g. https://example.com/') },
    async run({ url }) {
      const res = await safeFetch(url);
      const html = await readBody(res.response);
      const blocks = [...html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1]);
      const items = [];
      const errors = [];
      for (const b of blocks) {
        try { items.push(JSON.parse(b.trim())); } catch (e) { errors.push(String(e.message || e)); }
      }
      const flat = items.flatMap((j) => (Array.isArray(j) ? j : j && j['@graph'] ? j['@graph'] : [j]));
      const types = [...new Set(flat.map((o) => o && o['@type']).filter(Boolean).flat())];
      return {
        url: res.finalUrl,
        jsonld_blocks: blocks.length,
        valid: items.length,
        invalid: errors.length,
        types,
        errors,
        summary: blocks.length ? `${blocks.length} JSON-LD block${blocks.length === 1 ? '' : 's'} (${errors.length} invalid); types: ${types.join(', ') || 'none'}.` : `No JSON-LD found on ${res.finalUrl}.`,
      };
    },
  },
  {
    name: 'domain_rating',
    title: 'Get Ahrefs Domain Rating',
    description: 'Look up the Ahrefs Domain Rating (0 to 100 backlink-authority score) for a domain. Attribution to Ahrefs is required and returned in the result.',
    input: { domain: z.string().describe('The domain, e.g. example.com') },
    async run({ domain }) {
      const host = hostOf(domain);
      if (!host) throw new Error('Enter a domain, e.g. example.com.');
      const ac = new AbortController();
      const t = setTimeout(() => ac.abort(), 7000);
      try {
        const r = await fetch(`https://api.ahrefs.com/v3/public/domain-rating-free?target=${encodeURIComponent(host)}&output=json`, { headers: { accept: 'application/json' }, signal: ac.signal });
        if (!r.ok) throw new Error(`Ahrefs returned HTTP ${r.status}.`);
        const d = await r.json();
        const v = d && d.domain_rating && d.domain_rating.domain_rating;
        const value = typeof v === 'number' ? Math.round(v * 10) / 10 : null;
        return {
          domain: host,
          domain_rating: value,
          license: (d.domain_rating && d.domain_rating.license) || 'https://ahrefs.com/legal/domain-rating-license',
          attribution: 'Domain Rating by Ahrefs',
          summary: value == null ? `No Domain Rating available for ${host}.` : `${host} has an Ahrefs Domain Rating of ${value} / 100.`,
        };
      } finally {
        clearTimeout(t);
      }
    },
  },
  {
    name: 'dmarc_check',
    title: 'Check DMARC and SPF',
    description: 'Check a domain email authentication: the DMARC record and its policy (none, quarantine, reject) plus the SPF record. Useful for deliverability and spoofing protection.',
    input: { domain: z.string().describe('The domain, e.g. example.com') },
    async run({ domain }) {
      const host = hostOf(domain);
      if (!host) throw new Error('Enter a domain, e.g. example.com.');
      const clean = (v) => String(v).replace(/^"|"$/g, '').replace(/"\s+"/g, '');
      const [dmarcRes, txtRes] = await Promise.all([doh('_dmarc.' + host, 'TXT'), doh(host, 'TXT')]);
      // If either TXT lookup did not actually run, report "could not determine"
      // rather than "no DMARC / no SPF", which would be a false negative.
      if (!dmarcRes.ok || !txtRes.ok) {
        return {
          domain: host,
          resolved: false,
          summary: `${host}: DNS lookup failed, could not determine DMARC or SPF (not necessarily absent).`,
        };
      }
      const dmarc = dmarcRes.records.map((r) => clean(r.value)).find((v) => /v=DMARC1/i.test(v)) || null;
      const spf = txtRes.records.map((r) => clean(r.value)).find((v) => /v=spf1/i.test(v)) || null;
      const policy = dmarc ? ((dmarc.match(/\bp=([a-z]+)/i) || [])[1] || null) : null;
      const parts = [
        dmarc ? `DMARC ${policy ? 'p=' + policy : 'present'}` : 'no DMARC',
        spf ? 'SPF present' : 'no SPF',
      ];
      return {
        domain: host,
        resolved: true,
        dmarc: { found: !!dmarc, policy, record: dmarc },
        spf: { found: !!spf, record: spf },
        summary: `${host}: ${parts.join(', ')}.`,
      };
    },
  },
  {
    name: 'sitemap_check',
    title: 'Check the sitemap',
    description: 'Find and read a site sitemap (sitemap.xml or the one declared in robots.txt), and report whether it is a sitemap index or a urlset, how many entries it has, and how many carry a lastmod.',
    input: { url: z.string().describe('The site URL or domain, e.g. example.com') },
    async run({ url }) {
      const origin = normalizeUrl(url).origin;
      let smUrl = origin + '/sitemap.xml';
      let via = 'sitemap.xml';
      let res = await safeFetch(smUrl, { accept: 'application/xml, text/xml, */*' });
      if (res.status >= 400) {
        try {
          const rob = await safeFetch(origin + '/robots.txt', { accept: 'text/plain, */*' });
          const txt = rob.status < 400 ? await readBody(rob.response) : '';
          const m = txt.match(/^\s*sitemap:\s*(\S+)/im);
          if (m) { smUrl = m[1]; via = 'robots.txt'; res = await safeFetch(smUrl, { accept: 'application/xml, text/xml, */*' }); }
        } catch { /* none */ }
      }
      if (res.status >= 400) return { url: origin, found: false, summary: `No sitemap found for ${origin}.` };
      const xml = await readBody(res.response);
      const isIndex = /<sitemapindex[\s>]/i.test(xml);
      const entries = (xml.match(/<loc[\s>]/gi) || []).length;
      const withLastmod = (xml.match(/<lastmod[\s>]/gi) || []).length;
      return {
        url: origin,
        found: true,
        sitemap_url: smUrl,
        discovered_via: via,
        type: isIndex ? 'sitemapindex' : 'urlset',
        entries,
        with_lastmod: withLastmod,
        summary: `${smUrl}: ${isIndex ? 'sitemap index' : 'urlset'} with ${entries} entries (${withLastmod} with lastmod).`,
      };
    },
  },
  {
    name: 'og_preview',
    title: 'Preview Open Graph tags',
    description: 'Fetch a page and read its Open Graph and Twitter Card tags, the title and image a social or AI preview would show, and flag any missing.',
    input: { url: z.string().describe('The page URL, e.g. https://example.com/') },
    async run({ url }) {
      const res = await safeFetch(url);
      const html = await readBody(res.response);
      const meta = (prop) => {
        const re = new RegExp('<meta[^>]+(?:property|name)=["\\\']' + prop.replace(/[:]/g, '\\$&') + '["\\\'][^>]*>', 'i');
        const tag = (html.match(re) || [])[0] || '';
        return (tag.match(/content=["']([^"']*)["']/i) || [])[1] || null;
      };
      const og = { title: meta('og:title'), description: meta('og:description'), image: meta('og:image'), type: meta('og:type'), site_name: meta('og:site_name'), url: meta('og:url') };
      const twitter = { card: meta('twitter:card'), title: meta('twitter:title'), image: meta('twitter:image') };
      const titleTag = (html.match(/<title[^>]*>([^<]*)<\/title>/i) || [])[1] || null;
      const missing = ['og:title', 'og:description', 'og:image'].filter((k) => !og[k.split(':')[1]]);
      return {
        url: res.finalUrl,
        title_tag: titleTag,
        open_graph: og,
        twitter,
        missing,
        summary: missing.length ? `${res.finalUrl} is missing ${missing.join(', ')}.` : `${res.finalUrl} has a complete Open Graph card${og.title ? `: "${og.title}"` : ''}.`,
      };
    },
  },
  {
    name: 'alt_audit',
    title: 'Audit image alt text',
    description: 'Fetch a page and audit its images for alt text: how many have descriptive alt, how many are empty, and how many are missing it entirely, with a few example sources.',
    input: { url: z.string().describe('The page URL, e.g. https://example.com/') },
    async run({ url }) {
      const res = await safeFetch(url);
      const html = await readBody(res.response);
      const imgs = html.match(/<img\b[^>]*>/gi) || [];
      let withAlt = 0, emptyAlt = 0, missingAlt = 0;
      const missingExamples = [];
      for (const tag of imgs) {
        const altM = tag.match(/\balt=["']([^"']*)["']/i);
        if (!altM) {
          missingAlt++;
          const src = (tag.match(/\bsrc=["']([^"']+)["']/i) || [])[1];
          if (src && missingExamples.length < 8) missingExamples.push(src);
        } else if (altM[1].trim() === '') emptyAlt++;
        else withAlt++;
      }
      return {
        url: res.finalUrl,
        images: imgs.length,
        with_alt: withAlt,
        empty_alt: emptyAlt,
        missing_alt: missingAlt,
        missing_examples: missingExamples,
        summary: `${res.finalUrl}: ${imgs.length} images, ${withAlt} with alt, ${emptyAlt} empty, ${missingAlt} missing.`,
      };
    },
  },
];
