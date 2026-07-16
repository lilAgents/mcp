// End-to-end smoke test: spawn the server over stdio with a real MCP client,
// list the tools, and call every one against live domains, asserting each
// returns a non-error result with a summary. Run: pnpm smoke (needs network).

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const entry = join(here, '..', 'src', 'index.js');

const transport = new StdioClientTransport({ command: process.execPath, args: [entry] });
const client = new Client({ name: 'lilagents-smoke', version: '1.0.0' });
await client.connect(transport);

const { tools } = await client.listTools();
console.log('registered tools (' + tools.length + '): ' + tools.map((t) => t.name).join(', ') + '\n');

const CALLS = [
  ['stack_detect', { url: 'stripe.com' }],
  ['trace_redirects', { url: 'http://github.com' }],
  ['dns_snapshot', { domain: 'lilagents.com' }],
  ['check_headers', { url: 'https://lilagents.com' }],
  ['check_robots', { url: 'https://openai.com' }],
  ['check_indexability', { url: 'https://lilagents.com' }],
  ['validate_schema', { url: 'https://lilagents.com' }],
  ['domain_rating', { domain: 'github.com' }],
  ['dmarc_check', { domain: 'google.com' }],
  ['sitemap_check', { url: 'https://www.cloudflare.com' }],
  ['og_preview', { url: 'https://stripe.com' }],
  ['alt_audit', { url: 'https://lilagents.com' }],
];

let pass = 0, fail = 0;
for (const [name, args] of CALLS) {
  try {
    const res = await client.callTool({ name, arguments: args });
    const text = (res.content && res.content[0] && res.content[0].text) || '';
    if (res.isError) { console.log('FAIL ' + name + ' -> ' + text.slice(0, 140)); fail++; continue; }
    const data = JSON.parse(text);
    const ok = typeof data.summary === 'string' && data.summary.length > 0;
    console.log((ok ? 'PASS ' : 'FAIL ') + name + ' -> ' + String(data.summary || text).slice(0, 140));
    ok ? pass++ : fail++;
  } catch (e) {
    console.log('FAIL ' + name + ' -> ' + (e && e.message ? e.message : String(e)));
    fail++;
  }
}

await client.close();
console.log('\n' + pass + '/' + (pass + fail) + ' tools passed');
process.exit(fail ? 1 : 0);
