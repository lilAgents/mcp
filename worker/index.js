// lilAgents MCP, remote build (Cloudflare Worker, stateless Streamable HTTP).
// Wraps the exact same tool handlers as the npm package (../src/tools.js), so the
// local stdio server and the hosted server are always in lockstep. Read-only
// public tools, so no sessions and no auth: every POST is handled independently.

import { TOOLS } from '../src/tools.js';

const SERVER_INFO = { name: 'lilagents', version: '1.2.0' };
const INSTRUCTIONS =
  'lilAgents tools for auditing a website the way an AI agent sees it: detect its tech stack, trace redirects, snapshot DNS, audit security headers, check which AI crawlers robots.txt allows, check indexability, validate JSON-LD, and read the Ahrefs Domain Rating. Every tool takes a URL or domain and is a read-only public lookup.';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Authorization',
  'Access-Control-Max-Age': '86400',
};

// Build a JSON Schema for a tool from its (zod-described) input shape.
function inputSchema(input) {
  const properties = {};
  const required = [];
  for (const [key, shape] of Object.entries(input)) {
    properties[key] = { type: 'string', description: (shape && shape.description) || '' };
    required.push(key);
  }
  return { type: 'object', properties, required, additionalProperties: false };
}

function reply(id, result) { return { jsonrpc: '2.0', id, result }; }
function rpcError(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

async function handleRpc(msg) {
  if (!msg || typeof msg !== 'object') return rpcError(null, -32600, 'Invalid Request');
  const { id, method, params } = msg;
  const isNotification = id === undefined || id === null;

  switch (method) {
    case 'initialize':
      return reply(id, {
        protocolVersion: (params && params.protocolVersion) || '2025-06-18',
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
        instructions: INSTRUCTIONS,
      });
    case 'ping':
      return reply(id, {});
    case 'tools/list':
      return reply(id, {
        tools: TOOLS.map((t) => ({ name: t.name, title: t.title, description: t.description, inputSchema: inputSchema(t.input) })),
      });
    case 'tools/call': {
      const t = TOOLS.find((x) => x.name === (params && params.name));
      if (!t) return rpcError(id, -32602, 'Unknown tool: ' + (params && params.name));
      try {
        const data = await t.run((params && params.arguments) || {});
        return reply(id, { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] });
      } catch (e) {
        return reply(id, { content: [{ type: 'text', text: 'Error: ' + (e && e.message ? e.message : String(e)) }], isError: true });
      }
    }
    default:
      // initialized and other notifications carry no id and expect no response.
      if (isNotification) return null;
      return rpcError(id, -32601, 'Method not found: ' + method);
  }
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json', ...CORS } });
}

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

    if (request.method === 'GET') {
      // A Streamable HTTP client opens a GET with Accept: text/event-stream to
      // find a server-initiated stream. This server is stateless with no such
      // stream, so answer 405 (the spec-correct signal). Plain GETs get a small
      // human/discovery blob instead.
      const accept = request.headers.get('accept') || '';
      if (accept.includes('text/event-stream')) {
        return new Response('Method Not Allowed', { status: 405, headers: { ...CORS, Allow: 'POST' } });
      }
      return jsonResponse({
        name: 'lilAgents MCP',
        transport: 'streamable-http',
        docs: 'https://lilagents.com/mcp',
        tools: TOOLS.map((t) => t.name),
        message: 'POST JSON-RPC 2.0 MCP messages to this endpoint.',
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: CORS });
    }

    let body;
    try { body = await request.json(); } catch {
      return jsonResponse({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400);
    }

    if (Array.isArray(body)) {
      const results = (await Promise.all(body.map(handleRpc))).filter((r) => r !== null);
      return results.length ? jsonResponse(results) : new Response(null, { status: 202, headers: CORS });
    }

    const result = await handleRpc(body);
    if (result === null) return new Response(null, { status: 202, headers: CORS });
    return jsonResponse(result);
  },
};
