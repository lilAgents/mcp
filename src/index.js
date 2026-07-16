#!/usr/bin/env node
// lilAgents MCP server (stdio). Exposes the lilAgents free-tool fleet as
// read-only tools any AI agent can call. The tool handlers live in tools.js and
// are transport-agnostic, so a remote (HTTP/Worker) build can wrap the same set.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { TOOLS } from './tools.js';

const server = new McpServer(
  { name: 'lilagents', version: '1.1.0' },
  {
    instructions:
      'lilAgents tools for auditing a website the way an AI agent sees it: detect its tech stack, trace redirects, snapshot DNS, audit security headers, check which AI crawlers robots.txt allows, check indexability, validate JSON-LD, and read the Ahrefs Domain Rating. Every tool takes a URL or domain and is a read-only public lookup.',
  }
);

for (const t of TOOLS) {
  server.registerTool(
    t.name,
    { title: t.title, description: t.description, inputSchema: t.input },
    async (args) => {
      try {
        const data = await t.run(args);
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
      } catch (e) {
        return {
          content: [{ type: 'text', text: 'Error: ' + (e && e.message ? e.message : String(e)) }],
          isError: true,
        };
      }
    }
  );
}

const transport = new StdioServerTransport();
await server.connect(transport);
// stdio servers must not write to stdout; log readiness to stderr only.
console.error('lilAgents MCP server ready on stdio with ' + TOOLS.length + ' tools.');
