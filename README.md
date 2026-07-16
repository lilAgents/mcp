# lilAgents MCP

The lilAgents free-tool fleet, as tools for AI agents.

lilAgents grades how visible your site is to AI agents. This is the other half: the same checks, exposed over the [Model Context Protocol](https://modelcontextprotocol.io) so Claude, Cursor, and any MCP-aware agent can audit a website themselves. Every tool takes a URL or a domain and is a read-only public lookup.

A free tool by [lilAgents](https://lilagents.com).

## Tools

| Tool | What it does |
|------|--------------|
| `stack_detect` | Fingerprints CMS, framework, hosting, backend, marketing tech, and AI website builders, plus RDAP registration and Ahrefs Domain Rating. Proxies the canonical lilStack service for exact parity. |
| `trace_redirects` | Follows every redirect hop and reports each status code and Location. |
| `dns_snapshot` | Full DNS snapshot (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA) via DNS-over-HTTPS. |
| `check_headers` | Reports which baseline security headers are present or missing. |
| `check_robots` | Shows which major AI crawlers robots.txt allows or blocks, plus whether llms.txt exists. |
| `check_indexability` | Reads canonical, meta robots, and X-Robots-Tag to say if a page is indexable. |
| `validate_schema` | Extracts and validates every JSON-LD block and lists the schema.org types. |
| `domain_rating` | The Ahrefs Domain Rating (0 to 100), with the required attribution. |
| `dmarc_check` | The DMARC record and policy plus the SPF record for a domain. |
| `sitemap_check` | Finds the sitemap and reports its type, entry count, and lastmod coverage. |
| `og_preview` | Reads Open Graph and Twitter Card tags, the title and image a preview would show. |
| `alt_audit` | Audits a page's images for descriptive, empty, and missing alt text. |

## Install

### Remote, no install (Claude.ai, ChatGPT, and any Streamable HTTP client)

Add this URL as a custom connector or remote MCP server:

```
https://mcp.lilagents.com
```

No install and no key. This is the hosted server; it runs the same tools as the package below.

### Claude Code

Remote:

```
claude mcp add --transport http lilagents https://mcp.lilagents.com
```

Or local over stdio:

```
claude mcp add lilagents -- npx -y @lilagents/mcp
```

### Claude Desktop, Cursor, and other stdio clients

Add this to the client's MCP config (`claude_desktop_config.json`, `.cursor/mcp.json`, and so on):

```json
{
  "mcpServers": {
    "lilagents": {
      "command": "npx",
      "args": ["-y", "@lilagents/mcp"]
    }
  }
}
```

### From source

```
git clone https://github.com/lilAgents/mcp.git
cd mcp
pnpm install
node src/index.js
```

Point your client's `command` at `node` with the args `["/absolute/path/to/mcp/src/index.js"]`.

## Try it

Ask your agent things like:

- "Use lilagents to detect what stripe.com is built with."
- "Trace the redirects on this shortened link."
- "Which AI crawlers does openai.com block in robots.txt?"
- "Is this page indexable, and does it have valid JSON-LD?"

## Develop

```
pnpm install
pnpm smoke      # spawns the server and calls every tool against live domains
pnpm inspect    # opens the MCP Inspector
```

## Notes

- Node 18 or newer (uses the built-in fetch).
- Every outbound request is SSRF-guarded (no localhost or private addresses), follows redirects manually, and is time-boxed, matching the live lilAgents tools.
- Ahrefs Domain Rating is returned with its required attribution and license link.

## License

MIT. See [LICENSE](LICENSE). Made with love by lilAgents.
