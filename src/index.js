/**
 * longarm-mcp
 *
 * Cloudflare Worker implementing the MCP Streamable HTTP transport.
 * Registered once as a connector in claude.ai — available in every session
 * on every device with every model, no local installs required.
 *
 * Endpoint: POST /mcp   (MCP Streamable HTTP — https://spec.modelcontextprotocol.io)
 * Health:   GET  /health
 *
 * Auth: Bearer token via Authorization header.
 *       Set via `wrangler secret put AUTH_TOKEN` in production.
 *       For local dev, set AUTH_TOKEN in .env (see .env.example).
 */

import { TOOLS, callTool } from './tools.js';

const SERVER_INFO = { name: 'longarm-mcp', version: '1.3.1' };
const PROTOCOL_VERSION = '2024-11-05';

// ── Worker entry point ──────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return cors(new Response(null, { status: 204 }));
    }

    // Health check — unauthenticated
    if (url.pathname === '/health') {
      return cors(json({ ok: true, server: SERVER_INFO.name }));
    }

    // Auth gate
    if (!env.AUTH_TOKEN) {
      return cors(new Response(
        'AUTH_TOKEN not configured — set it with: wrangler secret put AUTH_TOKEN',
        { status: 500 },
      ));
    }
    if (!isAuthorized(request, env)) {
      return cors(new Response('Unauthorized', { status: 401 }));
    }

    // MCP endpoint
    if (url.pathname === '/mcp' || url.pathname === '/') {
      return handleMcp(request, env);
    }

    return cors(new Response('Not Found', { status: 404 }));
  },
};

// ── Auth ────────────────────────────────────────────────────────────────────
function isAuthorized(request, env) {
  if (!env.AUTH_TOKEN) return false; // defensive — caller already checks, but fail safe
  const auth = request.headers.get('Authorization') ?? '';
  const [scheme, token] = auth.split(' ');
  return scheme === 'Bearer' && token === env.AUTH_TOKEN;
}

// ── MCP handler ─────────────────────────────────────────────────────────────
async function handleMcp(request) {
  if (request.method !== 'POST') {
    return cors(new Response('Method Not Allowed', { status: 405 }));
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return cors(json(rpcError(null, -32700, 'Parse error')));
  }

  // MCP allows batch requests (array of messages)
  if (Array.isArray(body)) {
    const responses = await Promise.all(body.map(dispatch));
    return cors(json(responses.filter(Boolean)));
  }

  const response = await dispatch(body);

  // Notifications (no id) get 202, no body
  if (response === null) {
    return cors(new Response(null, { status: 202 }));
  }

  return cors(json(response));
}

// ── JSON-RPC dispatcher ──────────────────────────────────────────────────────
async function dispatch(message) {
  const { id, method, params } = message ?? {};

  // Notifications have no id and require no response
  if (id === undefined) return null;

  try {
    switch (method) {
      case 'initialize':
        return rpcOk(id, {
          protocolVersion: PROTOCOL_VERSION,
          serverInfo: SERVER_INFO,
          capabilities: { tools: {} },
        });

      case 'ping':
        return rpcOk(id, {});

      case 'tools/list':
        return rpcOk(id, { tools: TOOLS });

      case 'tools/call': {
        const { name, arguments: args = {} } = params ?? {};
        if (!name) throw new Error('tools/call requires params.name');
        const result = await callTool(name, args);
        return rpcOk(id, result);
      }

      default:
        return { jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } };
    }
  } catch (err) {
    console.error('[mcp error]', err?.stack ?? err?.message);
    return { jsonrpc: '2.0', id, error: { code: -32603, message: err?.message ?? 'Internal error' } };
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function rpcOk(id, result)          { return { jsonrpc: '2.0', id, result }; }
function rpcError(id, code, message){ return { jsonrpc: '2.0', id, error: { code, message } }; }

function json(data) {
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json' },
  });
}

function cors(response) {
  const h = new Headers(response.headers);
  h.set('Access-Control-Allow-Origin', '*');
  h.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  h.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id');
  return new Response(response.body, { status: response.status, headers: h });
}
