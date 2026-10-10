/**
 * MCP tool definitions and dispatch
 */

import { execSSH, readFileSSH, writeFileSSH, listDirSSH } from './ssh.js';

// ── SSH param schema (shared across all SSH tools) ─────────────────────────
const SSH_PARAMS = {
  host: { type: 'string', description: 'SSH host (hostname or IP)' },
  port: { type: 'number', description: 'SSH port (default: 22)' },
  user: { type: 'string', description: 'SSH username' },
  key:  {
    type: 'string',
    description: [
      'Private key — OpenSSH format (-----BEGIN OPENSSH PRIVATE KEY-----) or legacy PEM (-----BEGIN RSA PRIVATE KEY-----).',
      'Encrypted keys are supported via the passphrase parameter.',
      'PKCS8 keys (-----BEGIN PRIVATE KEY-----) are not supported; convert with: ssh-keygen -p -m PEM -f keyfile.',
    ].join(' '),
  },
  fingerprint: {
    type: 'string',
    description: [
      'Expected SSH host key fingerprint in SHA256:... format',
      '(from `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`).',
      'If omitted, the host key is accepted without verification on every call.',
    ].join(' '),
  },
  passphrase: {
    type: 'string',
    description: 'Passphrase for an encrypted private key. Omit for unencrypted keys.',
  },
};
const SSH_REQUIRED = ['host', 'user', 'key'];

// ── Tool definitions ────────────────────────────────────────────────────────
export const TOOLS = [
  {
    name: 'exec',
    description: [
      'Execute a shell command on a remote server via SSH.',
      'Returns stdout, stderr, and exit code.',
      'Use cwd to set the working directory before running the command.',
      'stdin is closed immediately and there is no PTY — non-interactive commands only.',
      'PATH reflects the SSH daemon environment, not .bashrc; sudo cannot prompt for a password.',
    ].join(' '),
    inputSchema: {
      type: 'object',
      properties: {
        ...SSH_PARAMS,
        cmd: { type: 'string', description: 'Shell command to run' },
        cwd: { type: 'string', description: 'Working directory (optional)' },
      },
      required: [...SSH_REQUIRED, 'cmd'],
    },
  },

  {
    name: 'read_file',
    description: [
      'Read a file from a remote server via SFTP.',
      'Returns file contents as text (default) or base64 for binary files.',
    ].join(' '),
    inputSchema: {
      type: 'object',
      properties: {
        ...SSH_PARAMS,
        path: { type: 'string', description: 'Absolute path to the file' },
        encoding: {
          type: 'string',
          description: "Response encoding: 'text' (default, UTF-8) or 'base64' for binary files",
          enum: ['text', 'base64'],
        },
      },
      required: [...SSH_REQUIRED, 'path'],
    },
  },

  {
    name: 'write_file',
    description: 'Write content to a file on a remote server via SFTP. Creates or overwrites.',
    inputSchema: {
      type: 'object',
      properties: {
        ...SSH_PARAMS,
        path:    { type: 'string', description: 'Absolute path to write' },
        content: { type: 'string', description: 'File content' },
      },
      required: [...SSH_REQUIRED, 'path', 'content'],
    },
  },

  {
    name: 'list_dir',
    description: 'List the contents of a directory on a remote server via SFTP.',
    inputSchema: {
      type: 'object',
      properties: {
        ...SSH_PARAMS,
        path: { type: 'string', description: 'Directory path to list' },
      },
      required: [...SSH_REQUIRED, 'path'],
    },
  },

  {
    name: 'fetch',
    description: [
      'Make an HTTP/HTTPS request to any URL.',
      'Use for REST APIs, webhooks, web scraping, or any HTTP endpoint.',
      'Returns status, all response headers, and body.',
      'Text responses (text/*, application/json, etc.) are returned as-is.',
      'Binary responses are returned as base64 with a [base64] prefix line.',
    ].join(' '),
    inputSchema: {
      type: 'object',
      properties: {
        url:     { type: 'string', description: 'Full URL to fetch' },
        method:  { type: 'string', description: 'HTTP method (default: GET)', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] },
        headers: { type: 'object', description: 'Request headers as key/value pairs', additionalProperties: { type: 'string' } },
        body:    { type: 'string', description: 'Request body (for POST / PUT / PATCH)' },
        timeout: { type: 'number', description: 'Timeout in milliseconds (default: 30000)' },
      },
      required: ['url'],
    },
  },
];

/**
 * Retry once on "Disallowed operation called within global scope" —
 * a Cloudflare Workers isolate cold-start restriction. Crypto APIs are
 * not available in the global scope during module initialisation; the
 * first request to a freshly started isolate can trigger this before the
 * runtime has finished setting up. The second call always succeeds.
 * Matches only that specific string so SSH auth/network errors are not
 * silently retried.
 */
async function withIsolateRetry(fn) {
  try {
    return await fn();
  } catch (err) {
    if (typeof err.message === 'string' && err.message.includes('Disallowed operation called within global scope')) {
      return await fn();
    }
    throw err;
  }
}

/**
 * Normalise a private key string before handing it to ssh2:
 *   - trim outer whitespace
 *   - convert literal two-char sequence \n to real newlines
 *   - strip leading and trailing whitespace from every line
 *   - if the base64 body is on a single line (no newlines between header
 *     and footer), reconstruct it with 64-char line wrapping
 *   - if an encrypted legacy PEM (Proc-Type, DEK-Info headers) has been
 *     collapsed onto one line, reconstruct the proper header/body format
 *
 * Keys that already have proper line breaks are left alone.
 */
function normalizeKey(raw) {
  if (!raw) return raw;
  let k = raw.trim().replace(/\\n/g, '\n');
  k = k.split('\n').map(l => l.trim()).join('\n');

  // Try to match a PEM envelope with newlines between header and footer
  const m = k.match(/^(-----BEGIN [^\n]+ KEY-----)\n([\s\S]+)\n(-----END [^\n]+ KEY-----)$/);
  if (m) {
    const inner = m[2];
    // If the inner content already has newlines, the key has structure
    // (proper 64-char wrapping, or encrypted PEM with Proc-Type/DEK-Info
    // headers). Leave it alone.
    if (!inner.includes('\n')) {
      k = rewrapPemBody(inner, m[1], m[3]);
    }
    return k;
  }

  // Header, body and footer all on one line (or no newlines at all)
  const single = k.match(/^(-----BEGIN [^\n]+ KEY-----)\s+(.+?)\s+(-----END [^\n]+ KEY-----)$/);
  if (single) {
    k = rewrapPemBody(single[2], single[1], single[3]);
  }
  return k;
}

/**
 * Rewrap a PEM body that has been collapsed onto one line.
 *
 * Handles two cases:
 *  1. Plain base64 — wrap at 64 chars.
 *  2. Encrypted legacy PEM with Proc-Type/DEK-Info headers mixed into
 *     the line — pull the headers out, rewrap only the base64, and
 *     reconstruct the proper format (headers, blank line, body).
 *
 * Returns the full PEM block (header + body + footer).
 */
function rewrapPemBody(inner, header, footer) {
  // Detect encrypted PEM headers collapsed into the body
  const enc = inner.match(/^(Proc-Type:\s*\S+)\s+(DEK-Info:\s*\S+)\s+(.+)$/);
  if (enc) {
    const b64 = enc[3].replace(/\s+/g, '');
    const lines = b64.match(/.{1,64}/g);
    if (!lines) return `${header}\n${enc[1]}\n${enc[2]}\n\n${footer}`;
    return `${header}\n${enc[1]}\n${enc[2]}\n\n${lines.join('\n')}\n${footer}`;
  }

  const body = inner.replace(/\s+/g, '');
  const lines = body.match(/.{1,64}/g);
  if (!lines) return `${header}\n${footer}`; // empty body — return unchanged
  return `${header}\n${lines.join('\n')}\n${footer}`;
}

// ── Tool dispatch ───────────────────────────────────────────────────────────
export async function callTool(name, args) {
  switch (name) {
    // ── exec ──
    case 'exec': {
      const { host, port = 22, user, key: rawKey, fingerprint, passphrase, cmd, cwd } = args;
      const key = normalizeKey(rawKey);
      if (/BEGIN( ENCRYPTED)? PRIVATE KEY/.test(key ?? '')) {
        return { content: [{ type: 'text', text: 'PKCS8 not supported — convert with: ssh-keygen -p -m PEM -f keyfile' }], isError: true };
      }
      const result = await withIsolateRetry(() => execSSH({ host, port, user, key, fingerprint, passphrase, cmd, cwd }));
      return {
        content: [{ type: 'text', text: formatExec(result) }],
        isError: false, // non-zero exit is not a transport error — model reads exitCode in the text
      };
    }

    // ── read_file ──
    case 'read_file': {
      const { host, port = 22, user, key: rawKey, fingerprint, passphrase, path, encoding = 'text' } = args;
      const key = normalizeKey(rawKey);
      if (/BEGIN( ENCRYPTED)? PRIVATE KEY/.test(key ?? '')) {
        return { content: [{ type: 'text', text: 'PKCS8 not supported — convert with: ssh-keygen -p -m PEM -f keyfile' }], isError: true };
      }
      const data = await withIsolateRetry(() => readFileSSH({ host, port, user, key, fingerprint, passphrase, path, encoding }));
      const text = encoding === 'base64' ? `[base64]\n${data}` : data;
      return { content: [{ type: 'text', text }] };
    }

    // ── write_file ──
    case 'write_file': {
      const { host, port = 22, user, key: rawKey, fingerprint, passphrase, path, content } = args;
      const key = normalizeKey(rawKey);
      if (/BEGIN( ENCRYPTED)? PRIVATE KEY/.test(key ?? '')) {
        return { content: [{ type: 'text', text: 'PKCS8 not supported — convert with: ssh-keygen -p -m PEM -f keyfile' }], isError: true };
      }
      await withIsolateRetry(() => writeFileSSH({ host, port, user, key, fingerprint, passphrase, path, content }));
      return { content: [{ type: 'text', text: `OK: wrote ${path}` }] };
    }

    // ── list_dir ──
    case 'list_dir': {
      const { host, port = 22, user, key: rawKey, fingerprint, passphrase, path } = args;
      const key = normalizeKey(rawKey);
      if (/BEGIN( ENCRYPTED)? PRIVATE KEY/.test(key ?? '')) {
        return { content: [{ type: 'text', text: 'PKCS8 not supported — convert with: ssh-keygen -p -m PEM -f keyfile' }], isError: true };
      }
      const entries = await withIsolateRetry(() => listDirSSH({ host, port, user, key, fingerprint, passphrase, path }));
      return { content: [{ type: 'text', text: entries.join('\n') || '(empty directory)' }] };
    }

    // ── fetch ──
    case 'fetch': {
      const { url, method = 'GET', headers = {}, body, timeout = 30_000 } = args;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      try {
        const res = await fetch(url, {
          method,
          headers,
          body: (body !== undefined && method !== 'GET' && method !== 'HEAD') ? body : undefined,
          signal: controller.signal,
        });

        const headerLines = [];
        res.headers.forEach((v, k) => { headerLines.push(`${k}: ${v}`); });

        const contentType = res.headers.get('content-type') ?? '';
        let bodyText;
        if (isTextMime(contentType)) {
          bodyText = await res.text();
        } else {
          const bytes = await res.arrayBuffer();
          bodyText = `[base64]\n${Buffer.from(bytes).toString('base64')}`;
        }

        const summary = `HTTP ${res.status} ${res.statusText}\n`
          + headerLines.join('\n') + '\n\n'
          + bodyText;

        return {
          content: [{ type: 'text', text: summary }],
          isError: !res.ok,
        };
      } finally {
        clearTimeout(timer);
      }
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function formatExec({ stdout, stderr, exitCode, signal }) {
  const parts = [];
  if (stdout) parts.push(stdout.trimEnd());
  if (stderr) parts.push(`[stderr]\n${stderr.trimEnd()}`);
  if (signal) {
    parts.push(`[killed: ${signal}]`);
  } else if (exitCode != null) {
    parts.push(`[exit: ${exitCode}]`);
  } else {
    parts.push('[exit: unknown]');
  }
  return parts.join('\n').trimStart();
}

/**
 * Return true if the MIME type is text-based and safe to decode as UTF-8.
 * Binary responses (images, archives, fonts, etc.) are returned as base64.
 */
function isTextMime(contentType) {
  if (!contentType) return true; // unknown — assume text
  const mime = contentType.toLowerCase().split(';')[0].trim();
  return (
    mime.startsWith('text/') ||
    mime === 'application/json' ||
    mime === 'application/xml' ||
    mime === 'application/javascript' ||
    mime === 'application/x-javascript' ||
    mime === 'application/x-www-form-urlencoded' ||
    mime.endsWith('+json') ||
    mime.endsWith('+xml')
  );
}
