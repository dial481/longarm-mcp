# longarm-mcp

SSH, SFTP, and HTTP/HTTPS fetch from any Claude session -- no local installs, no relay agent, works on every device with every model.

## Why this exists

Register one Cloudflare Worker as a claude.ai connector and every Claude session on your account gets SSH and HTTP access to your own infrastructure. No client-side installation, no bootstrap scripts, no per-session setup. The Worker stores nothing -- keys and tokens pass through as parameters on each call and are discarded when the request completes.

## Tools

| Tool | Description |
|---|---|
| `exec` | Run a shell command on a remote server via SSH. Returns stdout, stderr, exit code. stdin is closed immediately (non-interactive, no PTY). |
| `read_file` | Read a remote file via SFTP. `encoding: 'base64'` for binary files. |
| `write_file` | Write a remote file via SFTP. Creates or overwrites. |
| `list_dir` | List a remote directory via SFTP. |
| `fetch` | Make an HTTP/HTTPS request to any URL. Returns status, all response headers, and body. Binary responses are returned as base64. |

## Setup

### Prerequisites

- Cloudflare account (free tier works)
- Node.js 22+
- wrangler v4+

### Deploy

```bash
git clone https://github.com/dial481/longarm-mcp
cd longarm-mcp
npm install
```

Set your auth token -- this protects the MCP endpoint:

```bash
wrangler secret put AUTH_TOKEN
# paste a strong random token, e.g.: openssl rand -hex 32
```

**AUTH_TOKEN is required.** The Worker rejects all requests if no token is configured.

Deploy:

```bash
npm run deploy
```

The Worker URL is `https://longarm-mcp.<your-account>.workers.dev`.

### Register as a claude.ai connector

Settings > Connectors > Add connector:

- **URL**: `https://longarm-mcp.<your-account>.workers.dev/mcp`
- **Auth**: Bearer `<your AUTH_TOKEN>`

Done. Every Claude session on that account now has `exec`, `fetch`, and the file tools.

### Local development

```bash
cp .env.example .env   # fill in AUTH_TOKEN
npm run dev            # http://localhost:8787
```

## Using the tools

### SSH

All SSH tools share the same connection parameters:

| Parameter | Required | Description |
|---|---|---|
| `host` | yes | Hostname or IP |
| `user` | yes | SSH username |
| `key` | yes | Private key, full PEM |
| `port` | -- | SSH port (default: 22) |
| `fingerprint` | -- | Expected host key fingerprint in exact `SHA256:<base64>` format (from `ssh-keygen -lf`). Must include the `SHA256:` prefix. Trailing `=` padding is accepted. Only the negotiated host key type is checked (Ed25519 by default). If omitted, host key is accepted without verification on every call -- the Worker stores nothing between requests. |
| `passphrase` | -- | Passphrase for encrypted private keys. Omit for unencrypted keys. |

**Supported key formats:** OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`), legacy RSA PEM (`-----BEGIN RSA PRIVATE KEY-----`), and legacy EC PEM (`-----BEGIN EC PRIVATE KEY-----`), encrypted or unencrypted. PKCS8 keys (`-----BEGIN PRIVATE KEY-----` or `-----BEGIN ENCRYPTED PRIVATE KEY-----`) are not supported -- convert them first:

```bash
ssh-keygen -p -m PEM -f ~/.ssh/id_rsa   # converts in place; back up first
```

The tool normalises common formatting issues before parsing: literal `\n` escape sequences, leading and trailing whitespace per line, single-line base64 bodies, and collapsed encrypted PEM headers. A well-formed PEM block will work; a whitespace-mangled copy of one will usually work too.

**Long-running commands:** The Worker stays alive while waiting on the SSH socket -- network wait does not consume CPU time. The ceiling is your MCP client's own timeout (typically around 230 seconds for claude.ai). For commands that outlast that window, use `nohup cmd &` or a `tmux`/`screen` session and poll for results with a follow-up `exec`.

**No PTY:** `exec` runs in a non-interactive shell with no pseudo-terminal. PATH reflects the SSH daemon's environment -- `.bashrc` additions are not sourced, so tools installed via user PATH may need a full path. Commands that require a TTY (`sudo` password prompts, curses apps) will fail or hang; use `sudo -n` (NOPASSWD) for passwordless sudo.

**Output format:** `exec` returns stdout, stderr (prefixed with `[stderr]`), and a status line: `[exit: N]` for normal termination, `[killed: SIGNAL]` when the process was killed by a signal (e.g. `[killed: SIGKILL]`), or `[exit: unknown]` when the channel closed without reporting either.

```
exec: host=myserver.com user=deploy key="-----BEGIN OPENSSH PRIVATE KEY-----
..." cmd="uptime"
```

Optionally verify the host key before connecting. Get the fingerprint with:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
# 256 SHA256:abc123... root@myserver (ED25519)
#     ^^^^^^^^^^^^^^^^^^^^ copy exactly this part, prefix included
```

Pass the `SHA256:...` value verbatim. The Worker negotiates Ed25519 by default (first in
its `serverHostKey` list), so use the ed25519 host key fingerprint. If the server does
not have an Ed25519 key, remove `ssh-ed25519` from the `serverHostKey` list in `src/ssh.js`
and use the fingerprint for whatever key type the server offers.

```
exec: host=myserver.com user=deploy key="..." fingerprint="SHA256:abc123..." cmd="uptime"
```

### HTTP/HTTPS fetch

```
fetch: url=https://api.example.com/data
       method=POST
       headers={"Authorization": "Bearer token", "Content-Type": "application/json"}
       body={"hello": "world"}
       timeout=10000
```

Redirects are followed automatically. The response includes status, all response headers, and body. Text responses (text/*, application/json, etc.) are returned as-is; binary responses are returned as base64 with a `[base64]` prefix line.

## Security

**Bearer token:** The bearer token is the sole access control. Whoever holds it can call all five tools -- `exec` with SSH access to any server whose key they have, `fetch` to any URL reachable from Cloudflare's network. Treat it like an SSH private key. When stored as a claude.ai connector secret it is encrypted at rest; outside claude.ai, ensure it is not logged or committed.

**Keys in context:** Private keys and passphrases are passed as tool parameters. They appear in the tool call in the model's context window and, depending on your MCP client, may be stored in conversation history. Use deploy keys with narrow permissions, or the planned encrypted-key feature (see Roadmap) to limit transcript exposure.

**Key handling in the Worker:** The private key travels in the HTTPS request body to Cloudflare's infrastructure, lives in Worker memory for the duration of the SSH session (typically 5-20 seconds), and is then discarded. It is never written to storage, and request logging is disabled (`[observability]` is not set in `wrangler.toml`).

This is the same exposure model as a managed bastion host or a secrets manager that brokers SSH access transiently. If your threat model requires the private key to never leave your local network, a local SSH relay is the right tool instead.

## Cloudflare Workers runtime notes

CF Workers' `node:crypto` (provided by the `nodejs_compat` flag) is not a complete Node.js crypto implementation. Two SSH algorithm families silently fail and are excluded from the client's offer list:

**Key exchange -- X25519 / Curve25519**: `diffieHellman()` is not implemented. The client offers ECDH-NIST (`ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`) and classic DH (`diffie-hellman-group14-sha256`, `diffie-hellman-group14-sha1`) instead. All modern sshd versions support these.

**Packet encryption -- AES-GCM**: The AEAD authentication-tag path is not implemented. The client offers AES-CTR (`aes128-ctr`, `aes192-ctr`, `aes256-ctr`) with `hmac-sha2-256` / `hmac-sha2-512` instead.

**MAC algorithms:** The client does not offer `-etm` (encrypt-then-MAC) variants. Servers that require `hmac-sha2-256-etm@openssh.com` exclusively will refuse the connection. Most default sshd configurations accept the standard `hmac-sha2-256`.

These exclusions are handled transparently in `src/ssh.js`. Your server needs no configuration changes unless it has been hardened to require only algorithms this Worker cannot offer.

**Cold-start crypto timing:** On the very first request to a freshly-started Worker isolate, SSH may fail with a Cloudflare "Disallowed operation called within global scope" error from ssh2's internal crypto initialisation. The Worker retries automatically. If you see the error in a client that does not retry, call the tool again.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for planned features:
- Worker-pubkey credential encryption (keys never enter LLM context)
- Named host aliases (short names for connection details)
- Zero-credential agent mode (all keys stored in the Worker)

## Architecture

```
Claude session
    |  POST /mcp  (MCP Streamable HTTP, HTTPS)
    v
Cloudflare Worker
    |  cloudflare:sockets TCP
    v
your server :22
    |
    SSH session via ssh2 (pure JS, no native addons)
```

The Worker bundles [ssh2](https://github.com/mscdex/ssh2) via a custom esbuild step (`build.mjs`) that handles three CF Workers constraints:

1. **Native addons**: `.node` files are stubbed so ssh2 falls back to its pure-JS crypto path.
2. **WHATWG to Node.js stream bridge**: `cloudflare:sockets` returns WHATWG `ReadableStream` / `WritableStream`; ssh2 expects a Node.js `Duplex`. `src/ssh.js` bridges them.
3. **CJS/ESM interop**: CF Workers is ESM; ssh2 is CJS and calls `require('events')`, `require('stream')`, etc. at runtime. `build.mjs` prepends static `import` declarations to the bundle and wires them into `globalThis` so CJS `require()` calls resolve correctly at Worker startup.

## Scripts

```bash
npm run build    # esbuild -> dist/worker.js
npm run dev      # wrangler dev (local, reads .env)
npm run deploy   # wrangler deploy (production)
npm run tail     # wrangler tail (live request log)
```

## License

MIT
