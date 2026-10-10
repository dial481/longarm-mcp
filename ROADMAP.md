# Roadmap

Three independently shippable features. None is required for normal use and none changes the existing API -- all are purely additive.

---

## 1. Worker-pubkey credential encryption

### Motivation

Today the SSH private key travels in the HTTPS request body. It is processed transiently
(~20 s, never logged) but it does exist in the LLM's context window. In most threat models
that's fine -- the key is in a file anyway, and reading it also puts it in context. But for
teams with strict key-handling policies, or for long-running MCP sessions where a transcript
may be reviewed, there is one scheme that gives a hard guarantee: the private key never
enters LLM context at all.

### How it would work

**New Worker endpoint:** `GET /pubkey` -- returns the Worker's own RSA public key (4096-bit)
as PEM. This public key is derived from a `WORKER_PRIVATE_KEY` Worker Secret set at deploy
time. The Worker generates no key material on demand; the secret is set once by the operator.

**Client side (human, done offline, once per key):**

A hybrid encryption scheme is needed because RSA-OAEP can only encrypt small payloads
directly. SSH private keys (especially OpenSSH format) exceed the RSA-2048 OAEP limit
of ~190 bytes.

```bash
# 1. Fetch the Worker's public key
curl https://your-worker.workers.dev/pubkey -o worker_public.pem

# 2. Generate a random AES-256 key, encrypt the SSH key with it,
#    then encrypt the AES key with the Worker's RSA public key.
#    (A helper script will be provided.)
./encrypt-key.sh ~/.ssh/id_ed25519 worker_public.pem > id_ed25519.enc

# 3. Store the ciphertext in any config file
```

**At call time:** pass `encrypted_key` instead of `key`. The Worker decrypts server-side
using its secret before opening the SSH connection. The LLM only ever sees the ciphertext
blob -- even a full transcript leak reveals nothing usable.

**New tool parameter:**
```js
encrypted_key: {
  type: 'string',
  description: 'Hybrid-encrypted private key (base64). Use instead of `key`. ' +
               'Encrypt offline with the Worker\'s public key from GET /pubkey.',
}
```

**Worker-side decryption (src/crypto.js, new file):**
```js
import { subtle } from 'crypto';

export async function decryptKey(encryptedB64, workerPrivateKeyPem) {
  // Envelope: [RSA-OAEP encrypted AES key (512 bytes)] + [AES-256-GCM ciphertext]
  const envelope = Buffer.from(encryptedB64, 'base64');
  const rsaCiphertext = envelope.subarray(0, 512);
  const aesCiphertext = envelope.subarray(512);

  // Decrypt the AES key with RSA-OAEP
  const rsaKey = await subtle.importKey(
    'pkcs8', pemToDer(workerPrivateKeyPem),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false, ['decrypt']
  );
  const aesKeyRaw = await subtle.decrypt({ name: 'RSA-OAEP' }, rsaKey, rsaCiphertext);

  // Decrypt the SSH key with AES-256-GCM
  const aesKey = await subtle.importKey('raw', aesKeyRaw, 'AES-GCM', false, ['decrypt']);
  const iv = aesCiphertext.subarray(0, 12);
  const ct = aesCiphertext.subarray(12);
  const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return Buffer.from(plaintext).toString('utf8');
}
```

**In tools.js callTool():** if `encrypted_key` is present and `key` is absent, call
`decryptKey(encrypted_key, env.WORKER_PRIVATE_KEY)` and use the result as `key`.

### Things to watch out for

- CF Workers `subtle.decrypt` with RSA-OAEP works correctly (no known gaps unlike
  the AES-GCM and X25519 issues in the SSH layer).
- Hybrid encryption solves the key-size problem: AES-GCM handles any payload size,
  and only the 32-byte AES key needs RSA encryption.
- This feature is optional. If neither `key` nor `encrypted_key` is supplied, return a
  clear error. If both are supplied, `key` takes precedence (backward compat).
- The Worker private key in a Secret is static. If it leaks, rotate it and re-encrypt
  all stored ciphertexts. Document this clearly.

---

## 2. Named host aliases

### Motivation

Every call today requires `host`, `user`, `key`, and optionally `fingerprint`. For an ops
team with a stable set of targets -- a handful of prod/staging servers -- repeating all of
that on every tool call is verbose and puts the key in context repeatedly. Aliases let
agents use a short name and get the full config from the Worker.

### How it would work

**Storage:** Cloudflare KV namespace bound as `HOSTS` in wrangler.toml:
```toml
[[kv_namespaces]]
binding = "HOSTS"
id = "your-kv-namespace-id"
```

**Alias record shape (stored as JSON, key = alias name):**
```json
{
  "host": "prod.example.com",
  "port": 22,
  "user": "deploy",
  "fingerprint": "SHA256:abc123...",
  "key_secret": "PROD_KEY"
}
```

`key_secret` names a Worker Secret that holds the SSH private key. The key itself never
goes into KV -- only the secret name does.

**New tool parameter (all SSH tools):**
```js
host_alias: {
  type: 'string',
  description: 'Named host alias configured in the Worker. Overrides host/user/key/fingerprint.',
}
```

**Lookup in tools.js:**
```js
if (args.host_alias) {
  const record = await env.HOSTS.get(args.host_alias, { type: 'json' });
  if (!record) throw new Error(`Unknown host alias: ${args.host_alias}`);
  args = {
    ...args,
    host:        record.host,
    port:        record.port ?? 22,
    user:        record.user,
    fingerprint: record.fingerprint,
    key:         env[record.key_secret],
  };
}
```

**Alias management:** a small admin sub-path (`POST /admin/hosts`, `DELETE /admin/hosts/:name`,
`GET /admin/hosts`) protected by a separate bearer token (`ADMIN_TOKEN` secret). Operators
manage aliases via curl; agents only read them implicitly via `host_alias`.

**New tool: `list_aliases`** -- lists available alias names (not their contents) so agents
can discover what's configured without needing to know hostnames.

### Things to watch out for

- KV is included on the Free plan (100,000 reads/day, 1,000 writes/day, 1 GB stored). No upgrade required.
- `env[record.key_secret]` only works for secrets the Worker was deployed with. Adding a
  new alias requires a new secret + redeployment. This is the main ergonomic downside.
  Alternative: store encrypted keys in KV using the Worker-pubkey scheme above (features
  compose nicely).
- The admin endpoint must be auth-gated. A leaked `ADMIN_TOKEN` lets an attacker point
  aliases at their own servers (MITM via fingerprint bypass). Fingerprints are mandatory
  on alias records -- reject alias creation without one.
- `list_aliases` should return names only, never the `key_secret` field.
- Consider a read-through cache (in-memory, per isolate) since KV reads add ~50 ms. The
  Worker already has a 20 s SSH timeout so it's not critical, but it's free to add.

---

## 3. Zero-credential agent mode

### Motivation

The current design is a general-purpose gateway: callers supply their own SSH key on every
request, so one deployed Worker can reach any host any caller has credentials for. That
flexibility is the point for personal use or multi-agent setups.

But some teams want the opposite: a locked-down internal tool where the Worker is
pre-configured for a fixed set of hosts, agents pass *no* credentials whatsoever, and the
SSH keys never leave the operator's Cloudflare account. An intern can use the MCP server to
run deployments without ever seeing a private key.

### How it would work

**Deployment-time setup (operator, done once):**
```bash
# One secret per target host, named by convention
wrangler secret put SSH_KEY_PROD       # paste prod private key
wrangler secret put SSH_KEY_STAGING    # paste staging private key
```

**Static host table in wrangler.toml (or a KV record, see item 2):**
```toml
[vars]
HOSTS_JSON = '''
{
  "prod":    { "host": "prod.example.com",    "user": "deploy", "key_secret": "SSH_KEY_PROD",    "fingerprint": "SHA256:..." },
  "staging": { "host": "staging.example.com", "user": "deploy", "key_secret": "SSH_KEY_STAGING", "fingerprint": "SHA256:..." }
}
'''
```

**Call style (agent supplies no credentials):**
```json
{ "name": "exec", "arguments": { "host_alias": "prod", "cmd": "systemctl status myapp" } }
```

The Worker resolves `host_alias` to `{ host, user, fingerprint }` from `HOSTS_JSON` and
`key_secret` to the actual key from `env[record.key_secret]`. The agent sees the command
output; it never sees a hostname, username, or key.

**If the caller supplies `host` or `key` directly and this mode is active,** the Worker
can either reject it (strict mode -- good for compliance) or allow it (permissive mode,
backward compat). A `STRICT_MODE=true` var makes this configurable at deploy time.

### Relationship to items 1 and 2

This is item 2 (named aliases) minus the admin API plus item 1 (keys never in LLM context)
as the mandatory default, simplified for a static deployment. The three features compose:

| Feature | Key in LLM context? | Dynamic hosts? | Requires KV? |
|---------|--------------------|--------------------|--------------|
| Current | Yes | Yes (any) | No |
| Item 1 (encrypted key) | No (ciphertext only) | Yes (any) | No |
| Item 2 (named aliases) | No | Yes (KV-defined) | Yes |
| Item 3 (Worker-stored keys) | No | No (deploy-time only) | Optional |

For most operator deployments, item 3 is the right answer. Items 1 and 2 are for power
users who need flexibility.

### Things to watch out for

- Adding a new target host requires a new secret + redeployment. This is intentional --
  it is a feature, not a bug, for compliance-sensitive environments.
- The `HOSTS_JSON` var approach has a size limit (5 KB per variable). The real constraint is
  the variable count: 64 total on Free, 128 on Paid — secrets included, so one-secret-per-host
  caps the number of targets. For more hosts, use KV instead (item 2 can store the same
  records without changing the `key_secret` lookup).
- Never expose the host table via a public endpoint. `list_aliases` (from item 2) should
  return alias names only, no hostnames or user names, even in this mode.
- In strict mode, log (to `wrangler tail`, not to a persistent store) each rejected
  direct-credential call so operators can audit misuse attempts.

---

## Non-goals (explicitly out of scope)

- **Web console / UI** -- the target user is an LLM calling tools, not a human browsing a dashboard.
- **Multi-hop / jump hosts** -- the current architecture does one TCP connection per call; ProxyJump would require two concurrent CF sockets plus a local-forward pipe. Complex and rarely needed.
- **WebSocket keepalive sessions** -- stateless is a feature; persistent sessions add failure modes (Worker restart, session loss) with modest benefit given the 20 s timeout.
