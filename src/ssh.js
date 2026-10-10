/**
 * SSH tools — exec, read_file, write_file, list_dir
 *
 * Uses cloudflare:sockets for raw TCP (port 22) and ssh2 for the SSH
 * protocol layer. The key bridge: ssh2's connect() accepts a pre-built
 * `sock` duplex, so we never call net.Socket() — we hand it our own
 * Cloudflare TCP socket wrapped as a Node.js Duplex stream.
 *
 * Requires: nodejs_compat flag in wrangler.toml (provides crypto + stream)
 */

import { connect } from 'cloudflare:sockets';
import { Client } from 'ssh2';
import { Duplex } from 'stream';

const SSH_TIMEOUT_MS = 20_000;

/**
 * Bridge a Cloudflare TCP socket (WHATWG streams) to a Node.js Duplex.
 * ssh2 expects a Node.js-style stream; cloudflare:sockets gives us
 * ReadableStream / WritableStream.
 */
function cfSocketToDuplex(cfSocket) {
  const reader = cfSocket.readable.getReader();
  const writer = cfSocket.writable.getWriter();
  let reading = false;

  const duplex = new Duplex({
    // Called by Node.js internals when the consumer wants more data
    read() {
      if (reading) return;
      reading = true;

      const pump = () => {
        reader.read()
          .then(({ done, value }) => {
            if (done) {
              duplex.push(null);
              reading = false;
              return;
            }
            // push() returns false when the internal buffer is full —
            // stop pumping and wait for the next _read() call
            const keepGoing = duplex.push(Buffer.from(value));
            if (keepGoing) {
              pump();
            } else {
              reading = false;
            }
          })
          .catch(err => {
            reading = false;
            if (!duplex.destroyed) duplex.destroy(err);
          });
      };

      pump();
    },

    write(chunk, encoding, callback) {
      const data = chunk instanceof Uint8Array
        ? chunk
        : Buffer.from(chunk, encoding);
      writer.write(data).then(() => callback()).catch(callback);
    },

    final(callback) {
      writer.close().then(() => callback()).catch(callback);
    },

    destroy(err, callback) {
      cfSocket.close().catch(() => {}).finally(() => callback(err));
    },
  });

  // Propagate unexpected close from the CF socket
  cfSocket.closed
    .then(() => { if (!duplex.destroyed) duplex.push(null); })
    .catch(err => { if (!duplex.destroyed) duplex.destroy(err); });

  return duplex;
}

/**
 * Open an SSH Client connected to host:port via cloudflare:sockets.
 * Returns the ready Client; caller must call client.end() when done.
 *
 * @param {string} [fingerprint] - Expected host key fingerprint in
 *   "SHA256:..." format (from `ssh-keygen -lf /etc/ssh/ssh_host_*.pub`).
 *   If omitted, the host key is accepted without verification on every call.
 */
function openSSH({ host, port = 22, user, key, fingerprint, passphrase }) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`SSH connect timeout after ${SSH_TIMEOUT_MS}ms`)),
      SSH_TIMEOUT_MS
    );

    let cfSocket;
    try {
      cfSocket = connect({ hostname: host, port }, { secureTransport: 'off' });
    } catch (err) {
      clearTimeout(timer);
      return reject(new Error(`TCP connect failed: ${err.message}`));
    }

    const sock = cfSocketToDuplex(cfSocket);
    const client = new Client();

    // Capture negotiated algorithms so we can include them in error messages.
    // ssh2 emits 'handshake' with the chosen kex/cipher/hmac before 'ready'.
    client.on('handshake', (info) => {
      client._negotiated = info;
    });

    client.on('ready', () => {
      clearTimeout(timer);
      resolve(client);
    });

    client.on('error', err => {
      clearTimeout(timer);
      const neg = client._negotiated;
      const detail = neg
        ? ` [negotiated cs.cipher=${neg.cs?.cipher} sc.cipher=${neg.sc?.cipher}]`
        : ' [handshake not completed]';
      err.message += detail;
      reject(err);
    });

    client.connect({
      sock,           // pre-connected — never calls net.Socket()
      username: user,
      privateKey: key,
      passphrase: passphrase || undefined,
      readyTimeout: SSH_TIMEOUT_MS,
      // Host key verification. If a fingerprint is supplied, reject any server
      // whose SHA-256 host key fingerprint doesn't match — prevents MITM on
      // BGP/DNS-spoofed routes. Without a fingerprint, keys are accepted
      // unconditionally on every call — the Worker stores nothing between
      // requests.
      // Get the fingerprint with: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
      hostHash: fingerprint ? 'sha256' : undefined,
      hostVerifier: fingerprint
        ? (hashedKey) => {
            // ssh2 passes hashedKey as a hex digest string.
            // Decode to raw bytes first, then base64 — matching OpenSSH fingerprint format.
            const received = 'SHA256:' + Buffer.from(hashedKey, 'hex')
              .toString('base64')
              .replace(/=+$/, '');
            // Normalise the caller's fingerprint: strip any trailing = padding
            // (some tools include it; ssh-keygen -lf does not).
            const expected = fingerprint.replace(/=+$/, '');
            if (received !== expected) {
              clearTimeout(timer);
              reject(new Error(
                `Host key fingerprint mismatch — expected ${expected}, got ${received}`
              ));
              return false;
            }
            return true;
          }
        : undefined,
      // Broad algorithm list for maximum target compatibility.
      // curve25519 / X25519 excluded: CF Workers' node:crypto does not
      // implement the diffieHellman() path ssh2 uses for X25519 key exchange.
      // ECDH-NIST and classic DH work correctly and are supported by all
      // modern sshd versions (OpenSSH 5.7+).
      algorithms: {
        kex: [
          'ecdh-sha2-nistp256',
          'ecdh-sha2-nistp384',
          'diffie-hellman-group14-sha256',
          'diffie-hellman-group14-sha1',
        ],
        // AES-GCM excluded: CF Workers' node:crypto does not implement
        // the AEAD authentication tag path ssh2 uses for GCM ciphers.
        // CTR + HMAC works correctly and is supported by all modern sshd.
        cipher: [
          'aes128-ctr',
          'aes192-ctr',
          'aes256-ctr',
        ],
        serverHostKey: [
          'ssh-ed25519',
          'ecdsa-sha2-nistp256',
          'rsa-sha2-512',
          'rsa-sha2-256',
          'ssh-rsa',
        ],
        hmac: ['hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'],
      },
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Annotate an error with the negotiated SSH cipher so it appears in the
 * JSON-RPC error message and in wrangler tail output.
 */
function annotate(err, client) {
  const neg = client?._negotiated;
  if (neg) {
    err.message += ` [cs.cipher=${neg.cs?.cipher} sc.cipher=${neg.sc?.cipher}]`;
  }
  return err;
}

// ---------------------------------------------------------------------------
// Public tool implementations
// ---------------------------------------------------------------------------

/**
 * exec — run a shell command, return { stdout, stderr, exitCode }
 */
export async function execSSH({ host, port, user, key, fingerprint, passphrase, cmd, cwd }) {
  const client = await openSSH({ host, port, user, key, fingerprint, passphrase });
  // Single-quote the cwd to prevent shell expansion ($(...), backticks, etc.)
  const fullCmd = cwd ? `cd '${cwd.replace(/'/g, "'\\''")}' && ${cmd}` : cmd;

  return new Promise((resolve, reject) => {
    client.exec(fullCmd, (err, stream) => {
      if (err) { client.end(); return reject(annotate(err, client)); }

      stream.end(); // close stdin — prevents interactive prompts from hanging

      // Collect chunks as Buffers, decode once at the end.
      // String concatenation (stdout += chunk) decodes each chunk independently,
      // corrupting multi-byte UTF-8 characters split across chunk boundaries.
      const stdoutChunks = [];
      const stderrChunks = [];

      stream.on('data', chunk => {
        stdoutChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });
      stream.stderr.on('data', chunk => {
        stderrChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });

      stream.on('close', (code, signal) => {
        client.end();
        const stdout = Buffer.concat(stdoutChunks).toString('utf8');
        const stderr = Buffer.concat(stderrChunks).toString('utf8');
        resolve({ stdout, stderr, exitCode: code, signal: signal || undefined });
      });

      stream.on('error', err => { client.end(); reject(annotate(err, client)); });
    });
  });
}

/**
 * read_file — read a remote file via SFTP
 *
 * @param {string} [encoding='text'] - 'text' returns UTF-8 string;
 *   'base64' returns raw bytes as base64 (for binary files).
 */
export async function readFileSSH({ host, port, user, key, fingerprint, passphrase, path, encoding = 'text' }) {
  const client = await openSSH({ host, port, user, key, fingerprint, passphrase });

  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) { client.end(); return reject(annotate(err, client)); }

      if (encoding === 'base64') {
        sftp.readFile(path, (err, data) => {
          client.end();
          err ? reject(annotate(err, client)) : resolve(data.toString('base64'));
        });
      } else {
        sftp.readFile(path, 'utf8', (err, data) => {
          client.end();
          err ? reject(annotate(err, client)) : resolve(data);
        });
      }
    });
  });
}

/**
 * write_file — write content to a remote file via SFTP
 */
export async function writeFileSSH({ host, port, user, key, fingerprint, passphrase, path, content }) {
  const client = await openSSH({ host, port, user, key, fingerprint, passphrase });

  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) { client.end(); return reject(annotate(err, client)); }

      sftp.writeFile(path, content, (err) => {
        client.end();
        err ? reject(annotate(err, client)) : resolve();
      });
    });
  });
}

/**
 * list_dir — list a remote directory via SFTP
 * Returns array of strings: "d dirname" or "- filename (size bytes)"
 */
export async function listDirSSH({ host, port, user, key, fingerprint, passphrase, path }) {
  const client = await openSSH({ host, port, user, key, fingerprint, passphrase });

  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => {
      if (err) { client.end(); return reject(annotate(err, client)); }

      sftp.readdir(path, (err, list) => {
        client.end();
        if (err) return reject(annotate(err, client));

        const entries = list.map(entry => {
          const isDir = entry.attrs.mode
            ? (entry.attrs.mode & 0o170000) === 0o040000
            : false;
          const type = isDir ? 'd' : '-';
          const size = isDir ? '' : ` (${entry.attrs.size} bytes)`;
          return `${type} ${entry.filename}${size}`;
        });

        // Dirs first, then files, both alphabetical
        entries.sort((a, b) => {
          if (a[0] !== b[0]) return a[0] === 'd' ? -1 : 1;
          return a.localeCompare(b);
        });

        resolve(entries);
      });
    });
  });
}
