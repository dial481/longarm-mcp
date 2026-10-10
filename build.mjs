/**
 * Custom esbuild step for Cloudflare Workers + ssh2.
 *
 * The fundamental challenge: ssh2 is CJS and calls require('stream'),
 * require('crypto'), etc. inside functions. esbuild converts those to
 * __require2() calls in the bundle, but CF Workers ESM context has no
 * require() function — so the Worker crashes on startup.
 *
 * Fix strategy:
 *
 * 1. BANNER: prepend static ESM import declarations to the top of the output
 *    file. CF Workers resolves `node:*` at runtime via nodejs_compat.
 *    These imports are stored in globalThis.__cf_compat (default exports,
 *    i.e. the main module value just like Node's require() returns) and
 *    globalThis.__cf_compat_ns (namespace objects, all named exports).
 *
 * 2. PLUGIN: intercept every bare Node module name (stream, events, …).
 *    Instead of a virtual ESM module (which causes esbuild's CJS interop to
 *    wrap the value in { default: X } before handing it to __require2),
 *    generate a plain CJS module: `module.exports = globalThis.__cf_compat[m]`.
 *    esbuild's __require2 returns module.exports DIRECTLY — no namespace
 *    wrapper. So `require('events')` hands CJS code the EventEmitter class,
 *    exactly as Node.js does.
 *
 *    We also merge the namespace properties onto the default export so that
 *    both `require('stream').Readable` and destructuring work:
 *      const { Readable } = require('stream')  ← Readable from namespace
 *      class X extends require('stream')        ← Stream class from default
 *
 * 3. UNSUPPORTED: net, fs, http, … use a .cjs Proxy stub so imports succeed
 *    at load time and throw only if the code path is actually reached (it
 *    won't be for our exec/SFTP use case).
 */

import { build } from 'esbuild';
import { mkdirSync } from 'fs';

mkdirSync('dist', { recursive: true });

// Built-ins provided by CF Workers nodejs_compat (resolves via node: prefix)
const CF_COMPAT = [
  'assert', 'async_hooks', 'buffer', 'crypto', 'diagnostics_channel',
  'events', 'path', 'process', 'stream', 'string_decoder', 'url', 'util', 'zlib',
];
const compatRE = new RegExp(`^(${CF_COMPAT.join('|')})$`);

// Module name → safe JS identifier for banner variables
const toVar = m => `__cfn_${m.replace(/[^a-z0-9]/g, '_')}`;

// Banner prepended verbatim to dist/worker.js after bundling.
// All import declarations come before any executable code, so they are
// valid ESM syntax. CF Workers resolves node:* at startup via nodejs_compat.
const banner = [
  // Default imports — the primary export value (e.g. EventEmitter for events)
  ...CF_COMPAT.map(m => `import ${toVar(m)} from 'node:${m}';`),
  // Namespace imports — all named exports (e.g. Readable, Writable for stream)
  ...CF_COMPAT.map(m => `import * as ${toVar(m)}_ns from 'node:${m}';`),
  // Store in globalThis so the CJS shim wrappers below can read at require()-time
  `if (!globalThis.__cf_compat) {`,
  `  globalThis.__cf_compat    = { ${CF_COMPAT.map(m => `'${m}':${toVar(m)}`).join(', ')} };`,
  `  globalThis.__cf_compat_ns = { ${CF_COMPAT.map(m => `'${m}':${toVar(m)}_ns`).join(', ')} };`,
  `}`,
].join('\n');

await build({
  entryPoints: ['src/index.js'],
  bundle: true,
  outfile: 'dist/worker.js',
  format: 'esm',
  target: 'esnext',

  // Prepend static CF_COMPAT imports before the bundle body
  banner: { js: banner },

  // Native binaries → empty module so ssh2 falls back to pure-JS crypto
  loader: { '.node': 'empty' },

  // CF-specific and node:-prefixed imports stay external (resolved at runtime)
  external: ['cloudflare:sockets', 'node:*'],

  // CJS globals not available in ESM / CF Workers
  define: {
    '__dirname':  '"/"',
    '__filename': '"/index.js"',
  },

  // Modules NOT in nodejs_compat — CJS Proxy stub (import succeeds, call throws).
  // Must be .cjs so esbuild's require() returns the Proxy directly rather than
  // wrapping it in an ESM namespace object { default: Proxy }.
  alias: {
    'net':           './src/shims/cf-unsupported.cjs',
    'fs':            './src/shims/cf-unsupported.cjs',
    'http':          './src/shims/cf-unsupported.cjs',
    'https':         './src/shims/cf-unsupported.cjs',
    'dns':           './src/shims/cf-unsupported.cjs',
    'child_process': './src/shims/cf-unsupported.cjs',
    'os':            './src/shims/cf-unsupported.cjs',
    'tls':           './src/shims/cf-unsupported.cjs',
  },

  plugins: [{
    name: 'cf-node-compat',
    setup(b) {
      b.onResolve({ filter: compatRE }, args => ({
        path: args.path,
        namespace: 'cf-node-shim',
      }));

      // Generate a plain CJS module for each CF_COMPAT module.
      // - The default export (globalThis.__cf_compat[m]) matches what Node's
      //   require() returns: the main value (EventEmitter class, Stream class, …).
      // - We also merge the namespace (all named exports) onto that value so
      //   patterns like `require('stream').Readable` and `const {Readable} =
      //   require('stream')` both work, even if the default doesn't expose them.
      b.onLoad({ filter: /.*/, namespace: 'cf-node-shim' }, args => ({
        contents: `
var __def = globalThis.__cf_compat    && globalThis.__cf_compat['${args.path}'];
var __ns  = globalThis.__cf_compat_ns && globalThis.__cf_compat_ns['${args.path}'];
if (__def !== undefined && __ns) {
  try { Object.assign(__def, __ns); } catch (_) {}
}
module.exports = __def !== undefined ? __def : (__ns || {});
`.trim(),
        loader: 'js',
        resolveDir: '.',
      }));
    },
  }],
});

console.log('✓ dist/worker.js ready');
