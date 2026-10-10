/**
 * Stub for Node.js modules not available in Cloudflare Workers.
 *
 * MUST be CommonJS (.cjs) so that esbuild's CJS→CJS require() path returns
 * this Proxy directly. If this were an ESM file (export default ...), esbuild's
 * ESM→CJS interop would wrap it in a namespace object { default: Proxy }, and
 * then `http.Agent` would resolve to undefined, breaking class-extends.
 *
 * ssh2 imports net, fs, http, https, dns, and child_process at the top level
 * for SSH-agent socket connections, HTTP proxy support, and local filesystem
 * operations — none of which we use. These imports fail at Worker startup
 * because nodejs_compat doesn't provide them.
 *
 * This Proxy stub lets the imports succeed at module load time. If any of
 * those code paths were ever actually reached, the call would throw a clear
 * error. In our exec/SFTP use case, they are never reached.
 */
module.exports = new Proxy(
  {},
  {
    get(_, prop) {
      if (typeof prop === 'symbol') return undefined;
      // Return a class-like constructor AND a callable function in one object
      return new Proxy(function cf_stub() {
        throw new Error(`cf-unsupported: "${prop}" is not available in CF Workers`);
      }, {
        get(fn, subprop) {
          if (typeof subprop === 'symbol') return fn[subprop];
          return function() {
            throw new Error(`cf-unsupported: "${prop}.${subprop}" is not available in CF Workers`);
          };
        },
        construct() {
          throw new Error(`cf-unsupported: "new ${prop}()" is not available in CF Workers`);
        },
      });
    },
  }
);
