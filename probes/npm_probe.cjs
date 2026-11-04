'use strict';
// npm's installed configuration loader and HTTP transport; no install or npm lifecycle.
const path = require('node:path');
const fs = require('node:fs');
const [root, mode, url, seconds] = process.argv.slice(-4);
const emit = data => console.log('EMUDHRA_JSON:' + JSON.stringify(data));
async function main() {
  const Config = require(path.join(root, 'node_modules/@npmcli/config'));
  const {definitions, shorthands, flatten} = require(path.join(root, 'node_modules/@npmcli/config/lib/definitions'));
  const config = new Config({npmPath: root, definitions, shorthands, flatten,
    argv: [process.execPath, path.join(root, 'bin/npm-cli.js')], cwd: process.cwd()});
  await config.load();
  const flat = config.flat;
  const target = new URL(url === '-' ? 'https://example.com/' : url);
  const scope = '//' + target.host + target.pathname;
  const identity = !!(flat.cert || flat.key || Object.keys(flat).some(key => {
    const match = key.match(/^(\/\/.*\/):(certfile|keyfile)$/);
    return match && scope.startsWith(match[1]) && flat[key];
  }));
  const meta = {version: require(path.join(root, 'package.json')).version,
    strictSSL: flat.strictSSL !== false, cafileSet: !!config.get('cafile'), clientIdentity: identity};
  if (mode === 'meta') { emit({state: 'meta', data: meta}); return; }
  if (target.protocol !== 'https:' || target.username || target.password) {
    emit({state: 'skipped', detail: 'HTTPS URL without credentials required'}); return;
  }
  if (!meta.strictSSL || identity) {
    emit({state: 'skipped', detail: 'npm TLS validation disabled or client certificate configured; active test withheld'}); return;
  }
  if (config.get('cafile') && !fs.existsSync(config.get('cafile'))) {
    emit({state: 'unknown', detail: 'npm cafile is missing'}); return;
  }
  // Allowlist TLS/proxy options. Never pass registry tokens, cookies or client keys.
  const options = {};
  for (const key of ['ca', 'strictSSL', 'proxy', 'httpsProxy', 'noProxy', 'localAddress']) {
    if (flat[key] !== undefined) options[key] = flat[key];
  }
  options.proxy = flat.httpsProxy || flat.proxy;
  if (options.proxy) {
    try {
      const configuredProxy = new URL(options.proxy);
      if (configuredProxy.username || configuredProxy.password || !configuredProxy.hostname) {
        emit({state: 'skipped', detail: 'Authenticated or invalid proxy; active test withheld'}); return;
      }
    } catch (_) {
      emit({state: 'skipped', detail: 'Proxy cannot be safely checked; active test withheld'}); return;
    }
  }
  Object.assign(options, {method: 'GET', redirect: 'error', cache: 'no-store',
    retry: {retries: 0}, timeout: Number(seconds) * 1000,
    headers: {'user-agent': 'emudhra-dev-audit/2'}});
  const fetch = require(path.join(root, 'node_modules/make-fetch-happen'));
  try {
    const response = await fetch(url, options);
    emit({state: 'accepted', detail: 'npm HTTP transport: HTTP ' + response.status});
    if (response.body) response.body.destroy();
  } catch (error) {
    // Codes contain the verification reason; raw messages may contain proxy secrets.
    const codes = []; const seen = new Set();
    for (let e = error; e && !seen.has(e); e = e.cause) {
      seen.add(e); codes.push(String(e.code || e.name || 'Error'));
    }
    emit({state: 'error', detail: 'npm HTTP transport: ' + codes.join(' | ')});
  }
}
main().catch(() => emit({state: 'unknown', detail: 'Installed npm configuration/transport API unavailable'}));
