'use strict';
// Uses the selected runtime's default HTTPS/fetch trust and process environment.
const [mode, url, seconds] = process.argv.slice(-3);
const timeout = Math.max(1000, Number(seconds) * 1000);
const emit = obj => console.log('EMUDHRA_JSON:' + JSON.stringify(obj));
function error(e) {
  const seen = new Set(); const parts = [];
  while (e && !seen.has(e)) {
    seen.add(e); parts.push(String(e.code || e.name || 'Error') + ': ' + String(e.message || e)); e = e.cause;
  }
  return parts.join(' | ');
}
if (mode === 'meta') {
  emit({state:'meta', data:{version:process.version, executable:process.execPath, openssl:process.versions.openssl,
    extraCaSet:!!process.env.NODE_EXTRA_CA_CERTS, nodeOptionsSet:!!process.env.NODE_OPTIONS,
    validationDisabled:process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0',
    envProxyEnabled:process.env.NODE_USE_ENV_PROXY === '1'}});
} else if (mode === 'fetch') {
  if (typeof fetch !== 'function') emit({state:'skipped', detail:'built-in fetch unavailable', optional_missing:true});
  else {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeout);
    fetch(url, {redirect:'manual', signal:controller.signal}).then(async response => {
      emit({state:'accepted', detail:'HTTP ' + response.status});
      if (response.body) await response.body.cancel();
    }).catch(e => emit({state:'error', detail:error(e)})).finally(() => clearTimeout(timer));
  }
} else {
  const https = require('https'); let done = false;
  const finish = x => { if (!done) { done = true; emit(x); clearTimeout(timer); }};
  const request = https.get(url, response => {
    finish({state:'accepted', detail:'HTTP ' + response.statusCode}); response.destroy();
  });
  const timer = setTimeout(() => request.destroy(new Error('TIMEOUT')), timeout);
  request.on('error', e => finish({state:'error', detail:error(e)}));
}
