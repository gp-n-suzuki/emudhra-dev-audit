// Standard fetch only: no imports, dependency downloads, credentials, or redirects.
const args = typeof Deno !== 'undefined' ? Deno.args : process.argv.slice(2);
const [url, seconds] = args;
const emit = value => console.log('EMUDHRA_JSON:' + JSON.stringify(value));
const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), Number(seconds) * 1000);
try {
  const response = await fetch(url, { redirect: 'manual', credentials: 'omit', signal: controller.signal });
  emit({state: 'accepted', detail: 'HTTP ' + response.status});
  if (response.body) await response.body.cancel();
} catch (error) {
  const seen = new Set(), reasons = [];
  while (error && !seen.has(error)) {
    seen.add(error); reasons.push(String(error.code || error.name || 'Error') + ': ' + String(error.message || error));
    error = error.cause;
  }
  emit({state: 'error', detail: reasons.join(' | ')});
} finally { clearTimeout(timer); }
