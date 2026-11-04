<?php
// Separate from PHP streams: use curl's numeric OpenSSL verification result.
$url = $argv[count($argv)-2]; $seconds = (float)$argv[count($argv)-1];
function emit_result($data) { echo 'EMUDHRA_JSON:'.json_encode($data)."\n"; }
if (!extension_loaded('curl')) {
  emit_result(['state'=>'skipped','detail'=>'PHP curl extension unavailable','optional_missing'=>true]); exit;
}
if (parse_url($url, PHP_URL_SCHEME) !== 'https' || parse_url($url, PHP_URL_USER) !== null) {
  emit_result(['state'=>'skipped','detail'=>'HTTPS URL without credentials required']); exit;
}
$handle = curl_init($url);
$cafile = ini_get('curl.cainfo');
if ($cafile !== false && $cafile !== '') curl_setopt($handle, CURLOPT_CAINFO, $cafile);
curl_setopt_array($handle, [CURLOPT_NOBODY=>true, CURLOPT_FOLLOWLOCATION=>false,
  CURLOPT_RETURNTRANSFER=>true, CURLOPT_NETRC=>CURL_NETRC_IGNORED,
  CURLOPT_CONNECTTIMEOUT_MS=>(int)($seconds*1000), CURLOPT_TIMEOUT_MS=>(int)($seconds*1000)]);
$ok = curl_exec($handle); $errno = curl_errno($handle);
$verify = curl_getinfo($handle, CURLINFO_SSL_VERIFYRESULT);
$http = curl_getinfo($handle, CURLINFO_HTTP_CODE);
$backend = curl_version()['ssl_version'];
curl_close($handle);
if ($ok !== false) {
  emit_result(['state'=>'accepted','detail'=>'PHP curl: HTTP '.$http]); exit;
}
$reasons = [2=>'unable to get issuer certificate', 18=>'self-signed certificate',
  19=>'self-signed certificate in certificate chain', 20=>'unable to get local issuer certificate',
  21=>'unable to verify leaf signature', 23=>'certificate revoked',
  27=>'certificate not trusted', 28=>'certificate is blocked'];
// Expiry, hostname, purpose and proxy errors never become a trust rejection here.
if ($errno === 60 && strpos($backend, 'OpenSSL/') === 0 && isset($reasons[$verify])) {
  emit_result(['state'=>'error','detail'=>'PHP curl / OpenSSL verify='.$verify.': '.$reasons[$verify]]);
} else {
  emit_result(['state'=>'unknown','detail'=>'PHP curl: errno='.$errno.'; verify='.$verify.'; backend='.$backend]);
}
