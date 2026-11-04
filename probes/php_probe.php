<?php
// Default PHP/OpenSSL stream trust; response bodies are never consumed.
$url = $argv[count($argv)-2]; $timeout = (float)$argv[count($argv)-1];
$warnings = [];
// Preserve all warnings; the first generic warning does not identify the trust cause.
set_error_handler(function($n,$s) use (&$warnings) { $warnings[] = $s; return true; });
$context = stream_context_create([
  'http'=>['timeout'=>$timeout,'follow_location'=>0,'ignore_errors'=>true]
]);
try {
  $f = fopen($url, 'r', false, $context);
  if ($f === false) throw new Exception('stream could not be opened');
  fclose($f);
  echo 'EMUDHRA_JSON:'.json_encode(['state'=>'accepted','detail'=>'HTTPS response received'])."\n";
} catch (Throwable $e) {
  echo 'EMUDHRA_JSON:'.json_encode([
    'state'=>'unknown',
    'detail'=>'PHP stream: cause cannot be isolated; '.implode('; ', $warnings).'; '.$e->getMessage(),
    'openssl_version'=>OPENSSL_VERSION_TEXT, 'ca_locations'=>openssl_get_cert_locations()
  ])."\n";
}
restore_error_handler();
