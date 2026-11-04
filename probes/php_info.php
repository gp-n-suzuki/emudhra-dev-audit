<?php
// Only public TLS configuration; never dump phpinfo() or the process environment.
echo json_encode([
  'php' => PHP_VERSION,
  'openssl' => defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : 'unavailable',
  'locations' => function_exists('openssl_get_cert_locations') ? openssl_get_cert_locations() : []
]);
