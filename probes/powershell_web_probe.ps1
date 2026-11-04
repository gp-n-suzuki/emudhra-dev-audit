param([string]$Url,[double]$Seconds = 8)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
  $options = @{Uri=$Url; Method='Head'; UseBasicParsing=$true; MaximumRedirection=0; TimeoutSec=[int]$Seconds; ErrorAction='Stop'}
  $response = Invoke-WebRequest @options
  $result = @{state='accepted'; detail=('HTTP ' + [int]$response.StatusCode)}
} catch {
  $response = $_.Exception.Response
  $status = 0
  try { if ($response) { $status = [int]$response.StatusCode } } catch { $status = 0 }
  if ($status -ge 100 -and $status -le 599 -and $status -ne 407) {
    $result = @{state='accepted'; detail=('HTTP ' + $status)}
  } else {
    $messages = @(); $e = $_.Exception
    for ($i=0; $e -and $i -lt 8; $i++) { $messages += ($e.GetType().FullName + ': ' + $e.Message); $e = $e.InnerException }
    $result = @{state='error';detail=($messages -join ' | ')}
  }
}
'EMUDHRA_JSON:' + ($result | ConvertTo-Json -Compress)
