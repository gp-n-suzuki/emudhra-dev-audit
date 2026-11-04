param([string]$Url,[double]$Seconds = 8)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
  Add-Type -AssemblyName System.Net.Http
  $handler = New-Object System.Net.Http.HttpClientHandler
  $handler.AllowAutoRedirect = $false
  $handler.UseDefaultCredentials = $false
  $client = New-Object System.Net.Http.HttpClient($handler)
  $client.Timeout = [TimeSpan]::FromSeconds($Seconds)
  try {
    $r = $client.GetAsync($Url,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    $result = @{state='accepted'; detail=('HTTP ' + [int]$r.StatusCode)}
    $r.Dispose()
  } finally { $client.Dispose() }
} catch {
  $messages = @(); $e = $_.Exception
  for ($i=0; $e -and $i -lt 8; $i++) { $messages += ($e.GetType().FullName + ': ' + $e.Message); $e = $e.InnerException }
  $result = @{state='error';detail=($messages -join ' | ')}
}
'EMUDHRA_JSON:' + ($result | ConvertTo-Json -Compress)
