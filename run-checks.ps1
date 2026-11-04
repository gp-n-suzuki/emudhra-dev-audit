#requires -Version 5.1
# No administrator rights or policy changes are requested.
$ErrorActionPreference = 'Continue'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) { $PSNativeCommandUseErrorActionPreference = $false }
$entry = Join-Path $PSScriptRoot 'audit.py'
$forward = $args
$bundled = Join-Path $PSScriptRoot 'runtime\python.exe'
if (Test-Path -LiteralPath $bundled -PathType Leaf) {
  & $bundled -E -s -B $entry @forward
  if ($null -eq $LASTEXITCODE) { exit 2 }
  exit $LASTEXITCODE
}
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'RUNTIME.json')) {
  Write-Error 'The bundled Python is missing. Extract the complete Windows package again; see START-HERE-ja.md.'
  exit 2
}
if (Get-Command py.exe -ErrorAction SilentlyContinue) {
  & py.exe -3 -c 'import sys;sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>$null
  if ($LASTEXITCODE -eq 0) { & py.exe -3 -E -s -B $entry @forward; exit $LASTEXITCODE }
}
foreach ($candidate in @('python.exe','python3.exe')) {
  $cmd = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($cmd) {
    & $cmd.Source -c 'import sys;sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>$null
    if ($LASTEXITCODE -eq 0) { & $cmd.Source -E -s -B $entry @forward; exit $LASTEXITCODE }
  }
}
Write-Host 'Python 3.8+ is required for the CLI controller; nothing was installed.'
exit 2
