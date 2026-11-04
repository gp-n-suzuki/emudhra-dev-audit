@echo off
setlocal
if not exist "%~dp0runtime\python.exe" (
  echo The bundled Python is missing. Extract the complete Windows package again. 1>&2
  echo See the usage guide in docs. 1>&2
  exit /b 2
)
"%~dp0runtime\python.exe" -E -s -B "%~dp0audit.py" %*
exit /b %ERRORLEVEL%
