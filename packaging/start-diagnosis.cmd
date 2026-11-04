@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
if not exist "%~dp0app\runtime\python.exe" goto missing
"%~dp0app\runtime\python.exe" -E -s -B "%~dp0app\desktop_entry.py"
set "diagnosis_exit=%ERRORLEVEL%"
if not "%diagnosis_exit%"=="0" pause
exit /b %diagnosis_exit%
:missing
echo 診断を開始できませんでした。appフォルダーを含めて、配布ファイルをすべて展開し直してください。
pause
exit /b 3
