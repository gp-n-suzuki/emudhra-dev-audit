'use strict';
function makeCommand(os, scope, project, offline, bundled = false) {
  if (!['windows', 'mac', 'linux'].includes(os)) throw new Error('OSを選んでください。');
  if (!['project', 'host'].includes(scope)) throw new Error('検査対象を選んでください。');
  if (scope === 'project' && !project.trim()) throw new Error('プロジェクトのフォルダーを入力してください。');
  if (scope === 'project' && /[\x00-\x1f\x7f]/.test(project)) throw new Error('フォルダーのパスに改行や制御文字は使えません。');
  const quote = os === 'windows'
    ? value => "'" + value.replace(/'/g, "''") + "'"
    : value => "'" + value.replace(/'/g, "'\"'\"'") + "'";
  // Direct invocation avoids a second round of cmd.exe expansion for Windows paths.
  const launcher = os === 'windows'
    ? (bundled ? "& '.\\app\\runtime\\python.exe' -E -s -B '.\\app\\audit.py'" : "& '.\\runtime\\python.exe' -E -s -B '.\\audit.py'")
    : (bundled ? "bash './app/run-checks.sh'" : "bash './run-checks.sh'");
  return launcher + (scope === 'project' ? ' --project ' + quote(project) : ' --host-only') + (offline ? ' --offline' : '');
}
if (typeof module !== 'undefined') module.exports = {makeCommand};
if (typeof document !== 'undefined') {
  const form = document.getElementById('setup');
  const os = document.getElementById('os');
  const project = document.getElementById('project');
  const command = document.getElementById('command');
  const copy = document.getElementById('copy');
  const message = document.getElementById('command-status');
  const platform = navigator.platform || '';
  os.value = form.dataset?.platform || (/Win/.test(platform) ? 'windows' : /Mac/.test(platform) ? 'mac' : 'linux');
  function update() {
    const scope = document.getElementById('include-project').checked ? 'project' : 'host';
    document.getElementById('project-field').hidden = scope !== 'project';
    document.getElementById('terminal-step').textContent = os.value === 'windows'
      ? '展開した配布フォルダーのアドレス欄に powershell と入力して開く'
      : os.value === 'mac'
      ? 'Finderで展開した配布フォルダーを右クリック → サービス → フォルダに新規ターミナル'
      : '展開した配布フォルダーでターミナルを開く';
    try {
      command.value = makeCommand(os.value, scope, project.value, document.getElementById('offline').checked, form.dataset?.bundled === 'true');
      copy.disabled = false;
      message.textContent = '';
      project.removeAttribute('aria-invalid');
    } catch (error) {
      command.value = '';
      copy.disabled = true;
      message.textContent = error.message;
      project.setAttribute('aria-invalid', 'true');
    }
  }
  form.addEventListener('input', update);
  form.addEventListener('change', update);
  form.addEventListener('submit', event => event.preventDefault());
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(command.value);
      message.textContent = 'コピーしました';
    } catch (_) {
      command.focus(); command.select();
      message.textContent = 'コマンドを選択しました。Ctrl+C（Macは⌘C）でコピーしてください。';
    }
  });
  update();
}
