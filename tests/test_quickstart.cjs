const {test} = require('node:test');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const vm = require('node:vm');
const {makeCommand} = require('../quickstart.js');

test('a project must be explicitly provided before a runnable command appears', () => {
  assert.throws(() => makeCommand('mac', 'project', '', false), /フォルダー/);
  assert.throws(() => makeCommand('mac', 'project', '/tmp/one\nwhoami', false), /改行/);
});

test('host-only and offline choices are reflected without a fixed output folder', () => {
  const command = makeCommand('linux', 'host', '', true);
  assert.match(command, /--host-only --offline$/);
  assert.doesNotMatch(command, /--project|--out/);
});

test('POSIX paths preserve spaces, apostrophes and shell syntax as literal data', () => {
  const path = "/tmp/日本語 work/o'neil/$(whoami)`id`";
  const command = makeCommand('mac', 'project', path, false);
  const args = command.replace("bash './run-checks.sh'", "printf '%s\\n'");
  const result = spawnSync('/bin/bash', ['-c', args], {encoding:'utf8'});
  assert.equal(result.status, 0);
  assert.equal(result.stdout, '--project\n' + path + '\n');
});

test('PowerShell invokes bundled Python directly and quotes paths literally', () => {
  const command = makeCommand('windows', 'project', "C:\\work\\o'neil & %PATH% $x", false);
  assert.match(command, /^& '\.\\runtime\\python.exe' -E -s -B '\.\\audit.py'/);
  assert.ok(command.endsWith("--project 'C:\\work\\o''neil & %PATH% $x'"));
  assert.doesNotMatch(command, /cmd|ExecutionPolicy/);
});

test('opening the start page produces a host command; project input is optional', () => {
  const html = fs.readFileSync(require.resolve('../START-HERE.html'), 'utf8');
  const projectToggle = html.match(/<input\b[^>]*id="include-project"[^>]*>/);
  assert.ok(projectToggle, 'project selection is an optional control');
  assert.doesNotMatch(projectToggle[0], /\bchecked\b/);
  const elements = {};
  for (const id of ['setup','os','project','command','copy','command-status','project-field','terminal-step','offline','include-project']) {
    elements[id] = {value:'', checked:false, addEventListener(){}, removeAttribute(){}, setAttribute(){}};
  }
  const context = vm.createContext({document:{getElementById:id=>elements[id]}, navigator:{platform:'MacIntel'}});
  vm.runInContext(fs.readFileSync(require.resolve('../quickstart.js'), 'utf8'), context);
  assert.equal(elements.command.value, "bash './run-checks.sh' --host-only");
  assert.equal(elements.copy.disabled, false);
  assert.equal(elements['project-field'].hidden, true);
});

test('PC-only mode ignores an unused project path', () => {
  assert.equal(makeCommand('mac', 'host', 'old\ninvalid path', false), "bash './run-checks.sh' --host-only");
});

test('distributed entry page runs the nested app from the extracted root', () => {
  assert.equal(makeCommand('mac', 'host', '', false, true), "bash './app/run-checks.sh' --host-only");
  assert.equal(makeCommand('windows', 'host', '', true, true), "& '.\\app\\runtime\\python.exe' -E -s -B '.\\app\\audit.py' --host-only --offline");
  const path = "/tmp/日本語/o'neil";
  const command = makeCommand('linux', 'project', path, false, true);
  const result = spawnSync('/bin/bash', ['-c', command.replace("bash './app/run-checks.sh'", "printf '%s\\n'")], {encoding:'utf8'});
  assert.equal(result.status, 0);
  assert.equal(result.stdout, '--project\n' + path + '\n');
});

test('packaged OS wins over the computer used to view the guide', () => {
  const elements = {};
  for (const id of ['setup','os','project','command','copy','command-status','project-field','terminal-step','offline','include-project']) {
    elements[id] = {value:'', checked:false, addEventListener(){}, removeAttribute(){}, setAttribute(){}};
  }
  elements.setup.dataset = {bundled:'true', platform:'windows'};
  const context = vm.createContext({document:{getElementById:id=>elements[id]}, navigator:{platform:'MacIntel'}});
  vm.runInContext(fs.readFileSync(require.resolve('../quickstart.js'), 'utf8'), context);
  assert.equal(elements.os.value, 'windows');
  assert.match(elements.command.value, /app\\runtime\\python.exe/);
});
