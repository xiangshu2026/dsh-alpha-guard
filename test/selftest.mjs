/**
 * dsh-alpha-guard 纯策略自测。
 * 运行：<node> test/selftest.mjs
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PolicyEngine } from '../lib/policy.js';

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'alpha-guard-selftest-'));
const engine = new PolicyEngine({
  configPath: path.join(tmpDir, 'config.json'),
  auditPath: path.join(tmpDir, 'audit.jsonl'),
});

// 自测用工作区：改成临时目录，任何机器都能跑，不依赖个人路径
const WORKSPACE = path.join(tmpDir, 'workspace');
fs.mkdirSync(WORKSPACE, { recursive: true });
const HOME = os.homedir();

function exec(tool, args, options) {
  const opts = options || {};
  const header = {
    id: opts.sessionId || 'selftest-session',
    cwd: opts.cwd || WORKSPACE,
    agentPreset: 'ptc',
  };
  if (opts.sub) {
    header.origin = 'subagent';
    header.parentSession = 'parent-session';
    header.delegationDepth = 1;
  }
  return { name: tool, arguments: args, agent: { session: { id: header.id, header: header } } };
}

function allow(tool, args, options, label) {
  const reason = engine.check(exec(tool, args, options));
  assert.equal(reason, undefined, 'expected allow: ' + label + ' -> ' + reason);
  console.log('PASS allow  ' + label);
}

function deny(tool, args, options, label) {
  const reason = engine.check(exec(tool, args, options));
  assert.equal(typeof reason, 'string', 'expected deny: ' + label);
  assert.ok(reason.indexOf('alpha-guard') !== -1, 'deny reason should mention alpha-guard: ' + reason);
  console.log('PASS deny   ' + label);
}

function allowWith(eng, tool, args, options, label) {
  const reason = eng.check(exec (tool, args, options));
  assert.equal(reason, undefined, 'expected allow: ' + label + ' -> ' + reason);
  console.log('PASS allow  ' + label);
}

function denyWith(eng, tool, args, options, label) {
  const reason = eng.check(exec (tool, args, options));
  assert.equal(typeof reason, 'string', 'expected deny: ' + label);
  assert.ok(reason.indexOf('alpha-guard') !== -1, 'deny reason should mention alpha-guard: ' + reason);
  console.log('PASS deny   ' + label);
}

// ---- 读取白名单 ----
allow('read', { file_path: WORKSPACE + '\\AGENTS.md' }, {}, 'workspace read');
allow('read', { file_path: path.join(HOME, 'Desktop', 'x.txt') }, {}, 'desktop read');
allow('glob', { pattern: '**/*.md', path: WORKSPACE }, {}, 'glob workspace');
allow('grep', { pattern: 'foo', path: WORKSPACE }, {}, 'grep workspace');
allow('read', { file_path: 'relative-file.txt' }, { cwd: WORKSPACE }, 'relative path resolves to workspace');
allow('read', { file_path: path.join(HOME, 'AppData', 'Local', 'Temp', 'x.log') }, {}, 'temp read');

// ---- 敏感区 / 白名单外 ----
deny('read', { file_path: path.join(HOME, '.dsh', '.credentials.yaml') }, {}, 'credentials read');
deny('read', { file_path: 'C:\\Windows\\System32\\config\\SAM' }, {}, 'SAM read');
deny('read', { file_path: path.join(HOME, '.dsh', 'workbuddy-vault', 'global', 'x.json') }, {}, 'workbuddy vault read');
deny('read', { file_path: 'C:\\Users\\other\\secret.txt' }, {}, 'other user read');
deny('read', { file_path: 'D:\\secret\\a.txt' }, {}, 'outside whitelist read');
deny('read', { file_path: '\\\\server\\share\\a.txt' }, {}, 'UNC read');
deny('read', { file_path: path.join(HOME, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Login Data') }, {}, 'chrome login data');
deny('read', { file_path: path.join(HOME, 'AppData', 'Local', 'Microsoft', 'Windows', 'Explorer', '.cache', 'mm', 'KEY.md') }, {}, 'memory dir direct read');
deny('glob', { pattern: '**/*', path: path.join(HOME, '.ssh') }, {}, 'glob .ssh');
deny('read_image', { file_path: path.join(HOME, '.ssh', 'id_rsa') }, {}, 'read_image id_rsa');

// ---- 写入保护 ----
allow('write', { file_path: WORKSPACE + '\\new.txt', content: 'x' }, {}, 'workspace write');
deny('write', { file_path: path.join(HOME, '.dsh', 'alpha-guard', 'config.json'), content: '{}' }, {}, 'guard config write');
deny('write', { file_path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', content: 'x' }, {}, 'windows write');
deny('write', { file_path: 'C:\\Program Files\\x\\a.txt', content: 'x' }, {}, 'program files write');
deny('write', { file_path: path.join(HOME, '.ssh', 'authorized_keys'), content: 'x' }, {}, '.ssh write');
deny('write', { file_path: 'C:\\Users\\other\\a.txt', content: 'x' }, {}, 'other user write');

// ---- 危险命令 ----
deny('pwsh', { command: 'format c:' }, {}, 'format c:');
deny('pwsh', { command: 'diskpart' }, {}, 'diskpart');
deny('pwsh', { command: 'shutdown /s /t 0' }, {}, 'shutdown');
deny('pwsh', { command: 'vssadmin delete shadows /all' }, {}, 'vssadmin delete');
deny('pwsh', { command: 'Set-MpPreference -DisableRealtimeMonitoring $true' }, {}, 'disable defender');
deny('pwsh', { command: 'reg delete HKLM\\Software\\Foo /f' }, {}, 'reg delete HKLM');
deny('pwsh', { command: 'net user hacker P@ss /add' }, {}, 'net user add');
deny('pwsh', { command: `Get-Content ${path.join(HOME, '.dsh', '.credentials.yaml')}` }, {}, 'read credentials via pwsh');
deny('pwsh', { command: 'Get-ChildItem C:\\Users\\other' }, {}, 'other user via pwsh');
deny('pwsh', { command: 'Copy-Item \\\\server\\share\\a.txt C:\\x' }, {}, 'UNC via pwsh');
deny('pwsh', { command: 'Get-Content $env:USERPROFILE\\.dsh\\.credentials.yaml' }, {}, 'env-expanded credentials via pwsh');
deny('pwsh', { command: 'Remove-Item -Recurse -Force C:\\' }, {}, 'delete C: root');
allow('pwsh', { command: 'Get-ChildItem ' + WORKSPACE }, {}, 'normal list');
allow('pwsh', { command: 'node --version' }, {}, 'normal node');
allow('pwsh', { command: 'git status' }, {}, 'normal git');

// ---- run_code 文本扫描 ----
deny('run_code', { code: `import fs from 'node:fs'; fs.readFileSync('${path.join(HOME, '.dsh', '.credentials.yaml')}');` }, {}, 'run_code credentials path');
deny('run_code', { code: "import { execSync } from 'node:child_process'; execSync('format c:');" }, {}, 'run_code dangerous command');
deny('run_code', { code: "const p = 'C:\\Windows\\System32\\config\\SAM';" }, {}, 'run_code SAM path');
allow('run_code', { code: 'const x = 1 + 1; console.log(x);' }, {}, 'run_code normal');

// ---- 子代理隔离 ----
allow('read', { file_path: WORKSPACE + '\\a.txt' }, { sub: true }, 'subagent workspace read');
deny('read', { file_path: path.join(HOME, '.dsh', 'AGENTS.md') }, { sub: true }, 'subagent .dsh read');
deny('read', { file_path: path.join(HOME, 'Desktop', 'x.txt') }, { sub: true }, 'subagent desktop read');
deny('write', { file_path: path.join(HOME, '.dsh', 'profiles', 'desktop', 'cordis.patch.yml'), content: 'x' }, { sub: true }, 'subagent dsh config write');
allow('write', { file_path: WORKSPACE + '\\sub.txt', content: 'x' }, { sub: true }, 'subagent workspace write');
deny('memory', {}, { sub: true }, 'subagent memory tool');
deny('dtodo', {}, { sub: true }, 'subagent dtodo tool');
deny('de_channel_send', { content: 'hi' }, { sub: true }, 'subagent channel send');

// ---- 浏览器工具路径 ----
deny('bcdp_upload', { selector: 'input', path: path.join(HOME, '.ssh', 'id_rsa') }, {}, 'bcdp upload id_rsa');
deny('bcdp_download', { triggerSelector: 'a', savePath: 'C:\\Windows\\Temp\\..\\x' }, {}, 'bcdp download to windows');
deny('bcdp_navigate', { url: `file:///${path.join(HOME, '.dsh', '.credentials.yaml').replace(/[\\]/g, '/')}` }, {}, 'bcdp navigate file url');

// ---- 外发审计与 web_fetch 防护 ----
allow('web_fetch', { url: 'https://example.com/page' }, {}, 'web_fetch normal https');
deny('web_fetch', { url: 'http://127.0.0.1:19387/api' }, {}, 'web_fetch localhost');
deny('web_fetch', { url: 'http://10.0.0.1/admin' }, {}, 'web_fetch private ip');
deny('web_fetch', { url: 'file:///D:/secret/a.txt' }, {}, 'web_fetch non-http url');
allow('web_search', { queries: ['dsh alpha guard'] }, {}, 'web_search main');
deny('bcdp_fill', { selector: '#x', text: 'secret' }, { sub: true }, 'subagent bcdp_fill');
allow('web_fetch', { url: 'https://example.com' }, { sub: true }, 'subagent web_fetch default allowed');

// ---- 安装/下载程序需要主人同意 ----
deny('pwsh', { command: 'winget install Foo' }, {}, 'winget install denied');
deny('pwsh', { command: 'choco install foo' }, {}, 'choco install denied');
deny('pwsh', { command: 'msiexec /i setup.msi' }, {}, 'msiexec denied');
deny('pwsh', { command: 'dsh plugin add x' }, {}, 'dsh plugin add denied');
deny('pwsh', { command: 'npm install -g x' }, {}, 'npm global install denied');
deny('pwsh', { command: 'pip install --user x' }, {}, 'pip user install denied');
allow('pwsh', { command: 'pip install requests' }, {}, 'pip project install allowed');
allow('pwsh', { command: 'npm install' }, {}, 'npm project install allowed');
deny('pwsh', { command: 'curl -o tool.exe https://example.com/x' }, {}, 'curl download exe denied');
deny('pwsh', { command: 'Invoke-WebRequest https://example.com/x -OutFile tool.exe' }, {}, 'iwr download exe denied');
deny('bcdp_download', { triggerSelector: 'a', savePath: path.join(HOME, 'Downloads', 'setup.exe') }, {}, 'browser download exe denied');

// ---- 主人精确白名单 allowExact / warn 模式 ----
const cfgPath = path.join(tmpDir, 'config.json');
const baseCfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
baseCfg.commands = Object.assign({}, baseCfg.commands, { allowExact: ['format c:'] });
fs.writeFileSync(cfgPath, JSON.stringify(baseCfg, null, 2));
const engine2 = new PolicyEngine({ configPath: cfgPath, auditPath: path.join(tmpDir, 'audit2.jsonl') });
const allowReason = engine2.check(exec ('pwsh', { command: 'format c:' }, {}));
assert.equal(allowReason, undefined, 'allowExact should allow exact command: ' + allowReason);
console.log('PASS allow  allowExact exact command');
const stillDenied = engine2.check(exec ('pwsh', { command: 'format d:' }, {}));
assert.equal(typeof stillDenied, 'string', 'allowExact must not widen other commands');
console.log('PASS deny   allowExact does not widen other commands');
baseCfg.commands = Object.assign({}, baseCfg.commands, { mode: 'warn' });
fs.writeFileSync(cfgPath, JSON.stringify(baseCfg, null, 2));
const engine3 = new PolicyEngine({ configPath: cfgPath, auditPath: path.join(tmpDir, 'audit3.jsonl') });
const warnReason = engine3.check(exec ('pwsh', { command: 'format e:' }, {}));
assert.equal(warnReason, undefined, 'warn mode should allow dangerous command: ' + warnReason);
console.log('PASS allow  warn mode');
baseCfg.subagent = Object.assign({}, baseCfg.subagent, { allowWeb: false });
fs.writeFileSync(cfgPath, JSON.stringify(baseCfg, null, 2));
const engine4 = new PolicyEngine({ configPath: cfgPath, auditPath: path.join(tmpDir, 'audit4.jsonl') });
const strictReason = engine4.check(exec ('web_fetch', { url: 'https://example.com' }, { sub: true }));
assert.equal(typeof strictReason, 'string', 'subagent allowWeb=false should deny web tools');
console.log('PASS deny   subagent allowWeb=false');

// ---- 安装批准（双击一次）----
baseCfg.commands.mode = 'deny';
baseCfg.installApproval = Object.assign({}, baseCfg.installApproval, { path: path.join(tmpDir, 'install-approval.json'), windowSeconds: 120 });
fs.writeFileSync(cfgPath, JSON.stringify(baseCfg, null, 2));
const engine5 = new PolicyEngine({ configPath: cfgPath, auditPath: path.join(tmpDir, 'audit5.jsonl') });
denyWith(engine5, 'pwsh', { command: 'winget install Foo' }, {}, 'install without approval denied');
fs.writeFileSync(path.join(tmpDir, 'install-approval.json'), JSON.stringify({ ts: Math.floor(Date.now() / 1000), note: 'test' }));
allowWith(engine5, 'pwsh', { command: 'winget install Foo' }, {}, 'install with approval allowed');
denyWith(engine5, 'pwsh', { command: 'winget install Foo' }, {}, 'approval is one-shot');
fs.writeFileSync(path.join(tmpDir, 'install-approval.json'), JSON.stringify({ ts: Math.floor(Date.now() / 1000), note: 'test' }));
denyWith(engine5, 'pwsh', { command: 'winget install Foo' }, { sub: true }, 'subagent cannot use install approval');
denyWith(engine5, 'pwsh', { command: 'approve-install.cmd' }, {}, 'approve script execution denied');

// ---- 审计日志 ----
const auditText = fs.readFileSync(path.join(tmpDir, 'audit.jsonl'), 'utf8');
assert.ok(auditText.indexOf('"decision":"deny"') !== -1, 'audit should contain deny entries');
assert.ok(auditText.indexOf('"decision":"audit"') !== -1, 'audit should contain outbound audit entries');
console.log('PASS audit log written (' + auditText.split('\n').filter(Boolean).length + ' lines)');


// ---- 恶意软件审计与隔离区 ----
const { auditFile, extractTargetPaths } = await import('../lib/malware-audit.js');
const { Quarantine, PendingQueue } = await import('../lib/quarantine.js');

const malDir = path.join(tmpDir, 'malware');
fs.mkdirSync(malDir, { recursive: true });

const NUL = String.fromCharCode(0);
const BSL = String.fromCharCode(92);

// 高风险样本：凭据 + 网络 + 键盘钩子 + 敏感数据路径
const stealerBytes = Buffer.concat([
  Buffer.from('MZ' + NUL.repeat(128), 'latin1'),
  Buffer.from([
    'CryptUnprotectData', 'InternetOpenW', 'HttpSendRequestW',
    'SetWindowsHookExW', 'GetAsyncKeyState', 'CreateRemoteThread',
    'Google' + BSL + BSL + 'Chrome',
    'Login Data', 'Cookies', '.ssh', 'id_rsa',
  ].join(NUL), 'latin1'),
]);
const stealerPath = path.join(malDir, 'stealer-sample.exe');
fs.writeFileSync(stealerPath, stealerBytes);

const cleanBytes = Buffer.concat([
  Buffer.from('MZ' + NUL.repeat(128), 'latin1'),
  Buffer.from(['GetModuleHandleW', 'CreateWindowExW', 'MessageBoxW'].join(NUL), 'latin1'),
]);
const cleanPath = path.join(malDir, 'clean-sample.exe');
fs.writeFileSync(cleanPath, cleanBytes);

const fakePath = path.join(malDir, 'fake-sample.exe');
fs.writeFileSync(fakePath, 'not a real executable');

const rHigh = auditFile(stealerPath, {});
assert.equal(rHigh.level, 'high', 'stealer should be high risk, got ' + rHigh.level + ' score=' + rHigh.score);
assert.ok(rHigh.score >= 60, 'stealer score should be >= 60, got ' + rHigh.score);
assert.ok(rHigh.findings.some(function (f) { return f.id === 'combo-net-exfil'; }), 'should flag net+exfil combo');
console.log('PASS audit  high-risk sample detected (score=' + rHigh.score + ')');

const rClean = auditFile(cleanPath, {});
assert.equal(rClean.level, 'clean', 'clean sample should be clean, got ' + rClean.level);
console.log('PASS audit  clean sample passes');

const rFake = auditFile(fakePath, {});
assert.ok(rFake.findings.some(function (f) { return f.id === 'magic-mismatch'; }), 'fake exe should trigger magic-mismatch');
console.log('PASS audit  magic mismatch detected');

const rMissing = auditFile(path.join(malDir, 'nope.exe'), {});
assert.equal(rMissing.exists, false, 'missing file should report exists=false');
console.log('PASS audit  missing file handled');

const extracted = extractTargetPaths('Start-Process "' + stealerPath + '"', malDir);
assert.equal(extracted.length, 1, 'should extract 1 path, got ' + extracted.length);
const noneExtracted = extractTargetPaths('Get-Process | Where-Object { $_.Id -gt 100 }', malDir);
assert.equal(noneExtracted.length, 0, 'plain command should extract nothing');
console.log('PASS audit  path extraction works');

const qDir = path.join(tmpDir, 'quarantine');
const q = new Quarantine({ dir: qDir });
const added = q.add(stealerPath, { reason: 'selftest', audit: rHigh });
assert.ok(added.ok, 'quarantine add should succeed: ' + added.error);
assert.equal(fs.existsSync(stealerPath), false, 'original should be moved away');
assert.ok(fs.existsSync(path.join(qDir, added.id + '.bin')), 'blob should exist as bin');
assert.equal(q.list().length, 1, 'list should have 1 item');
console.log('PASS quarantine add');

const restored = q.restore(added.id, path.join(malDir, 'restored.exe'));
assert.ok(restored.ok, 'restore should succeed: ' + restored.error);
assert.ok(fs.existsSync(restored.restoredTo), 'restored file should exist');
assert.equal(q.list().length, 0, 'list should be empty after restore');
console.log('PASS quarantine restore');

const added2 = q.add(cleanPath, { reason: 'selftest-delete', audit: rClean });
assert.ok(added2.ok, 'second add should succeed');
const removed = q.remove(added2.id);
assert.ok(removed.ok, 'remove should succeed: ' + removed.error);
assert.equal(q.list().length, 0, 'list empty after delete');
console.log('PASS quarantine delete');

const pq = new PendingQueue(qDir);
const fakeTarget = 'C:' + BSL + 'tmp' + BSL + 'a.exe';
const p1 = pq.push({ path: fakeTarget, level: 'medium', score: 45, summary: 'test' });
const p1again = pq.push({ path: fakeTarget, level: 'medium', score: 45, summary: 'test' });
assert.equal(p1.id, p1again.id, 'duplicate push should reuse entry');
assert.equal(pq.pending().length, 1, 'pending should have 1 item');
pq.resolve(p1.id, 'resolved-keep');
assert.equal(pq.pending().length, 0, 'pending empty after resolve');
console.log('PASS pending queue');

const malCfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
malCfg.malware = Object.assign({}, malCfg.malware, {
  enabled: true, blockAt: 30, autoQuarantine: true,
  quarantineDir: path.join(tmpDir, 'q2'),
});
fs.writeFileSync(cfgPath, JSON.stringify(malCfg, null, 2));

fs.writeFileSync(stealerPath, stealerBytes);
const engine6 = new PolicyEngine({ configPath: cfgPath, auditPath: path.join(tmpDir, 'audit6.jsonl') });
const blockReason = engine6.check(exec('pwsh', { command: 'Start-Process "' + stealerPath + '"' }, {}));
assert.equal(typeof blockReason, 'string', 'high-risk exe execution should be blocked');
assert.ok(blockReason.indexOf('可疑文件') !== -1, 'block message should mention suspicious file');
console.log('PASS malware block high-risk exe');

fs.writeFileSync(cleanPath, cleanBytes);
const engine7 = new PolicyEngine({ configPath: cfgPath, auditPath: path.join(tmpDir, 'audit7.jsonl') });
const cleanReason = engine7.check(exec('pwsh', { command: 'Start-Process "' + cleanPath + '"' }, {}));
assert.equal(cleanReason, undefined, 'clean exe should be allowed, got: ' + cleanReason);
console.log('PASS malware allows clean exe');

const apiResult = engine7.auditTarget(fakePath);
assert.equal(apiResult.level, 'low', 'auditTarget should return low for fake sample');
const apiBatch = engine7.auditTargets([fakePath, cleanPath]);
assert.equal(apiBatch.length, 2, 'auditTargets should return 2 results');
console.log('PASS audit api');

fs.rmSync(tmpDir, { recursive: true, force: true });
console.log('\nALL SELFTESTS PASSED');
