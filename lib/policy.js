// dsh-alpha-guard · DeepSeek Harness 策略层护栏
// https://github.com/xiangshu2026/dsh-alpha-guard
/**
 * dsh-alpha-guard policy engine.
 *
 * 策略层职责：
 *  - 读取白名单：只允许 read/glob/grep/read_image 等工具访问指定根目录；
 *  - 敏感区拒绝：凭据、浏览器配置、聊天记录、其他用户目录、系统机密等一律拒绝；
 *  - 写入保护：保护系统目录、凭据、防护配置自身；
 *  - 危险命令拦截：格式化/分区/引导/关机/删根目录/禁用安全软件/导出凭据等；
 *  - 子代理隔离：子代理/队友只能读工作区与临时目录，且禁用 memory/dtodo 等工具；
 *  - 审计：拒绝与告警写入 JSONL。
 *
 * 说明：这是策略层防护，不是内核级隔离。run_code / pwsh 仍可执行任意代码，
 * 因此对这两类工具做文本扫描（敏感路径 + 高危命令）为尽力而为的拦截。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditFile, extractTargetPaths } from './malware-audit.js';
import { Quarantine, PendingQueue, EXECUTABLE_EXTENSIONS } from './quarantine.js';

const HOME = os.homedir();

// Plugin's own install root (this file lives at <root>/lib/policy.js, so root = parent of lib/).
// The source itself is full of sensitive-path keywords (.ssh, .credentials.yaml,
// CredEnumerateW and friends), so the static audit inevitably scores it 100/100.
// That is a self-reference false positive, not a threat. Anyone able to write into
// this directory could already edit policy.js directly, at which point the guard is
// gone anyway -- so exempting it lowers no real protection. Executables are NOT
// exempted: an .exe dropped in here is still audited.
const SELF_ROOT = (() => {
  try {
    return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  } catch (e) {
    return '';
  }
})();

// Own directory: exempt text source only; binaries/executables are still fully audited
const SELF_BINARY_EXT = new Set(['.exe', '.dll', '.sys', '.scr', '.cpl', '.msi', '.msix', '.com', '.pif', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.wsf', '.hta', '.jar', '.crx', '.reg', '.lnk']);

function isSelfSource(p) {
  if (!SELF_ROOT || typeof p !== 'string' || !p) return false;
  try {
    const r = path.resolve(p);
    return r === SELF_ROOT || r.startsWith(SELF_ROOT + path.sep);
  } catch (e) {
    return false;
  }
}

/**
 * 把「相对用户主目录的路径片段」拼成绝对路径。
 * 例：hp('.dsh', 'alpha-guard') → <HOME>/.dsh/alpha-guard
 * 这样同一份策略文件在任何用户名 / 任何系统上都能直接跑，不需要改代码。
 */
function hp(...segments) {
  return path.join(HOME, ...segments);
}

/**
 * 从环境变量 DSH_GUARD_EXTRA_ROOTS 读取额外的读取白名单根目录。
 * 用分号或逗号分隔；不设置则为空数组。这样个人工作盘不必写死进源码。
 */
function extraRootsFromEnv() {
  const raw = process.env.DSH_GUARD_EXTRA_ROOTS || '';
  return raw.split(/[;,]/).map(function (s) { return s.trim(); }).filter(Boolean);
}

/** 当前登录用户名（从 HOME 推导，不再写死）。用于「其他用户目录」判定。 */
function currentUserName() {
  try {
    return path.basename(HOME).toLowerCase();
  } catch (e) {
    return '';
  }
}

/**
 * 判断一个 C:\Users\ 下的目录名是否指向「当前用户」。
 *
 * 为什么需要这个而不只是字符串比较：Windows 有 8.3 短文件名。
 * 用户名超过 8 个字符时，系统会生成一个形如 RUNNER~1 的短名，
 * 和长名 runneradmin 指向同一个目录。GitHub Actions 的临时目录就长这样：
 *   C:\Users\RUNNER~1\AppData\Local\Temp\...
 * 如果只做 === 比较，短名会被误判成「其他用户」，导致正常操作被拒。
 *
 * 判定规则：
 *   1. 完全相同 → 同一用户
 *   2. 短名（含 ~数字 后缀）去掉后缀后，是当前用户名的前缀 → 同一用户
 *      例：runner~1 vs runneradmin → 前缀 runner 匹配
 *   3. 其它 → 不是同一用户
 */
function isCurrentUserDirName(name) {
  const raw = String(name || '').toLowerCase();
  if (!raw) return false;
  const current = currentUserName();
  if (!current) return /~\d+$/.test(raw); // 推导不出当前用户：仅对 8.3 短名放行，其余仍拒
  if (raw === current) return true;
  const m = /^(.+)~(\d+)$/.exec(raw);
  if (m) {
    const base = m[1];
    if (current === base) return true;
    if (current.startsWith(base)) return true;
  }
  return false;
}

// 防护配置所在目录（用于文本扫描时的写入意图判定）
const PROTECTED_DIR_KEY = keyOfRaw(hp('.dsh', 'alpha-guard'));
// 「写入类动词」正则：命中即认为这段命令/代码是在写文件
const WRITE_VERB_RE = /(set-content|add-content|out-file|writefile|writefilesync|appendfile|copy-item|move-item|remove-item|rename-item|unlink|fs\.write|fs\.append|>\s*["']?)/i;

function keyOfRaw(p) {
  return String(p).toLowerCase().replace(/\//g, '\\');
}
const DEFAULT_CONFIG_PATH = path.join(HOME, '.dsh', 'alpha-guard', 'config.json');
const DEFAULT_AUDIT_PATH = path.join(HOME, '.dsh', 'alpha-guard', 'audit.jsonl');
const TMP_DIRS = [os.tmpdir(), 'C:\\Windows\\Temp'];
const DSH_INSTALL = (function () {
  try {
    return path.dirname(process.execPath);
  } catch (e) {
    return hp('AppData', 'Local', 'Programs', 'DeepSeek Harness');
  }
})();

const DEFAULT_COMMAND_DENY = [
  /\bformat(?:\.com)?\s+[a-z]:/i,
  /\bdiskpart\b/i,
  /\bFormat-Volume\b/i,
  /\bClear-Disk\b/i,
  /\bInitialize-Disk\b/i,
  /\bRemove-Partition\b/i,
  /\bResize-Partition\b/i,
  /\bbcdedit\b/i,
  /\bbootrec\b/i,
  /\bvssadmin\b[^\n]*\bdelete\b/i,
  /\bwbadmin\b[^\n]*\bdelete\b/i,
  /\bshutdown\b[^\n]*\s(?:\/s|\/r|\/p|-s|-r|-p)\b/i,
  /\bRestart-Computer\b/i,
  /\bStop-Computer\b/i,
  /\bnet\s+user\b[^\n]*\/add\b/i,
  /\bnet\s+localgroup\b[^\n]*\/add\b/i,
  /\bNew-LocalUser\b/i,
  /\bSet-MpPreference\b[^\n]*-Disable/i,
  /\bAdd-MpPreference\b[^\n]*-ExclusionPath/i,
  /\bDisable-WindowsOptionalFeature\b/i,
  /\bSet-NetFirewallProfile\b[^\n]*-Enabled\s+(?:false|0)/i,
  /\bnetsh\s+advfirewall\s+set\b[^\n]*\boff\b/i,
  /\breg\s+delete\s+(?:hklm|hkcr|hku)/i,
  /\breg\s+save\s+hklm\\(?:sam|system|security)\b/i,
  /\bRemove-Item\b[^\n]*hklm:/i,
  /\bmimikatz\b/i,
  /\bprocdump\b[^\n]*\blsass\b/i,
  /\bcomsvcs\.dll\b[^\n]*minidump/i,
  /\bInvoke-Expression\b[^\n]*(?:DownloadString|Invoke-WebRequest|\biwr\b|\bcurl\b|\bwget\b)/i,
  /\bIEX\b[^\n]*(?:DownloadString|\biwr\b|Invoke-WebRequest)/i,
  /\s-EncodedCommand\b/i,
  /\b(?:rd|rmdir|del)\b[^\n]*\/s[^\n]*\/q[^\n]*\b[a-z]:\\(?:\s|$|\*)/i,
  /\bRemove-Item\b[^\n]*-Recurse[^\n]*-Force[^\n]*\b[a-z]:\\(?:\s|$|\*)/i,
  /\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+\/(?:\s|$)/i,
  /\brm\s+-[a-z]*f[a-z]*r[a-z]*\s+\/(?:\s|$)/i,
  /\btakeown\b[^\n]*\/f\s+[a-z]:\\(?:\s|$)/i,
  /\bicacls\s+[a-z]:\\(?:\s|$)[^\n]*\/grant/i,
  /\bcipher\b[^\n]*\/w\b/i,
  /\bwevtutil\b[^\n]*\bcl\b/i,
  /\bwmic\b[^\n]*\bdelete\b/i,
  /\bapprove-install\b/i,
  /\binstall-approval\.json\b/i
];

const DEFAULT_COMMAND_WARN = [
  /\bsc\s+create\b/i,
  /\bschtasks\b[^\n]*\/create\b/i,
  /\bNew-Service\b/i,
  /\breg\s+add\b[^\n]*\\run\b/i,
  /\bStart-Process\b[^\n]*-Verb\s+RunAs/i,
  /\bpip\s+install\b/i
];

const DEFAULT_APPROVAL_PATH = path.join(HOME, '.dsh', 'alpha-guard', 'install-approval.json');

const DEFAULT_INSTALL_DENY = [
  /\bwinget\s+(?:install|upgrade|uninstall)\b/i,
  /\bchoco\s+(?:install|upgrade|uninstall)\b/i,
  /\bscoop\s+(?:install|uninstall)\b/i,
  /\bmsiexec\b/i,
  /\bsetup(?:[-_.]?[a-z0-9]+)?\.exe\b/i,
  /\bdsh\s+plugin\b[^\n]*\b(?:add|remove|update)\b/i,
  /\bnpm\s+(?:install|i|add)\s+(?:-g|--global)\b/i,
  /\bpnpm\s+(?:add|install)\s+(?:-g|--global)\b/i,
  /\bpip\s+install\b[^\n]*(?:--user|--global)\b/i,
  /\bInvoke-WebRequest\b[^\n]*\.(?:exe|msi|bat|cmd|ps1)\b/i,
  /\bcurl\b[^\n]*-o\b[^\n]*\.(?:exe|msi|bat|cmd|ps1)\b/i,
  /\bwget\b[^\n]*\.(?:exe|msi|bat|cmd|ps1)\b/i
];

const EOL = String.fromCharCode(13) + String.fromCharCode(10);
const APPROVE_PS1_CONTENT = [
  '$p = Join-Path $env:USERPROFILE \'.dsh/alpha-guard/install-approval.json\'',
  '@{ ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); note = \'owner-approved-one-install\' } | ConvertTo-Json -Compress | Set-Content -LiteralPath $p -Encoding UTF8',
  'Write-Host \'OK: next install allowed for 2 minutes (one use).\'',
  ''
].join(EOL);
const APPROVE_CMD_CONTENT = [
  '@echo off',
  'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0approve-install.ps1"',
  'pause',
  ''
].join(EOL);

export const DEFAULT_CONFIG = {
  _readme: 'dsh-alpha-guard 配置文件。主人可直接编辑本文件；保存后插件会在下一次工具调用时自动生效（无需重启）。read.allowRoots 是读取白名单根目录；read.denyPaths 永远拒绝（优先级最高）；write.denyPaths 是禁止写入/删除的路径；commands.extraDenyPatterns 可追加高危命令正则（JS 正则字符串）。',
  version: 1,
  enabled: true,
  failClosed: false,
  read: {
    allowRoots: [
      // 额外工作盘：用环境变量 DSH_GUARD_EXTRA_ROOTS 传（多个用分号或逗号分隔），
      // 例如 DSH_GUARD_EXTRA_ROOTS="E:\\work;D:\\projects"
      ...extraRootsFromEnv(),
      hp('.dsh'),
      hp('Desktop'),
      hp('Documents'),
      hp('Downloads'),
      hp('Pictures'),
      hp('Videos'),
      hp('Music'),
      hp('AppData', 'Local', 'Temp'),
      hp('AppData', 'Local', 'Programs', 'DeepSeek Harness'),
      hp('codexpp'),
      hp('.codex'),
      hp('.claude'),
      hp('.kimi'),
      hp('AppData', 'Local', 'Android'),
      'C:\\Windows\\Temp'
    ],
    denyPaths: [
      hp('.dsh', '.credentials.yaml'),
      hp('.dsh', 'workbuddy-vault'),
      hp('.dsh', 'sessions'),
      hp('.dsh', 'memories'),
      hp('AppData', 'Local', 'Microsoft', 'Windows', 'Explorer', '.cache', 'mm'),
      hp('.ssh'),
      hp('.gnupg'),
      hp('.aws'),
      hp('.azure'),
      hp('.config', 'gcloud'),
      hp('.codex', 'auth.json'),
      hp('.claude', 'settings.json'),
      hp('.claude.json'),
      hp('AppData', 'Local', 'Google', 'Chrome', 'User Data'),
      hp('AppData', 'Local', 'Microsoft', 'Edge', 'User Data'),
      hp('AppData', 'Local', 'BraveSoftware'),
      hp('AppData', 'Roaming', 'Mozilla', 'Firefox'),
      hp('AppData', 'Roaming', 'Opera Software'),
      hp('Documents', 'WeChat Files'),
      hp('Documents', 'xwechat_files'),
      hp('Documents', 'Tencent Files'),
      hp('AppData', 'Roaming', 'Tencent'),
      hp('AppData', 'Local', 'Tencent'),
      hp('AppData', 'Roaming', 'Bitwarden'),
      hp('AppData', 'Roaming', '1Password'),
      hp('AppData', 'Local', '1Password'),
      hp('AppData', 'Local', 'KeePass'),
      'C:\\Windows\\System32\\config',
      'C:\\Windows\\NTDS',
      'C:\\Windows\\repair',
      'C:\\Windows\\Minidump',
      'C:\\Windows\\MEMORY.DMP',
      'C:\\$Recycle.Bin',
      'C:\\System Volume Information',
      'C:\\Users\\Public',
      'C:\\ProgramData\\Microsoft\\Windows\\System'
    ],
    denyNamePatterns: [
      '*.kdbx',
      '*.kdb',
      '*.keychain',
      'id_rsa',
      'id_ed25519',
      '*.pem',
      '*.pfx',
      '*.p12',
      'pagefile.sys',
      'hiberfil.sys',
      'MEMORY.DMP'
    ],
    denyOtherUserProfiles: true,
    denyNetworkPaths: true
  },
  write: {
    denyPaths: [
      hp('.dsh', 'alpha-guard'),
      hp('.dsh', '.credentials.yaml'),
      hp('.dsh', 'workbuddy-vault'),
      hp('.dsh', 'sessions'),
      hp('.ssh'),
      hp('.gnupg'),
      hp('.aws'),
      hp('.azure'),
      hp('.codex', 'auth.json'),
      hp('.claude', 'settings.json'),
      hp('.claude.json'),
      hp('AppData', 'Local', 'Microsoft', 'Windows', 'Explorer', '.cache', 'mm'),
      hp('AppData', 'Local', 'Programs', 'DeepSeek Harness'),
      'C:\\Windows',
      'C:\\Program Files',
      'C:\\Program Files (x86)',
      'C:\\ProgramData',
      'C:\\$Recycle.Bin',
      'C:\\System Volume Information',
      'C:\\Users\\Public'
    ],
    denyNamePatterns: [
      '*.kdbx',
      '*.kdb',
      '*.keychain',
      'id_rsa',
      'id_ed25519'
    ],
    denyOtherUserProfiles: true,
    denyNetworkPaths: true,
    warnPaths: [
      hp('.dsh', 'plugins-src', 'dsh-alpha-guard'),
      hp('.dsh', 'profiles', 'desktop'),
      hp('.dsh', 'AGENTS.md')
    ]
  },
  commands: {
    denyPathsInText: true,
    mode: 'deny',
    allowExact: [],
    extraDenyPatterns: [],
    extraWarnPatterns: []
  },
  runCode: {
    scanText: true
  },
  web: {
    audit: true,
    denyLocalHosts: true,
    suspiciousUrlLength: 500,
    sensitiveKeywords: ['password', 'passwd', 'token', 'secret', 'api_key', 'apikey', 'cookie', '密码', '验证码', '身份证', '银行卡', '凭据']
  },
  subagent: {
    enabled: true,
    allowWeb: true,
    readRoots: [],
    writeRoots: [],
    denyBrowserTools: [
      'bcdp_fill',
      'bcdp_click',
      'bcdp_key',
      'bcdp_check',
      'bcdp_select',
      'bcdp_drag',
      'bcdp_hover',
      'bcdp_upload',
      'bcdp_script',
      'bcdp_cli',
      'bcdp_dialog',
      'bcdp_cdp',
      'bcdp_http'
    ],
    denyTools: [
      'memory',
      'dtodo',
      'de_channel_send',
      'spawn_teammate',
      'subagent',
      'subagent_fork',
      'schedule_create',
      'schedule_update',
      'schedule_delete'
    ],
    allowDshInstallRead: true
  },
  malware: {
    // 安装/执行前静态审计：只读字节，不运行目标
    enabled: true,
    // 审计时最多读多少字节（默认 32MB，防大文件卡死）
    maxBytes: 33554432,
    // 风险分达到多少就拦下并通知主人（0-100）
    blockAt: 30,
    // 只通知不拦（配合 blockAt 使用；true 时永不拒绝，仅告警）
    notifyOnly: false,
    // 自动把拦下的文件移入隔离区（false = 只记录 pending，等主人决定）
    autoQuarantine: true,
    // 隔离区目录（空 = ~/.dsh/alpha-guard/quarantine）
    quarantineDir: '',
    // 是否对子代理/队友也启用（默认启用，但只告警不拦）
    subagentNotify: true,
    // 待决队列保留天数
    pendingKeepDays: 30
  },
  installApproval: {
    enabled: true,
    path: DEFAULT_APPROVAL_PATH,
    windowSeconds: 120
  },
  audit: {
    enabled: true,
    path: DEFAULT_AUDIT_PATH,
    maxBytes: 5242880
  }
};

const REGEX_SPECIALS = '.*+?^$()[]{}|\\';

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function deepMerge(base, extra) {
  if (!isPlainObject(base) || !isPlainObject(extra)) return extra === undefined ? base : extra;
  const out = Object.assign({}, base);
  for (const key of Object.keys(extra)) {
    const value = extra[key];
    if (isPlainObject(value) && isPlainObject(base[key])) out[key] = deepMerge(base[key], value);
    else out[key] = value;
  }
  return out;
}

function escapeRegExp(text) {
  let out = '';
  const s = String(text);
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    out += REGEX_SPECIALS.indexOf(ch) === -1 ? ch : '\\' + ch;
  }
  return out;
}

function globToRegExp(pattern) {
  let out = '';
  const s = String(pattern);
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    if (ch === '*') out += '.*';
    else if (ch === '?') out += '.';
    else out += escapeRegExp(ch);
  }
  return new RegExp('^' + out + '$', 'i');
}

function expandVars(input) {
  let s = String(input);
  s = s.replace(/%([^%]+)%/g, function (match, name) {
    return Object.prototype.hasOwnProperty.call(process.env, name) ? process.env[name] : match;
  });
  s = s.replace(/\$env:([A-Za-z_][A-Za-z0-9_]*)/gi, function (match, name) {
    return Object.prototype.hasOwnProperty.call(process.env, name) ? process.env[name] : match;
  });
  s = s.replace(/\$HOME\b/gi, HOME);
  s = s.replace(/(^|[\s"'=;(])~(?=[\\/])/g, function (match, prefix) {
    return prefix + HOME;
  });
  return s;
}

function unquote(input) {
  const s = String(input).trim();
  if (s.length >= 2 && ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'"))) {
    return s.slice(1, -1);
  }
  return s;
}

export function normalizePath(raw, base) {
  if (raw === undefined || raw === null) return '';
  let s = String(raw).trim();
  if (s === '') return '';
  s = unquote(s);
  if (/^file:\/\//i.test(s)) {
    try {
      let rest = decodeURIComponent(s.replace(/^file:\/\//i, ''));
      if (/^\/[A-Za-z]:/.test(rest)) rest = rest.slice(1);
      s = rest;
    } catch (e) {
      // keep original on malformed file URL
    }
  }
  s = expandVars(s);
  try {
    if (path.win32.isAbsolute(s) || /^[A-Za-z]:[\\/]/.test(s)) s = path.win32.resolve(s);
    else s = path.win32.resolve(base || process.cwd(), s);
  } catch (e) {
    return s;
  }
  s = path.win32.normalize(s);
  if (/^[A-Za-z]:\\$/.test(s)) return s;
  s = s.replace(/\\+$/, '');
  return s;
}

function keyOf(p) {
  return String(p).toLowerCase();
}

/**
 * 把 Windows 8.3 短名（如 C:\Users\RUNNER~1\...）还原成长名形式。
 *
 * 为什么需要：CI / 某些工具会把 HOME 报成长名（runneradmin），
 * 但 cwd 或临时目录可能是短名（RUNNER~1）。两者指向同一目录，
 * 但字符串前缀比较认不出来，会导致白名单校验误判。
 * 这里只处理「~数字」出现在 C:\Users\<name> 段的场景，其余原样返回。
 */
function normalizeShortUserName(p) {
  const s = String(p || '');
  const m = /^(c:\\users\\)([^\\]+)([\s\S]*)$/i.exec(s);
  if (!m) return s;
  const head = m[1];
  const name = m[2];
  const rest = m[3];
  const cur = currentUserName();
  if (!cur || !isCurrentUserDirName(name)) return s;
  // 当前用户：统一替换成长名，避免短名/长名混用
  return head + cur + rest;
}

export function within(root, target) {
  const r = keyOf(normalizeShortUserName(root));
  const t = keyOf(normalizeShortUserName(target));
  if (r === '' || t === '') return false;
  if (t === r) return true;
  const r2 = r.charAt(r.length - 1) === '\\' ? r : r + '\\';
  return t.indexOf(r2) === 0;
}

function matchPathDeny(target, denyPaths) {
  for (const deny of denyPaths) {
    if (deny && within(deny, target)) return true;
  }
  return false;
}

function matchNameDeny(target, regexes) {
  const base = path.win32.basename(String(target));
  for (const re of regexes) {
    if (re.test(base)) return true;
  }
  return false;
}

function isOtherUserPath(p) {
  const m = /^c:\\users\\([^\\]+)/i.exec(String(p));
  if (!m) return false;
  return !isCurrentUserDirName(m[1]);
}

function isNetworkPath(p) {
  const s = String(p);
  if (s.indexOf('\\\\') !== 0) return false;
  if (s.indexOf('\\\\?\\') === 0) return false;
  return true;
}
function isPrivateHost(host) {
  const h = String(host || '').toLowerCase();
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0') return true;
  if (h.length > 6 && (h.slice(-6) === '.local' || h.slice(-9) === '.internal')) return true;
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

function pushUnique(list, value) {
  if (!value) return;
  const k = keyOf(value);
  for (const item of list) {
    if (keyOf(item) === k) return;
  }
  list.push(value);
}

function localTimeString() {
  const d = new Date();
  const pad = function (n) { return (n < 10 ? '0' : '') + n; };
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}

export class PolicyEngine {
  constructor(pluginConfig) {
    this.pluginConfig = pluginConfig || {};
    this.configPath = this.pluginConfig.configPath
      ? normalizePath(this.pluginConfig.configPath, HOME)
      : DEFAULT_CONFIG_PATH;
    this.auditPath = this.pluginConfig.auditPath
      ? normalizePath(this.pluginConfig.auditPath, HOME)
      : DEFAULT_AUDIT_PATH;
    this._mtimeMs = -1;
    this._cfg = null;
    this._compiled = null;
    this._auditCount = 0;
    this._ensureConfigFile();
    this.reload(true);
  }

  _ensureConfigFile() {
    try {
      fs.mkdirSync(path.dirname(this.configPath), { recursive: true });
      const approveDir = path.dirname(this.configPath);
      const approvePs1 = path.join(approveDir, 'approve-install.ps1');
      const approveCmd = path.join(approveDir, 'approve-install.cmd');
      if (!fs.existsSync(approvePs1)) fs.writeFileSync(approvePs1, APPROVE_PS1_CONTENT, 'utf8');
      if (!fs.existsSync(approveCmd)) fs.writeFileSync(approveCmd, APPROVE_CMD_CONTENT, 'utf8');
      if (!fs.existsSync(this.configPath)) {
        fs.writeFileSync(this.configPath, JSON.stringify(DEFAULT_CONFIG, null, 2), 'utf8');
        return;
      }
      const raw = fs.readFileSync(this.configPath, 'utf8');
      const parsed = JSON.parse(raw);
      let changed = false;
      if (!parsed.web) changed = true;
      if (!parsed.commands || parsed.commands.allowExact === undefined) changed = true;
      if (!parsed.subagent || parsed.subagent.allowWeb === undefined) changed = true;
      if (!parsed.subagent || !parsed.subagent.denyBrowserTools) changed = true;
      if (!parsed.malware) changed = true;
      if (changed) {
        fs.writeFileSync(this.configPath, JSON.stringify(deepMerge(DEFAULT_CONFIG, parsed), null, 2), 'utf8');
      }
    } catch (e) {
      console.error('[alpha-guard] cannot prepare config file: ' + String(e));
    }
  }

  reload(force) {
    try {
      const stat = fs.statSync(this.configPath);
      if (!force && this._cfg && stat.mtimeMs === this._mtimeMs) return;
      const raw = fs.readFileSync(this.configPath, 'utf8');
      const parsed = JSON.parse(raw);
      const merged = deepMerge(DEFAULT_CONFIG, parsed);
      this._cfg = merged;
      this._compiled = this._compile(merged);
      this._mtimeMs = stat.mtimeMs;
    } catch (e) {
      if (!this._cfg) {
        this._cfg = DEFAULT_CONFIG;
        this._compiled = this._compile(DEFAULT_CONFIG);
      }
      console.error('[alpha-guard] config reload failed (keeping previous): ' + String(e));
    }
  }

  _compile(cfg) {
    const norm = function (p) { return normalizePath(p, HOME); };
    const denyRead = (cfg.read.denyPaths || []).map(norm).filter(Boolean);
    const allowRead = (cfg.read.allowRoots || []).map(norm).filter(Boolean);
    const denyWrite = (cfg.write.denyPaths || []).map(norm).filter(Boolean);
    const warnWrite = (cfg.write.warnPaths || []).map(norm).filter(Boolean);
    const nameDenyRead = (cfg.read.denyNamePatterns || []).map(globToRegExp);
    const nameDenyWrite = (cfg.write.denyNamePatterns || []).map(globToRegExp);
    const cmdDeny = DEFAULT_COMMAND_DENY.concat((cfg.commands.extraDenyPatterns || []).map(function (source) {
      return new RegExp(String(source), 'i');
    }));
    const cmdWarn = DEFAULT_COMMAND_WARN.concat((cfg.commands.extraWarnPatterns || []).map(function (source) {
      return new RegExp(String(source), 'i');
    }));
    const installDeny = DEFAULT_INSTALL_DENY.concat((cfg.commands.extraInstallDenyPatterns || []).map(function (source) {
      return new RegExp(String(source), 'i');
    }));
    const protectedText = [normalizePath(path.join(HOME, '.dsh', 'alpha-guard', 'config.json'), HOME)].filter(Boolean);
    const allowExact = (cfg.commands.allowExact || []).map(function (raw) {
      const s = String(raw).trim();
      if (s.toLowerCase().indexOf('prefix:') === 0) {
        return { prefix: s.slice(7).trim().replace(/\s+/g, ' ').toLowerCase() };
      }
      return { text: s.replace(/\s+/g, ' ').toLowerCase() };
    }).filter(function (item) { return item.text || item.prefix; });
    return {
      denyRead: denyRead,
      allowRead: allowRead,
      denyWrite: denyWrite,
      warnWrite: warnWrite,
      nameDenyRead: nameDenyRead,
      nameDenyWrite: nameDenyWrite,
      cmdDeny: cmdDeny,
      cmdWarn: cmdWarn,
      installDeny: installDeny,
      allowExact: allowExact,
      protectedText: protectedText
    };
  }

  _context(exec) {
    const agent = exec ? exec.agent : undefined;
    const session = agent ? agent.session : undefined;
    const header = session && session.header ? session.header : {};
    let cwd = typeof header.cwd === 'string' ? header.cwd : '';
    if (!cwd) {
      try { cwd = process.cwd(); } catch (e) { cwd = ''; }
    }
    const isSub = header.origin === 'subagent'
      || typeof header.parentSession === 'string'
      || (typeof header.delegationDepth === 'number' && header.delegationDepth > 0);
    const sessionId = header.id || (session && session.id) || '';
    return { cwd: cwd, isSub: isSub, sessionId: sessionId, preset: header.agentPreset || '' };
  }

  _readRoots(ctx) {
    const cfg = this._cfg;
    const norm = function (p) { return normalizePath(p, HOME); };
    const roots = [];
    if (ctx.isSub && cfg.subagent && cfg.subagent.enabled !== false) {
      pushUnique(roots, norm(ctx.cwd));
      for (const tmp of TMP_DIRS) pushUnique(roots, norm(tmp));
      if (cfg.subagent.allowDshInstallRead !== false) pushUnique(roots, norm(DSH_INSTALL));
      for (const extra of (cfg.subagent.readRoots || [])) pushUnique(roots, norm(extra));
      return roots;
    }
    for (const root of this._compiled.allowRead) pushUnique(roots, root);
    pushUnique(roots, norm(ctx.cwd));
    return roots;
  }

  _subWriteRoots(ctx) {
    const cfg = this._cfg;
    const norm = function (p) { return normalizePath(p, HOME); };
    const roots = [];
    pushUnique(roots, norm(ctx.cwd));
    for (const tmp of TMP_DIRS) pushUnique(roots, norm(tmp));
    for (const extra of (cfg.subagent.writeRoots || [])) pushUnique(roots, norm(extra));
    return roots;
  }

  check(exec) {
    if (this._bypassActive()) return undefined;
    let cfg = this._cfg;
    try {
      this.reload(false);
      cfg = this._cfg;
      if (!cfg || cfg.enabled === false || this.pluginConfig.enabled === false) return undefined;
      const ctx = this._context(exec);
      const tool = exec && exec.name ? String(exec.name) : '';
      const args = exec && exec.arguments && typeof exec.arguments === 'object' ? exec.arguments : {};
      if (ctx.isSub && cfg.subagent && cfg.subagent.enabled !== false) {
        const deniedTools = cfg.subagent.denyTools || [];
        if (deniedTools.indexOf(tool) !== -1) {
          return this._deny(ctx, tool, args, '子代理/队友不允许使用该工具（隔离策略）');
        }
        if (cfg.subagent.allowWeb === false && (tool.indexOf('web_') === 0 || tool.indexOf('bcdp_') === 0)) {
          return this._deny(ctx, tool, args, '子代理严格模式：禁止联网与浏览器工具（subagent.allowWeb=false）');
        }
      }
      switch (tool) {
        case 'read':
        case 'read_image':
        case 'modlens_read_image':
          return this._checkRead(args.file_path !== undefined ? args.file_path : args.path, ctx, tool, args);
        case 'glob':
        case 'grep':
          return this._checkRead(args.path !== undefined && args.path !== '' ? args.path : ctx.cwd, ctx, tool, args);
        case 'write':
        case 'edit':
          return this._checkWrite(args.file_path, ctx, tool, args);
        case 'pwsh':
        case 'bash':
        case 'terminal':
          return this._checkCommand(args.command, args.workdir, ctx, tool, args);
        case 'run_code':
          return this._checkCode(args.code, ctx, tool, args);
        case 'web_fetch':
          return this._checkWebFetch(args.url, ctx, tool, args);
        case 'web_search':
          this._auditOutbound(tool, args, ctx, '联网搜索（仅记录）');
          return undefined;
        case 'bcdp_upload':
        case 'bcdp_fill':
        case 'bcdp_click':
        case 'bcdp_key':
        case 'bcdp_check':
        case 'bcdp_select':
        case 'bcdp_drag':
        case 'bcdp_hover':
        case 'bcdp_script':
        case 'bcdp_cli':
        case 'bcdp_dialog':
        case 'bcdp_cdp':
        case 'bcdp_http':
          return this._checkBrowser(tool, args, ctx);
        case 'bcdp_download':
          if (args.savePath && /\.(?:exe|msi|msix|bat|cmd|ps1)$/i.test(String(args.savePath))) {
            return this._deny(ctx, tool, args, '浏览器下载可执行文件需要主人同意：' + args.savePath);
          }
          return args.savePath ? this._checkWrite(args.savePath, ctx, tool, args) : undefined;
        case 'bcdp_screenshot':
          return args.path ? this._checkWrite(args.path, ctx, tool, args) : undefined;
        case 'bcdp_navigate':
          return this._checkNavigate(args.url, ctx, tool, args);
        case 'de_channel_send':
          return this._checkChannel(args, ctx, tool);
        default:
          return undefined;
      }
    } catch (err) {
      try { console.error('[alpha-guard] check error: ' + (err && err.stack ? err.stack : String(err))); } catch (e) {}
      if (cfg && cfg.failClosed) return 'alpha-guard 内部错误，已按 fail-closed 拒绝本次调用';
      return undefined;
    }
  }

  _checkRead(raw, ctx, tool, args) {
    const p = normalizePath(raw, ctx.cwd);
    if (!p) return undefined;
    const cfg = this._cfg;
    if (cfg.read.denyNetworkPaths !== false && isNetworkPath(p)) {
      return this._deny(ctx, tool, args, '网络共享路径默认禁止访问：' + p);
    }
    if (cfg.read.denyOtherUserProfiles !== false && isOtherUserPath(p)) {
      return this._deny(ctx, tool, args, '其他用户目录禁止访问：' + p);
    }
    if (matchPathDeny(p, this._compiled.denyRead) || matchNameDeny(p, this._compiled.nameDenyRead)) {
      return this._deny(ctx, tool, args, '敏感路径禁止读取：' + p);
    }
    const roots = this._readRoots(ctx);
    for (const root of roots) {
      if (within(root, p)) return undefined;
    }
    return this._deny(ctx, tool, args, '路径不在读取白名单内：' + p);
  }

  _checkWrite(raw, ctx, tool, args) {
    const p = normalizePath(raw, ctx.cwd);
    if (!p) return undefined;
    const cfg = this._cfg;
    if (cfg.write.denyNetworkPaths !== false && isNetworkPath(p)) {
      return this._deny(ctx, tool, args, '网络共享路径默认禁止写入：' + p);
    }
    if (cfg.write.denyOtherUserProfiles !== false && isOtherUserPath(p)) {
      return this._deny(ctx, tool, args, '其他用户目录禁止写入：' + p);
    }
    if (matchPathDeny(p, this._compiled.denyWrite) || matchNameDeny(p, this._compiled.nameDenyWrite)) {
      return this._deny(ctx, tool, args, '受保护路径禁止写入：' + p);
    }
    if (ctx.isSub && cfg.subagent && cfg.subagent.enabled !== false) {
      const roots = this._subWriteRoots(ctx);
      let ok = false;
      for (const root of roots) {
        if (within(root, p)) { ok = true; break; }
      }
      if (!ok) return this._deny(ctx, tool, args, '子代理/队友只能写当前工作区或临时目录：' + p);
    }
    if (matchPathDeny(p, this._compiled.warnWrite)) {
      this._warn(ctx, tool, args, '写入受保护但允许的路径（已记录）：' + p);
    }
    return undefined;
  }

  _checkCommand(command, workdir, ctx, tool, args) {
    if (typeof command !== 'string' || command.trim() === '') return undefined;
    const cfg = this._cfg;
    if (workdir !== undefined && workdir !== null && workdir !== '') {
      const w = normalizePath(workdir, ctx.cwd);
      if (w) {
        if (isNetworkPath(w) && cfg.read.denyNetworkPaths !== false) {
          return this._deny(ctx, tool, args, '工作目录为网络共享路径：' + w);
        }
        if (isOtherUserPath(w) && cfg.read.denyOtherUserProfiles !== false) {
          return this._deny(ctx, tool, args, '工作目录为其他用户目录：' + w);
        }
        if (matchPathDeny(w, this._compiled.denyRead)) {
          return this._deny(ctx, tool, args, '工作目录位于敏感区：' + w);
        }
      }
    }
    const reason = this._scanText(command, ctx, tool, args, { commandPatterns: true });
    if (reason) return reason;
    return this._checkMalware(command, ctx, tool, args);
  }

  _checkCode(code, ctx, tool, args) {
    if (!this._cfg.runCode || this._cfg.runCode.scanText === false) return undefined;
    if (typeof code !== 'string' || code === '') return undefined;
    const hasExecutionSink = /(child_process|execSync|execFileSync|spawnSync|exec\(|spawn\(|powershell\s+-|pwsh\s+-|cmd\s*\/c|ShellExecute)/i.test(code);
    const reason = this._scanText(code, ctx, tool, args, { commandPatterns: hasExecutionSink });
    if (reason) return reason;
    return this._checkMalware(code, ctx, tool, args);
  }

  _commandAllowed(text) {
    const normalized = String(text).replace(/\s+/g, ' ').trim().toLowerCase();
    for (const entry of this._compiled.allowExact) {
      if (entry.prefix ? normalized.indexOf(entry.prefix) === 0 : normalized === entry.text) return true;
    }
    return false;
  }

  _checkUrl(url, ctx, tool, args) {
    if (typeof url !== 'string' || url === '') return undefined;
    if (/^file:/i.test(url)) return this._checkRead(url, ctx, tool, args);
    return undefined;
  }

  _checkChannel(args, ctx, tool) {
    if (ctx.isSub) return this._deny(ctx, tool, args, '子代理/队友禁止向外部渠道发送内容');
    const attachments = Array.isArray(args.attachments) ? args.attachments : [];
    for (const item of attachments) {
      if (item && typeof item.path === 'string' && item.path !== '') {
        const reason = this._checkRead(item.path, ctx, tool, args);
        if (reason) return reason;
      }
    }
    this._auditOutbound(tool, args, ctx, '渠道发送（仅记录）');
    return undefined;
  }

  _checkWebFetch(url, ctx, tool, args) {
    if (typeof url !== 'string' || url === '') return undefined;
    if (!(url.indexOf('http://') === 0 || url.indexOf('https://') === 0)) {
      return this._deny(ctx, tool, args, 'web_fetch 只允许 http/https URL');
    }
    let parsed;
    try { parsed = new URL(url); } catch (e) { return undefined; }
    const cfg = this._cfg;
    if (cfg.web && cfg.web.denyLocalHosts !== false && isPrivateHost(parsed.hostname)) {
      return this._deny(ctx, tool, args, 'web_fetch 禁止访问本机/内网地址（防被诱导读取本机服务）：' + parsed.hostname);
    }
    this._auditOutbound(tool, args, ctx, '网页抓取（仅记录）');
    const suspicious = [];
    if (url.length > ((cfg.web && cfg.web.suspiciousUrlLength) || 500)) suspicious.push('URL 超长');
    if (/(?:[A-Za-z0-9+/=]{80,})/.test(parsed.search || '')) suspicious.push('URL 含长编码串');
    const keywords = (cfg.web && cfg.web.sensitiveKeywords) || [];
    const lowerUrl = url.toLowerCase();
    for (const kw of keywords) {
      if (kw && lowerUrl.indexOf(String(kw).toLowerCase()) !== -1) { suspicious.push('含敏感关键词'); break; }
    }
    if (suspicious.length > 0) {
      this._warn(ctx, tool, args, '可疑外发（' + suspicious.join('、') + '）：' + url.slice(0, 200));
    }
    return undefined;
  }

  _checkBrowser(tool, args, ctx) {
    const cfg = this._cfg;
    if (ctx.isSub && cfg.subagent && cfg.subagent.enabled !== false) {
      const denied = cfg.subagent.denyBrowserTools || [];
      if (denied.indexOf(tool) !== -1) {
        return this._deny(ctx, tool, args, '子代理/队友不允许浏览器交互/上传操作（防外发）');
      }
    }
    if (tool === 'bcdp_upload') {
      const reason = this._checkRead(args.path, ctx, tool, args);
      if (reason) return reason;
    }
    this._auditOutbound(tool, args, ctx, '浏览器操作（仅记录）');
    return undefined;
  }

  _checkNavigate(url, ctx, tool, args) {
    const reason = this._checkUrl(url, ctx, tool, args);
    if (reason) return reason;
    this._auditOutbound(tool, args, ctx, '浏览器导航（仅记录）');
    return undefined;
  }

  _auditOutbound(tool, args, ctx, reason) {
    try {
      if (tool.indexOf('web_') === 0 && this._cfg && this._cfg.web && this._cfg.web.audit === false) return;
      this._audit({
        ts: new Date().toISOString(),
        tsLocal: localTimeString(),
        session: ctx.sessionId,
        origin: ctx.isSub ? 'subagent' : 'main',
        tool: tool,
        decision: 'audit',
        outbound: true,
        reason: reason,
        preview: this._preview(tool, args)
      });
    } catch (e) {}
  }


  // ───────────────────────────────────────────────────────────
  // 恶意软件自动防护
  // ───────────────────────────────────────────────────────────

  _malwareCfg() {
    const cfg = this._cfg;
    if (!cfg || !cfg.malware) return null;
    if (cfg.malware.enabled === false) return null;
    return cfg.malware;
  }

  _quarantine() {
    const m = this._malwareCfg();
    const dir = m && m.quarantineDir ? m.quarantineDir : '';
    try {
      if (!this._quarantineInstance || this._quarantineDirUsed !== dir) {
        this._quarantineInstance = new Quarantine({ dir: dir || undefined, enabled: true });
        this._quarantineDirUsed = dir;
      }
      return this._quarantineInstance;
    } catch (e) {
      return null;
    }
  }

  _pendingQueue() {
    const q = this._quarantine();
    if (!q) return null;
    try {
      return new PendingQueue(q.dir);
    } catch (e) {
      return null;
    }
  }

  /**
   * 对命令/代码文本做恶意软件审计。
   * 从文本里提取真实存在的可执行文件路径，逐个静态审计；
   * 命中风险阈值就通知主人（并在 autoQuarantine 时移入隔离区）。
   */
  _checkMalware(text, ctx, tool, args) {
    if (this._bypassActive()) return undefined;
    const m = this._malwareCfg();
    if (!m) return undefined;
    if (ctx.isSub && m.subagentNotify === false) return undefined;
    if (typeof text !== 'string' || text.length < 4) return undefined;

    let targets = [];
    try {
      targets = extractTargetPaths(text, ctx.cwd);
    } catch (e) {
      return undefined;
    }
    if (targets.length === 0) return undefined;

    const results = [];
    for (const target of targets) {
      // Own source: skip the keyword verdict; executables are still audited
      if (isSelfSource(target) && !SELF_BINARY_EXT.has(path.extname(target).toLowerCase())) continue;
      let r;
      try {
        r = auditFile(target, { maxBytes: m.maxBytes });
      } catch (e) {
        continue;
      }
      if (!r || !r.exists) continue;
      if (r.level === 'clean' || r.level === 'unknown') continue;
      if (r.score < Number(m.blockAt || 30)) continue;
      results.push(r);
    }
    if (results.length === 0) return undefined;

    // 记录到待决队列 + 可选自动隔离
    const queue = this._pendingQueue();
    const quarantine = this._quarantine();
    const quarantined = [];

    for (const r of results) {
      try {
        if (queue) queue.push({ path: r.path, level: r.level, score: r.score, summary: r.summary, findings: r.findings, source: tool });
      } catch (e) { /* ignore */ }
      if (m.autoQuarantine !== false && quarantine && !ctx.isSub) {
        try {
          const res = quarantine.add(r.path, { reason: 'malware-audit: ' + r.summary, audit: r, decision: 'auto-quarantine' });
          if (res && res.ok) quarantined.push({ path: r.path, id: res.id });
        } catch (e) { /* ignore */ }
      }
    }

    // 组装中文提示
    const lines = [];
    lines.push('检测到 ' + results.length + ' 个可疑文件，已拦下等你决定：');
    for (const r of results) {
      const lv = { low: '低风险', medium: '中风险', high: '高风险' }[r.level] || r.level;
      lines.push('');
      lines.push('· ' + r.path);
      lines.push('  ' + lv + ' · 风险分 ' + r.score + '/100');
      if (r.summary) lines.push('  ' + r.summary);
      const top = (r.findings || []).slice().sort(function (a, b) { return (b.weight || 0) - (a.weight || 0); }).slice(0, 4);
      for (const f of top) {
        lines.push('  - ' + f.label + (f.detail ? '（' + f.detail + '）' : ''));
      }
      const q = quarantined.find(function (x) { return x.path === r.path; });
      if (q) lines.push('  已移入隔离区：' + q.id);
    }
    lines.push('');
    lines.push('告诉我要「留着」还是「删掉」，或者「先放着」，我再动手。');

    const message = lines.join(String.fromCharCode(10));

    if (m.notifyOnly === true || ctx.isSub) {
      this._warn(ctx, tool, args, '恶意软件审计告警（仅通知）：' + results.map(function (r) { return r.path + '(' + r.score + ')'; }).join(', '));
      return undefined;
    }

    this._audit({
      ts: new Date().toISOString(),
      tsLocal: localTimeString(),
      session: ctx.sessionId,
      origin: ctx.isSub ? 'subagent' : 'main',
      tool: tool,
      decision: 'malware-block',
      reason: results.map(function (r) { return r.path + ' score=' + r.score + ' level=' + r.level; }).join(' | '),
      preview: this._preview(tool, args),
    });
    return message;
  }

  _scanText(text, ctx, tool, args, options) {
    const cfg = this._cfg;
    const opts = options || {};
    const expanded = expandVars(text);
    const compact = expanded.toLowerCase().replace(/\//g, '\\');
    if (cfg.commands.denyPathsInText !== false) {
      for (const deny of this._compiled.denyRead) {
        if (deny && compact.indexOf(keyOf(deny)) !== -1) {
          return this._deny(ctx, tool, args, '命令/代码引用了敏感路径：' + deny);
        }
      }
      const protectedHit = this._compiled.protectedText.find(function (deny) {
        return deny && compact.indexOf(keyOf(deny)) !== -1;
      });
      const writeIntent = Boolean(PROTECTED_DIR_KEY)
        && compact.indexOf(PROTECTED_DIR_KEY) !== -1
        && WRITE_VERB_RE.test(compact);
      if (protectedHit && writeIntent) {
        return this._deny(ctx, tool, args, '命令/代码试图改动防护配置（禁止）：' + protectedHit);
      }
    }
    for (const token of ['approve-install', 'install-approval.json']) {
      if (compact.indexOf(token) !== -1) {
        return this._deny(ctx, tool, args, '命令/代码引用了安装批准机制（禁止由模型操作）');
      }
    }
    const otherUser = /c:\\users\\([^\\\s"']+)/i.exec(compact);
    if (otherUser && !isCurrentUserDirName(otherUser[1])) {
      return this._deny(ctx, tool, args, '命令/代码引用了其他用户目录：' + otherUser[1]);
    }
    if (/(^|[\s"'=;,(])\\\\[a-z0-9]/i.test(expanded)) {
      return this._deny(ctx, tool, args, '命令/代码访问网络共享路径');
    }
    if (opts.commandPatterns !== false) {
      const allowedByOwner = this._commandAllowed(expanded);
      const denyMode = cfg.commands.mode !== 'warn';
      if (!allowedByOwner) {
        const installHit = this._matchInstall(expanded);
        if (installHit) {
          if (!ctx.isSub && this._consumeInstallApproval()) {
            this._auditApprove(ctx, tool, args, '主人双击批准安装：' + String(installHit));
          } else if (!denyMode) {
            this._warn(ctx, tool, args, '安装类命令（warn 模式，已记录）：' + String(installHit));
          } else {
            return this._deny(ctx, tool, args, '安装/下载程序需要主人同意：请双击桌面「安装放行」图标（或 alpha-guard 目录下 approve-install.cmd），2 分钟内有效、一次使用。命中规则：' + String(installHit));
          }
        } else {
          for (const re of this._compiled.cmdDeny) {
            if (re.test(expanded)) {
              if (!denyMode) {
                this._warn(ctx, tool, args, '命令命中高危规则（warn 模式，已记录）：' + String(re));
                break;
              }
              return this._deny(ctx, tool, args, '命令/代码命中高危规则：' + String(re));
            }
          }
        }
      } else {
        this._warn(ctx, tool, args, '命令命中主人 allowExact 白名单，已放行：' + this._preview(tool, args));
      }
      for (const re of this._compiled.cmdWarn) {
        if (re.test(expanded)) {
          this._warn(ctx, tool, args, '命令命中提示规则（已记录）：' + String(re));
          break;
        }
      }
    }
    return undefined;
  }

  _matchInstall(text) {
    for (const re of this._compiled.installDeny) {
      if (re.test(text)) return re;
    }
    return undefined;
  }

  _consumeInstallApproval() {
    const cfg = this._cfg;
    if (!cfg || !cfg.installApproval || cfg.installApproval.enabled === false) return false;
    try {
      const file = cfg.installApproval.path ? normalizePath(cfg.installApproval.path, HOME) : DEFAULT_APPROVAL_PATH;
      const raw = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
      const parsed = JSON.parse(raw);
      const ts = Number(parsed.ts || 0);
      const windowSeconds = Number(cfg.installApproval.windowSeconds || 120);
      const age = Date.now() / 1000 - ts;
      if (!(ts > 0) || age < 0 || age > windowSeconds) return false;
      fs.writeFileSync(file, JSON.stringify({ used: true, usedAt: Date.now() }), 'utf8');
      return true;
    } catch (e) {
      return false;
    }
  }

  _auditApprove(ctx, tool, args, reason) {
    try {
      this._audit({
        ts: new Date().toISOString(),
        tsLocal: localTimeString(),
        session: ctx.sessionId,
        origin: ctx.isSub ? 'subagent' : 'main',
        tool: tool,
        decision: 'approve',
        reason: reason,
        preview: this._preview(tool, args)
      });
    } catch (e) {}
  }

  // ───────────────────────────────────────────────────────────
  // 对外 API（供 index.js 注册工具或脚本调用）
  // ───────────────────────────────────────────────────────────

  /** 审计单个文件，返回结果对象（注意：不能用 auditPath 作名字，构造函数里已有同名字段存日志路径） */
  auditTarget(filePath) {
    const m = this._malwareCfg();
    const maxBytes = m ? m.maxBytes : undefined;
    return auditFile(filePath, { maxBytes: maxBytes });
  }

  /** 审计一批文件 */
  auditTargets(filePaths) {
    const m = this._malwareCfg();
    const maxBytes = m ? m.maxBytes : undefined;
    const out = [];
    for (const p of filePaths || []) out.push(auditFile(p, { maxBytes: maxBytes }));
    out.sort(function (a, b) { return (b.score || 0) - (a.score || 0); });
    return out;
  }

  /** 列出隔离区 */
  listQuarantine() {
    const q = this._quarantine();
    if (!q) return { ok: false, error: '隔离区不可用' };
    return { ok: true, items: q.list(), stats: q.stats() };
  }

  /** 把文件移入隔离区 */
  quarantineFile(filePath, reason) {
    const q = this._quarantine();
    if (!q) return { ok: false, error: '隔离区不可用' };
    return q.add(filePath, { reason: reason || '主人手动隔离', decision: 'owner-manual' });
  }

  /** 从隔离区取出 */
  restoreQuarantined(id, targetPath) {
    const q = this._quarantine();
    if (!q) return { ok: false, error: '隔离区不可用' };
    return q.restore(id, targetPath);
  }

  /** 永久删除隔离项 */
  deleteQuarantined(id) {
    const q = this._quarantine();
    if (!q) return { ok: false, error: '隔离区不可用' };
    return q.remove(id);
  }

  /** 待决队列 */
  listPending() {
    const pq = this._pendingQueue();
    if (!pq) return { ok: false, error: '待决队列不可用' };
    return { ok: true, items: pq.pending() };
  }

  resolvePending(id, status) {
    const pq = this._pendingQueue();
    if (!pq) return { ok: false, error: '待决队列不可用' };
    return pq.resolve(id, status);
  }

  _redact(text) {
    let s = String(text);
    s = s.replace(/(sk-[A-Za-z0-9_-]{6,})/g, 'sk-***');
    s = s.replace(/(ghp_[A-Za-z0-9]{10,})/g, 'ghp_***');
    s = s.replace(/([A-Za-z0-9_-]{40,})/g, '***');
    s = s.replace(/((?:password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]\s*)([^\s"',;]{3,})/gi, '$1***');
    return s;
  }

  _preview(tool, args) {
    try {
      if (!args || typeof args !== 'object') return '';
      if (typeof args.file_path === 'string') return this._redact(args.file_path);
      if (typeof args.path === 'string') return this._redact(args.path);
      if (typeof args.command === 'string') return this._redact(args.command.slice(0, 300));
      if (typeof args.code === 'string') return this._redact(args.code.slice(0, 200));
      if (typeof args.url === 'string') return this._redact(args.url);
      const json = JSON.stringify(args);
      return typeof json === 'string' ? this._redact(json.slice(0, 200)) : '';
    } catch (e) {
      return '';
    }
  }

  // 限时放行：桌面「限时放行」图标激活后，窗口内直接放行
  _bypassActive() {
    try {
      const bp = path.join(path.dirname(this.configPath), 'guard-bypass.json');
      if (!fs.existsSync(bp)) return false;
      const st = JSON.parse(fs.readFileSync(bp, 'utf8'));
      if (!st || st.active !== true || !st.until) return false;
      const until = new Date(st.until).getTime();
      if (!Number.isFinite(until)) return false;
      return Date.now() < until;
    } catch (e) {
      return false;
    }
  }

  _deny(ctx, tool, args, reason) {
    const preview = this._preview(tool, args);
    const message = 'alpha-guard 拒绝：' + reason
      + '。工具=' + tool
      + (preview ? '，参数=' + preview : '')
      + '。这是主人的安全策略；如确需，请主人手动修改 ' + DEFAULT_CONFIG_PATH + '。';
    this._audit({
      ts: new Date().toISOString(),
      tsLocal: localTimeString(),
      session: ctx.sessionId,
      origin: ctx.isSub ? 'subagent' : 'main',
      tool: tool,
      decision: 'deny',
      reason: reason,
      preview: preview
    });
    return message;
  }

  _warn(ctx, tool, args, reason) {
    this._audit({
      ts: new Date().toISOString(),
      tsLocal: localTimeString(),
      session: ctx.sessionId,
      origin: ctx.isSub ? 'subagent' : 'main',
      tool: tool,
      decision: 'warn',
      reason: reason,
      preview: this._preview(tool, args)
    });
  }

  _audit(entry) {
    try {
      const cfg = this._cfg;
      if (!cfg || !cfg.audit || cfg.audit.enabled === false) return;
      fs.mkdirSync(path.dirname(this.auditPath), { recursive: true });
      fs.appendFileSync(this.auditPath, JSON.stringify(entry) + '\n', 'utf8');
      this._auditCount += 1;
      if (this._auditCount % 20 === 0) {
        try {
          const stat = fs.statSync(this.auditPath);
          const max = cfg.audit.maxBytes || 5242880;
          if (stat.size > max) {
            const backup = this.auditPath + '.1';
            try { fs.rmSync(backup, { force: true }); } catch (e) {}
            fs.renameSync(this.auditPath, backup);
          }
        } catch (e) {}
      }
    } catch (e) {
      try { console.error('[alpha-guard] audit write failed: ' + String(e)); } catch (e2) {}
    }
  }
}
