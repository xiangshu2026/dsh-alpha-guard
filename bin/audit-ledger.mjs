#!/usr/bin/env node
// dsh-alpha-guard · DeepSeek Harness 策略层护栏
// https://github.com/xiangshu2026/dsh-alpha-guard
/**
 * audit-ledger.mjs —— alpha-guard 审计日志完整性账本
 *
 * 来源：2026-10-31 从「大肥鱼记忆系统」学到的三道保险之二（文本账本）
 * 目的：证明 audit.jsonl 没被篡改过（改一条、删一条、插一条都能查出来）
 *
 * 用法：
 *   node audit-ledger.mjs --init            首次建立账本
 *   node audit-ledger.mjs --sync            把新增行补进账本（老记录不覆盖）
 *   node audit-ledger.mjs --verify          校验（不一致则退出码 1）
 *   node audit-ledger.mjs --verify --quiet  只输出结论
 *   node audit-ledger.mjs --stats           看账本统计
 *
 * 纪律：先 sync 再 verify。反过来会把新增行误报成「被篡改」。
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';

const HOME = os.homedir();
const GUARD_DIR = process.env.AG_DIR || path.join(HOME, '.dsh', 'alpha-guard');
const AUDIT = process.env.AG_AUDIT || path.join(GUARD_DIR, 'audit.jsonl');
const LEDGER = process.env.AG_LEDGER || path.join(GUARD_DIR, 'audit-ledger.json');

const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

function readLines(file) {
  if (!fs.existsSync(file)) return [];
  const raw = fs.readFileSync(file, 'utf8');
  return raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
}

/** 每行用「行号 + 内容哈希」登记，行号能抓住删除，哈希能抓住改写 */
function buildEntry(lineNo, text) {
  return { n: lineNo, sha256: sha(text), len: text.length };
}

function loadLedger() {
  if (!fs.existsSync(LEDGER)) return null;
  try {
    return JSON.parse(fs.readFileSync(LEDGER, 'utf8'));
  } catch (e) {
    console.error('[ledger] 账本文件损坏：' + e.message);
    return null;
  }
}

function saveLedger(obj) {
  fs.writeFileSync(LEDGER, JSON.stringify(obj, null, 0), 'utf8');
}

function cmdInit() {
  if (fs.existsSync(LEDGER)) {
    console.error('[ledger] 账本已存在，拒绝覆盖。要重建请先手动备份并删除：' + LEDGER);
    process.exit(2);
  }
  const lines = readLines(AUDIT);
  const entries = lines.map((t, i) => buildEntry(i + 1, t));
  const now = new Date().toISOString();
  saveLedger({ version: 1, createdAt: now, lastSync: now, count: entries.length, entries });
  console.log('[ledger] 建立完成：' + entries.length + ' 行');
  console.log('[ledger] 账本路径：' + LEDGER);
}

function cmdSync() {
  const led = loadLedger();
  if (!led) {
    console.error('[ledger] 没有账本，先跑 --init');
    process.exit(2);
  }
  const lines = readLines(AUDIT);
  const have = new Set(led.entries.map((e) => e.n));
  let added = 0;
  for (let i = 0; i < lines.length; i++) {
    const n = i + 1;
    if (have.has(n)) continue;
    led.entries.push(buildEntry(n, lines[i]));
    added++;
  }
  led.entries.sort((a, b) => a.n - b.n);
  led.count = led.entries.length;
  led.lastSync = new Date().toISOString();
  saveLedger(led);
  console.log('[ledger] 同步完成：新增 ' + added + ' 行，账本共 ' + led.count + ' 行');
}

function cmdVerify(quiet) {
  const led = loadLedger();
  if (!led) {
    console.error('[ledger] 没有账本，先跑 --init');
    process.exit(2);
  }
  const lines = readLines(AUDIT);
  const problems = [];

  // 1) 改写检测：账本里登记过的行，内容必须一字不差
  for (const e of led.entries) {
    const cur = lines[e.n - 1];
    if (cur === undefined) {
      problems.push({ kind: 'missing', n: e.n, detail: '第 ' + e.n + ' 行不见了' });
      continue;
    }
    const h = sha(cur);
    if (h !== e.sha256) {
      problems.push({ kind: 'modified', n: e.n, detail: '第 ' + e.n + ' 行内容被改' });
    }
  }

  // 2) 新增检测：账本之后新增的行（正常情况，sync 一下就好）
  const ledMax = led.entries.reduce((m, e) => Math.max(m, e.n), 0);
  const appended = Math.max(0, lines.length - ledMax);

  // 3) 插入检测：账本覆盖范围内，行数比账本多
  const inRange = lines.slice(0, ledMax).length;
  if (inRange !== led.entries.length) {
    problems.push({
      kind: 'count',
      detail: '账本范围内应有 ' + led.entries.length + ' 行，实际 ' + inRange + ' 行',
    });
  }

  const ok = problems.length === 0;
  if (!quiet) {
    console.log('──────────────────────────────');
    console.log('账本登记   ' + led.entries.length + ' 行');
    console.log('当前文件   ' + lines.length + ' 行');
    console.log('账本外新增 ' + appended + ' 行' + (appended > 0 ? '（正常，跑 --sync 补进账本）' : ''));
    if (ok) {
      console.log('结论       OK · 已登记的 ' + led.entries.length + ' 行全部一致');
    } else {
      console.log('结论       ❌ 发现 ' + problems.length + ' 处异常：');
      for (const p of problems.slice(0, 20)) console.log('  [' + p.kind + '] ' + p.detail);
      if (problems.length > 20) console.log('  ...还有 ' + (problems.length - 20) + ' 处');
    }
    console.log('──────────────────────────────');
  }
  process.exit(ok ? 0 : 1);
}

function cmdStats() {
  const led = loadLedger();
  if (!led) {
    console.error('[ledger] 没有账本，先跑 --init');
    process.exit(2);
  }
  const lines = readLines(AUDIT);
  const sz = fs.existsSync(AUDIT) ? fs.statSync(AUDIT).size : 0;
  console.log('账本建立   ' + led.createdAt);
  console.log('最后同步   ' + (led.lastSync || '从未'));
  console.log('账本登记   ' + led.entries.length + ' 行');
  console.log('当前文件   ' + lines.length + ' 行 / ' + (sz / 1024).toFixed(1) + ' KB');
  console.log('未登记     ' + Math.max(0, lines.length - led.entries.length) + ' 行');
}

const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const quiet = has('--quiet');

if (has('--init')) cmdInit();
else if (has('--sync')) cmdSync();
else if (has('--verify')) cmdVerify(quiet);
else if (has('--stats')) cmdStats();
else {
  console.log('用法：');
  console.log('  node audit-ledger.mjs --init    首次建立账本');
  console.log('  node audit-ledger.mjs --sync    补进新增行');
  console.log('  node audit-ledger.mjs --verify  校验');
  console.log('  node audit-ledger.mjs --stats   统计');
}
