// dsh-alpha-guard · DeepSeek Harness 策略层护栏
// https://github.com/xiangshu2026/dsh-alpha-guard
/**
 * dsh-alpha-guard · quarantine
 *
 * 隔离区（沙盒）：把可疑文件从原位置移走、去掉可执行扩展名、加上禁止执行的 ACL，
 * 主人要的时候再原样提出来。
 *
 * 目录布局（默认 ~/.dsh/alpha-guard/quarantine/）：
 *   <id>.bin      原始字节，扩展名一律改成 .bin —— 双击不会运行
 *   <id>.json     元数据：原始路径、原名、sha256、大小、隔离时间、原因、审计结论
 *   index.json    索引（便于列表与恢复）
 *
 * 安全约束：
 *  - 隔离后文件不可执行（扩展名 + ACL 双重）；
 *  - 恢复时必须显式给出 id，且记录到审计日志；
 *  - 永不自动删除：只能主人明确要求才 delete。
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const HOME = os.homedir();
export const DEFAULT_QUARANTINE_DIR = path.join(HOME, '.dsh', 'alpha-guard', 'quarantine');

const INDEX_NAME = 'index.json';
const EXECUTABLE_EXTS = new Set([
  '.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.msi', '.msix',
  '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
  '.jar', '.crx', '.com', '.pif', '.hta', '.reg', '.lnk',
]);

function nowIso() {
  return new Date().toISOString();
}

function localStamp() {
  const d = new Date();
  const pad = function (n) { return (n < 10 ? '0' : '') + n; };
  return d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) + '-' + pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds());
}

function newId() {
  const rand = crypto.randomBytes(3).toString('hex');
  return localStamp() + '-' + rand;
}

function readJsonSafe(file, fallback) {
  try {
    const raw = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
    return JSON.parse(raw);
  } catch (e) {
    return fallback;
  }
}

function writeJsonAtomic(file, value) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}

function sha256File(filePath) {
  try {
    const hash = crypto.createHash('sha256');
    const fd = fs.openSync(filePath, 'r');
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    let read = 0;
    let total = 0;
    while ((read = fs.readSync(fd, chunk, 0, chunk.length, total)) > 0) {
      hash.update(chunk.subarray(0, read));
      total += read;
    }
    fs.closeSync(fd);
    return hash.digest('hex');
  } catch (e) {
    return '';
  }
}

/**
 * 给隔离目录加 ACL：当前用户完全控制，但**拒绝执行**。
 * 这样即使有人把 .bin 改回 .exe，也在这个目录里跑不起来。
 */
function hardenDirectory(dir) {
  const notes = [];
  try {
    // 关闭继承，去掉 Users 的权限，只留当前用户（拒绝执行位）
    const user = process.env.USERNAME || '';
    execFileSync('icacls', [dir, '/inheritance:r'], { stdio: 'ignore', windowsHide: true });
    if (user) {
      execFileSync('icacls', [dir, '/grant:r', user + ':(OI)(CI)F'], { stdio: 'ignore', windowsHide: true });
      execFileSync('icacls', [dir, '/deny', user + ':(OI)(CI)(X)'], { stdio: 'ignore', windowsHide: true });
      notes.push('ACL 已加固：' + user + ' 完全控制但拒绝执行');
    }
  } catch (e) {
    notes.push('ACL 加固失败（文件仍已改名 .bin）：' + String(e && e.message ? e.message : e));
  }
  return notes;
}

export class Quarantine {
  constructor(options) {
    const opts = options || {};
    this.dir = opts.dir ? path.resolve(opts.dir) : DEFAULT_QUARANTINE_DIR;
    this.enabled = opts.enabled !== false;
    this.ensure();
  }

  ensure() {
    try {
      fs.mkdirSync(this.dir, { recursive: true });
      const idx = path.join(this.dir, INDEX_NAME);
      if (!fs.existsSync(idx)) writeJsonAtomic(idx, { version: 1, items: [] });
    } catch (e) {
      // 目录建不了就让后续操作自然失败并返回错误
    }
  }

  indexPath() {
    return path.join(this.dir, INDEX_NAME);
  }

  readIndex() {
    const data = readJsonSafe(this.indexPath(), { version: 1, items: [] });
    if (!data || !Array.isArray(data.items)) return { version: 1, items: [] };
    return data;
  }

  writeIndex(data) {
    writeJsonAtomic(this.indexPath(), data);
  }

  /**
   * 把文件移入隔离区。
   *
   * @param {string} filePath 原文件绝对路径
   * @param {object} meta { reason, audit, askedBy, decision }
   * @returns {object} { ok, id, error, item }
   */
  add(filePath, meta) {
    if (!this.enabled) return { ok: false, error: '隔离区未启用（config.malware.quarantine.enabled = false）' };
    const abs = path.resolve(filePath);
    let stat;
    try {
      stat = fs.statSync(abs);
    } catch (e) {
      return { ok: false, error: '文件不存在或无法访问：' + abs };
    }
    if (!stat.isFile()) return { ok: false, error: '目标不是普通文件：' + abs };

    // 不允许把隔离区自己的文件再隔离
    if (abs.toLowerCase().indexOf(this.dir.toLowerCase()) === 0) {
      return { ok: false, error: '目标已在隔离区内' };
    }

    this.ensure();
    const id = newId();
    const blobPath = path.join(this.dir, id + '.bin');
    const metaPath = path.join(this.dir, id + '.json');
    const originalName = path.basename(abs);
    const ext = path.extname(abs).toLowerCase();
    const hash = sha256File(abs);

    let moved = false;
    let copyMode = 'move';
    try {
      fs.renameSync(abs, blobPath);
      moved = true;
    } catch (e) {
      // 跨卷或占用时退化为"复制 + 改名 + 删除原文件"
      try {
        fs.copyFileSync(abs, blobPath);
        copyMode = 'copy';
        try {
          fs.rmSync(abs, { force: true });
          moved = true;
        } catch (e2) {
          // 原文件删不掉（被占用），至少副本已隔离
          moved = true;
          copyMode = 'copy-left-original';
        }
      } catch (e3) {
        return { ok: false, error: '隔离失败：' + String(e3 && e3.message ? e3.message : e3) };
      }
    }
    if (!moved) return { ok: false, error: '隔离失败：无法移动文件' };

    const item = {
      id: id,
      originalPath: abs,
      originalName: originalName,
      originalExt: ext,
      wasExecutable: EXECUTABLE_EXTS.has(ext),
      blob: path.basename(blobPath),
      size: stat.size,
      sha256: hash,
      quarantinedAt: nowIso(),
      reason: (meta && meta.reason) || '',
      audit: (meta && meta.audit) || null,
      decision: (meta && meta.decision) || 'owner-approved',
      copyMode: copyMode,
      aclNotes: [],
    };
    item.aclNotes = hardenDirectory(this.dir);

    try {
      writeJsonAtomic(metaPath, item);
    } catch (e) {
      // 元数据写失败也要保证索引有记录
    }

    const idx = this.readIndex();
    idx.items.push({
      id: item.id,
      originalPath: item.originalPath,
      originalName: item.originalName,
      size: item.size,
      sha256: item.sha256,
      quarantinedAt: item.quarantinedAt,
      reason: item.reason,
      level: item.audit ? item.audit.level : 'unknown',
      score: item.audit ? item.audit.score : 0,
    });
    this.writeIndex(idx);

    return { ok: true, id: id, item: item };
  }

  list() {
    const idx = this.readIndex();
    return idx.items.slice().sort(function (a, b) {
      return String(b.quarantinedAt).localeCompare(String(a.quarantinedAt));
    });
  }

  get(id) {
    const idx = this.readIndex();
    const found = idx.items.find(function (it) { return it.id === id; });
    if (!found) return null;
    const meta = readJsonSafe(path.join(this.dir, id + '.json'), null);
    return meta || found;
  }

  /**
   * 把隔离的文件提出去（恢复）。
   *
   * @param {string} id 隔离项 id
   * @param {string} targetPath 可选，恢复到哪里（默认原路径；原路径已存在则加 .restored 后缀）
   * @returns {object} { ok, restoredTo, error }
   */
  restore(id, targetPath) {
    const item = this.get(id);
    if (!item) return { ok: false, error: '找不到隔离项：' + id };
    const blobPath = path.join(this.dir, item.blob || (id + '.bin'));
    if (!fs.existsSync(blobPath)) return { ok: false, error: '隔离文件丢失：' + blobPath };

    let dest = targetPath ? path.resolve(targetPath) : path.resolve(item.originalPath);
    try {
      fs.mkdirSync(path.dirname(dest), { recursive: true });
    } catch (e) { /* ignore */ }

    // 目标已存在时避免覆盖
    if (fs.existsSync(dest)) {
      const ext = path.extname(dest);
      const base = dest.slice(0, dest.length - ext.length);
      dest = base + '.restored' + ext;
    }

    try {
      fs.copyFileSync(blobPath, dest);
    } catch (e) {
      return { ok: false, error: '恢复失败：' + String(e && e.message ? e.message : e) };
    }

    // 从索引里移除，但保留一份恢复记录
    const idx = this.readIndex();
    const keep = idx.items.filter(function (it) { return it.id !== id; });
    idx.items = keep;
    idx.restored = Array.isArray(idx.restored) ? idx.restored : [];
    idx.restored.push({ id: id, restoredTo: dest, restoredAt: nowIso(), originalPath: item.originalPath });
    this.writeIndex(idx);

    try { fs.rmSync(blobPath, { force: true }); } catch (e) { /* ignore */ }
    try { fs.rmSync(path.join(this.dir, id + '.json'), { force: true }); } catch (e) { /* ignore */ }

    return { ok: true, restoredTo: dest, id: id };
  }

  /**
   * 永久删除隔离项（不可恢复）。
   */
  remove(id) {
    const item = this.get(id);
    if (!item) return { ok: false, error: '找不到隔离项：' + id };
    const blobPath = path.join(this.dir, item.blob || (id + '.bin'));
    try {
      fs.rmSync(blobPath, { force: true });
    } catch (e) {
      return { ok: false, error: '删除失败：' + String(e && e.message ? e.message : e) };
    }
    try { fs.rmSync(path.join(this.dir, id + '.json'), { force: true }); } catch (e) { /* ignore */ }

    const idx = this.readIndex();
    idx.items = idx.items.filter(function (it) { return it.id !== id; });
    idx.deleted = Array.isArray(idx.deleted) ? idx.deleted : [];
    idx.deleted.push({ id: id, originalPath: item.originalPath, deletedAt: nowIso() });
    this.writeIndex(idx);
    return { ok: true, id: id };
  }

  /** 统计信息 */
  stats() {
    const idx = this.readIndex();
    let bytes = 0;
    for (const it of idx.items) bytes += Number(it.size) || 0;
    return {
      dir: this.dir,
      count: idx.items.length,
      bytes: bytes,
      restored: (idx.restored || []).length,
      deleted: (idx.deleted || []).length,
    };
  }
}

/**
 * 待主人决定的队列（pending）。
 *
 * 流程：检出可疑文件 → 进 pending（只记录，不动文件）→ 通知主人
 *       → 主人说"留着" → quarantine.add()
 *       → 主人说"不要" → 主人自己决定删（或主人明确授权后删）
 *
 * pending 存在 quarantine 目录的 pending.json，避免再开一个目录。
 */
export class PendingQueue {
  constructor(dir) {
    this.dir = dir ? path.resolve(dir) : DEFAULT_QUARANTINE_DIR;
    this.file = path.join(this.dir, 'pending.json');
    try { fs.mkdirSync(this.dir, { recursive: true }); } catch (e) { /* ignore */ }
    if (!fs.existsSync(this.file)) writeJsonAtomic(this.file, { version: 1, items: [] });
  }

  read() {
    const data = readJsonSafe(this.file, { version: 1, items: [] });
    if (!data || !Array.isArray(data.items)) return { version: 1, items: [] };
    return data;
  }

  write(data) {
    writeJsonAtomic(this.file, data);
  }

  /** 加入待决队列；同一个路径不重复加 */
  push(entry) {
    const data = this.read();
    const key = String(entry.path || '').toLowerCase();
    const exists = data.items.find(function (it) {
      return String(it.path || '').toLowerCase() === key && it.status === 'pending';
    });
    if (exists) return exists;
    const item = {
      id: newId(),
      path: entry.path,
      level: entry.level || 'unknown',
      score: entry.score || 0,
      summary: entry.summary || '',
      findings: entry.findings || [],
      detectedAt: nowIso(),
      status: 'pending',
      source: entry.source || '',
    };
    data.items.push(item);
    this.write(data);
    return item;
  }

  list(status) {
    const data = this.read();
    const items = data.items.slice();
    if (status) return items.filter(function (it) { return it.status === status; });
    return items;
  }

  pending() {
    return this.list('pending');
  }

  /** 标记状态：resolved-keep / resolved-quarantine / resolved-delete / dismissed */
  resolve(id, status) {
    const data = this.read();
    const item = data.items.find(function (it) { return it.id === id; });
    if (!item) return { ok: false, error: '找不到待决项：' + id };
    item.status = status;
    item.resolvedAt = nowIso();
    this.write(data);
    return { ok: true, item: item };
  }

  /** 清掉已处理的老记录 */
  prune(days) {
    const cutoff = Date.now() - (Number(days) > 0 ? Number(days) : 30) * 86400000;
    const data = this.read();
    const before = data.items.length;
    data.items = data.items.filter(function (it) {
      if (it.status === 'pending') return true;
      const t = Date.parse(it.resolvedAt || it.detectedAt || 0);
      return !(t > 0 && t < cutoff);
    });
    this.write(data);
    return { removed: before - data.items.length, remaining: data.items.length };
  }
}

export const EXECUTABLE_EXTENSIONS = Array.from(EXECUTABLE_EXTS);
