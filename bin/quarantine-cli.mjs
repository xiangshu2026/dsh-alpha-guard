#!/usr/bin/env node
// dsh-alpha-guard · DeepSeek Harness 策略层护栏
// https://github.com/xiangshu2026/dsh-alpha-guard
/**
 * alpha-guard 隔离区命令行工具
 *
 * 用法（用 bundled node 运行）：
 *   node quarantine-cli.mjs list                    列出隔离区
 *   node quarantine-cli.mjs pending                 列出待决队列（等你决定的可疑文件）
 *   node quarantine-cli.mjs audit <文件...>          静态审计（不移动文件）
 *   node quarantine-cli.mjs put <文件> [原因]        手动移入隔离区
 *   node quarantine-cli.mjs get <id> [目标路径]      从隔离区取出（恢复）
 *   node quarantine-cli.mjs del <id>                永久删除隔离项
 *   node quarantine-cli.mjs stats                   统计
 */
import path from 'node:path';
import { auditFile, formatReport } from '../lib/malware-audit.js';
import { Quarantine, PendingQueue, DEFAULT_QUARANTINE_DIR } from '../lib/quarantine.js';

const args = process.argv.slice(2);
const cmd = args[0] || 'list';

function out(text) {
  process.stdout.write(String(text) + String.fromCharCode(10));
}

function makeQ() {
  return new Quarantine({ dir: DEFAULT_QUARANTINE_DIR });
}

switch (cmd) {
  case 'list': {
    const q = makeQ();
    const items = q.list();
    const st = q.stats();
    if (items.length === 0) {
      out('隔离区是空的。');
      out('目录：' + st.dir);
      break;
    }
    out('隔离区：' + st.dir + '（' + st.count + ' 项 / ' + (st.bytes / 1048576).toFixed(1) + ' MB）');
    out('');
    for (const it of items) {
      out('ID    : ' + it.id);
      out('原名  : ' + it.originalName);
      out('原路径: ' + it.originalPath);
      out('风险  : ' + it.level + ' / ' + it.score + ' 分');
      out('时间  : ' + it.quarantinedAt);
      if (it.reason) out('原因  : ' + it.reason);
      out('');
    }
    break;
  }

  case 'pending': {
    const q = makeQ();
    const pq = new PendingQueue(q.dir);
    const items = pq.pending();
    if (items.length === 0) {
      out('待决队列为空，没有等你决定的可疑文件。');
      break;
    }
    out('待你决定的可疑文件（' + items.length + ' 项）：');
    out('');
    for (const it of items) {
      out('ID    : ' + it.id);
      out('路径  : ' + it.path);
      out('风险  : ' + it.level + ' / ' + it.score + ' 分');
      out('摘要  : ' + it.summary);
      out('检出  : ' + it.detectedAt);
      out('');
    }
    break;
  }

  case 'audit': {
    const files = args.slice(1);
    if (files.length === 0) {
      out('用法：audit <文件路径...>');
      process.exitCode = 2;
      break;
    }
    const results = files.map(function (f) { return auditFile(path.resolve(f), {}); });
    out(formatReport(results));
    break;
  }

  case 'put': {
    const target = args[1];
    if (!target) {
      out('用法：put <文件路径> [原因]');
      process.exitCode = 2;
      break;
    }
    const abs = path.resolve(target);
    const audit = auditFile(abs, {});
    const q = makeQ();
    const res = q.add(abs, { reason: args[2] || '主人手动隔离', audit: audit, decision: 'owner-manual' });
    if (res.ok) {
      out('已移入隔离区：' + res.id);
      out('原路径：' + abs);
      out('风险：' + audit.level + ' / ' + audit.score + ' 分');
    } else {
      out('失败：' + res.error);
      process.exitCode = 1;
    }
    break;
  }

  case 'get': {
    const id = args[1];
    if (!id) {
      out('用法：get <id> [目标路径]');
      process.exitCode = 2;
      break;
    }
    const q = makeQ();
    const res = q.restore(id, args[2]);
    if (res.ok) {
      out('已取出：' + res.restoredTo);
    } else {
      out('失败：' + res.error);
      process.exitCode = 1;
    }
    break;
  }

  case 'del': {
    const id = args[1];
    if (!id) {
      out('用法：del <id>');
      process.exitCode = 2;
      break;
    }
    const q = makeQ();
    const res = q.remove(id);
    out(res.ok ? '已永久删除：' + id : '失败：' + res.error);
    if (!res.ok) process.exitCode = 1;
    break;
  }

  case 'stats': {
    const q = makeQ();
    const st = q.stats();
    out('隔离区目录：' + st.dir);
    out('当前隔离：' + st.count + ' 项 / ' + (st.bytes / 1048576).toFixed(1) + ' MB');
    out('历史取出：' + st.restored + ' 次');
    out('历史删除：' + st.deleted + ' 次');
    break;
  }

  default:
    out('未知命令：' + cmd);
    out('可用：list / pending / audit / put / get / del / stats');
    process.exitCode = 2;
}
