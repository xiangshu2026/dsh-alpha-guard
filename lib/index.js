/**
 * dsh-alpha-guard
 *
 * 主人专属防护插件：注册一个全局 tools.guard，对每次工具调用做策略检查。
 * 策略细节见 lib/policy.js 与 README.md。
 *
 * 设计原则：
 *  - 绝不因为插件自身异常而阻塞所有工具调用（除非 config.failClosed = true）；
 *  - 配置热加载：config.json 修改后下一次调用生效；
 *  - 拒绝与告警写入审计日志。
 */
import { PolicyEngine } from './policy.js';

export const name = 'alpha-guard';
export const inject = ['tools'];

export function apply(ctx, config) {
  let engine;
  try {
    engine = new PolicyEngine(config || {});
  } catch (error) {
    console.error('[alpha-guard] init failed: ' + String(error));
    return;
  }

  try {
    const dispose = ctx.tools.guard(function (exec) {
      return engine.check(exec);
    });
    try {
      ctx.effect(function () { return dispose; }, 'alpha-guard: tools.guard');
    } catch (effectError) {
      try { ctx.on('dispose', dispose); } catch (onError) {}
    }
    console.log('[alpha-guard] active; config=' + engine.configPath);
  } catch (error) {
    console.error('[alpha-guard] register failed: ' + String(error));
  }
}
