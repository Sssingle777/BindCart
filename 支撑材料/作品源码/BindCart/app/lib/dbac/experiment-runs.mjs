import { AppError } from '../protocol.mjs';
import { DBAC_MODES } from './policy.mjs';

const fail = (code, message, status = 400) => { throw new AppError(code, message, status); };
const validId = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
const clone = value => structuredClone(value);

// This registry records complete existing experiments, not invented protocol
// stages. Keep every admitted id for this process lifetime: evicting an id would
// allow a delayed retry to execute the same request again. Capacity is bounded.
export function createExperimentRuns({ run, scenarios, canStart = () => true, maxRecords = 64 }) {
  if (typeof run !== 'function' || typeof scenarios !== 'function' || !Number.isSafeInteger(maxRecords) || maxRecords < 1) throw new TypeError('Invalid experiment run registry configuration');
  const records = new Map();
  let active = null;
  function id(value) {
    if (!validId(value)) fail('EXPERIMENT_RUN_INVALID_ID', '实验运行编号必须是浏览器生成的 UUID v4。');
    return value.toLowerCase();
  }
  return {
    busy: () => active !== null,
    get(runId) {
      const record = records.get(id(runId));
      if (!record) fail('EXPERIMENT_RUN_NOT_FOUND', '本进程没有此实验运行记录；服务重启后无法恢复旧记录。这不表示实验被取消或请求被拒绝，请先核对再明确开始新实验。', 404);
      return clone(record);
    },
    list: () => ({ runs: [...records.values()].slice(-10).reverse().map(clone), retained: records.size, capacity: maxRecords, persistence: 'process-memory' }),
    start(input, { blocked = false } = {}) {
      if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !['runId', 'mode', 'scenarioId'].includes(key))) fail('EXPERIMENT_RUN_INVALID_INPUT', '实验运行只接受 runId、mode 和 scenarioId。');
      const runId = id(input.runId), { mode, scenarioId } = input;
      if (!DBAC_MODES.includes(mode)) fail('DBAC_INVALID_MODE', '请选择有效的实验模式。');
      if (typeof scenarioId !== 'string' || !scenarios().some(value => value.id === scenarioId)) fail('EXPERIMENT_UNKNOWN_SCENARIO', '请选择已有攻击实验。');
      const existing = records.get(runId);
      if (existing) {
        if (existing.mode !== mode || existing.scenarioId !== scenarioId) fail('EXPERIMENT_RUN_CONFLICT', '此运行编号已绑定另一模式或场景，不能覆盖原实验。', 409);
        return clone(existing);
      }
      if (blocked || active !== null || !canStart()) fail('BUSY', '已有演示操作或实验正在执行，请先查询原运行，等待完成后再操作。', 409);
      if (records.size >= maxRecords) fail('EXPERIMENT_RUN_CAPACITY', '本进程的实验记录已达到上限，请保留所需结果后重新启动演示；原运行编号不会被自动清除或重新执行。', 429);
      const record = { runId, status: 'running', mode, scenarioId, startedAt: new Date().toISOString() };
      records.set(runId, record);
      active = runId;
      // Retain the work after the request returns or the browser disconnects.
      // A security rejection is a returned experiment result, not a job failure.
      Promise.resolve().then(() => run({ mode, scenarioId })).then(result => {
        record.result = clone(result);
        record.status = 'completed';
      }).catch(error => {
        record.error = { code: error?.code ?? 'EXPERIMENT_RUN_FAILED', message: error?.message ?? '实验运行未完成，未取得安全验证结论。' };
        record.status = 'failed';
      }).finally(() => {
        record.completedAt = new Date().toISOString();
        active = null;
      });
      return clone(record);
    },
  };
}
