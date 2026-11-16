import { wsUrl } from '../api.js'
import { stream } from '../stores/stream.js'
import { projects } from '../stores/projects.js'
import { session } from '../stores/session.js'

// WebSocket 生命周期：断线指数退避重连；重连后全量回填时间线（seq 权威防重复）
let ws = null
let retry = 0
let timer = null

export function connectWS(projectId) {
  disconnectWS()
  if (!projectId || !session.token) return
  ws = new WebSocket(wsUrl(projectId))
  ws.onopen = () => {
    stream.connected = true
    retry = 0
    // 连接建立后全量回填一次（清空 + seq 权威），防断线窗口丢事件
    stream.backfill(projectId).then(() => projects.refresh()).catch(() => {})
  }
  // v3.7.2 数据实时性修复：stage_tool 事件此前被 stream 消费后不再触发任何数据刷新——
  // 黑板/战利品/子代理/交付物/覆盖度在运行期间永远停留在 select() 快照（用户须手动刷新才更新）。
  // 现按工具名映射定向数据刷新，与 scheduleRefresh 共享 400ms 去抖风格。
  const TOOL_DATA_REFRESH = {
    upsert_fact: ['board'], record_loot: ['board'], shell_open: ['board'],
    spawn_subagent: ['board'], poll_subagents: ['board'],
    write_file: ['files'], update_coverage: ['coverage'],
    record_finding: ['detail'], record_asset: ['detail'],
    plan_subtasks: ['detail'], update_subtask: ['detail'],
    complete_stage: ['detail', 'files', 'coverage', 'board'],
  }
  const dataTimers = {}
  function scheduleDataRefresh(kinds, pid) {
    for (const k of kinds) {
      if (dataTimers[k]) continue
      dataTimers[k] = setTimeout(() => {
        delete dataTimers[k]
        if (projects.currentId !== pid) return
        if (k === 'board') projects.loadBoard(pid).catch(() => {})
        else if (k === 'files') projects.loadFiles().catch(() => {})
        else if (k === 'coverage') projects.loadCoverage().catch(() => {})
        else if (k === 'detail') projects.refresh().catch(() => {})
      }, 400)
    }
  }
  ws.onmessage = ev => {
    let msg; try { msg = JSON.parse(ev.data) } catch (e) { return }
    const handled = stream.onWS(msg.type, msg.data || {})
    if (handled) {
      const kinds = TOOL_DATA_REFRESH[msg.data?.tool]
      if (kinds) scheduleDataRefresh(kinds, projectId)
    } else {
      // detail 类事件：审批/提问/子任务/阶段/项目/漏洞/熔断 → 刷新详情（去抖）
      scheduleRefresh()
      if (msg.type === 'ask' && msg.data?.status === 'pending') session.showToast('九头在等你回答提问（右侧「审批/提问」）')
      if (msg.type === 'kill') session.showToast('项目已熔断：' + (msg.data?.reason || ''))
    }
  }
  ws.onclose = () => {
    stream.connected = false
    if (projects.currentId === projectId) scheduleReconnect(projectId)
  }
  ws.onerror = () => { try { ws && ws.close() } catch (e) {} }
}

function scheduleReconnect(projectId) {
  clearTimeout(timer)
  const delay = Math.min(8000, 1000 * Math.pow(2, retry++))
  timer = setTimeout(() => { if (projects.currentId === projectId) connectWS(projectId) }, delay)
}

let refreshTimer = null
let dirty = false
function scheduleRefresh() {
  dirty = true
  clearTimeout(refreshTimer)
  refreshTimer = setTimeout(async () => {
    if (!dirty) return
    dirty = false
    await projects.refresh()
    await projects.loadCoverage()
    // v2.7.5：项目状态类事件（续跑/熔断/失败/收口）同步刷新列表——
    // 顶栏「选择项目」下拉框数据源是 list，此前只刷 detail 导致状态滞后显示「暂停」
    await projects.loadList()
  }, 400)
}

export function disconnectWS() {
  clearTimeout(timer)
  if (ws) { try { ws.onclose = null; ws.close() } catch (e) {} }
  ws = null
  stream.connected = false
}

// 8s 轮询兜底：detail + stream 增量（防 WS 静默丢事件）
setInterval(async () => {
  if (!session.token || !projects.currentId) return
  try { await projects.refresh() } catch (e) {}
  try { await stream.pollIncrement(projects.currentId) } catch (e) {}
}, 8000)
