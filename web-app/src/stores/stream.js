import { reactive } from 'vue'
import { api } from '../api.js'

// 统一执行流时间线：msg(ai/user) / tool / log 全部来自后端 stream（持久化）。
// v6.3.2 重复显示修复：同一事件走双通道（WS 实时推送 + 8s 轮询增量），seq 是唯一权威——
// 后端 WS 副本携带 seq（与落库同源），前端以 seenSeq 已见集合去重；切项目时整组清空
// （seq 全局单调，跨项目不复用），回填不清 seenSeq（回填数据必含全部已见 seq，可防在途回包双投）。
// v7.4.3 历史保全：后端 live 桶只保最近 2000 条，更早记录滚动转入归档桶（只挪不删）——
// 初始回填取最新窗口（?tail=），更早历史经 loadEarlier 按 ?before= 分页加载，不再有展示层淘汰。
export const stream = reactive({
  events: [],          // {kind, role, stage, text, tool, args, result, ts, seq}
  toolCalls: [],       // 工具调用单独索引（Inspector 用）
  lastSeq: 0,
  connected: false,
  seenSeq: new Set(),  // 本项目会话内已展示事件的 seq（双通道去重索引）
  _epoch: 0,           // 视图纪元：$reset 递增，丢弃切项目后仍在途的过期回包
  projectId: '',       // 当前回填/增量所属项目（重连判定：同项目走增量保分页历史）
  oldestSeq: 0,        // 已加载的最旧 seq（loadEarlier 分页游标）
  exhausted: true,     // 历史是否已见底（false=仍有更早记录可加载）
  backfilling: false,  // 回填进行中（空态与闪烁抑制）

  $reset() {
    this._epoch++
    this.events = []; this.toolCalls = []; this.lastSeq = 0
    this.seenSeq = new Set()
    this.projectId = ''
    this.oldestSeq = 0; this.exhausted = true; this.backfilling = false
  },

  pushEvent(e) {
    if (e.seq) {
      if (this.seenSeq.has(e.seq)) return // 双通道去重：WS 已实时展示，轮询增量跳过
      this.seenSeq.add(e.seq)
    }
    this.events.push(e)
    if (e.kind === 'tool') this.toolCalls.push(e)
    // v7.4.3：不再做展示层滚动淘汰——历史由后端归档保全，按需经 loadEarlier 分页加载
  },

  _prepend(list) {
    // v7.4.4 顺序修复：后端分页返回升序，逐条 unshift 会整段反转——去重后整体前置
    const fresh = (list || []).filter(e => !(e.seq && this.seenSeq.has(e.seq)))
    if (!fresh.length) return
    for (const e of fresh) if (e.seq) this.seenSeq.add(e.seq)
    this.events.unshift(...fresh)
    const tools = fresh.filter(e => e.kind === 'tool')
    if (tools.length) this.toolCalls.unshift(...tools)
  },

  // 全量回填（初始加载与重连）：取最新窗口（?tail=N），seq 权威，防断线窗口丢事件。
  // 不清 seenSeq：回填响应必含会话内全部已见 seq，保留它才能挡住在途 WS 事件与回填双投。
  async backfill(projectId) {
    const epoch = this._epoch
    this.backfilling = true
    try {
      const j = await api(`/api/projects/${projectId}/stream?tail=2000`)
      if (epoch !== this._epoch) return // 回包在途期间已切换项目：丢弃
      this.projectId = projectId
      this.events = []; this.toolCalls = []
      for (const e of (j.events || [])) this.pushEvent(e)
      this.lastSeq = j.last || 0
      this.oldestSeq = this.events.length ? this.events[0].seq : 0
      this.exhausted = !!j.exhausted
    } finally {
      if (epoch === this._epoch) this.backfilling = false
    }
  },

  // 加载更早（?before=oldestSeq&limit=N）：返回 true 表示有新增内容。
  async loadEarlier(projectId) {
    if (!this.oldestSeq || this.exhausted) return false
    const epoch = this._epoch
    const j = await api(`/api/projects/${projectId}/stream?before=${this.oldestSeq}&limit=1000`)
    if (epoch !== this._epoch) return false
    this._prepend(j.events || [])
    if (this.events.length && this.events[0].seq) {
      this.oldestSeq = this.events[0].seq
    }
    this.exhausted = !!j.exhausted
    return (j.events || []).length > 0
  },

  // 增量补拉（重连窗口兜底，seq 权威去重）
  async pollIncrement(projectId) {
    const epoch = this._epoch
    const j = await api(`/api/projects/${projectId}/stream?after=${this.lastSeq}`)
    if (epoch !== this._epoch) return // 回包在途期间已切换项目：丢弃
    for (const e of (j.events || [])) {
      if (e.seq > this.lastSeq) { this.pushEvent(e); this.lastSeq = e.seq }
    }
  },

  // WS 实时事件分发；返回 true 表示已消费（消息/工具/日志类），false 交由调用方刷新 detail
  onWS(type, data) {
    switch (type) {
      case 'stage_msg':
        this.pushEvent({ kind: 'msg', role: data.role || 'assistant', stage: data.stage, text: data.text, ts: new Date().toISOString(), seq: data.seq })
        return true
      case 'stage_tool':
      case 'chat_tool':
        this.pushEvent({ kind: 'tool', stage: data.stage, tool: data.tool, args: data.args, result: data.result, ts: new Date().toISOString(), seq: data.seq })
        return true
      case 'log':
        if (data.text) this.pushEvent({ kind: 'log', stage: data.stage, text: data.text, ts: data.ts, seq: data.seq })
        return true
      default:
        return false
    }
  }
})
