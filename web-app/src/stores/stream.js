import { reactive } from 'vue'
import { api } from '../api.js'

// 统一执行流时间线：msg(ai/user) / tool / log 全部来自后端 stream（持久化）。
// v6.3.2 重复显示修复：同一事件走双通道（WS 实时推送 + 8s 轮询增量），seq 是唯一权威——
// 后端 WS 副本携带 seq（与落库同源），前端以 seenSeq 已见集合去重；切项目时整组清空
// （seq 全局单调，跨项目不复用），回填不清 seenSeq（回填数据必含全部已见 seq，可防在途回包双投）。
export const stream = reactive({
  events: [],          // {kind, role, stage, text, tool, args, result, ts, seq}
  toolCalls: [],       // 工具调用单独索引（Inspector 用）
  lastSeq: 0,
  connected: false,
  seenSeq: new Set(),  // 本项目会话内已展示事件的 seq（双通道去重索引）
  _epoch: 0,           // 视图纪元：$reset 递增，丢弃切项目后仍在途的过期回包

  $reset() {
    this._epoch++
    this.events = []; this.toolCalls = []; this.lastSeq = 0
    this.seenSeq = new Set()
  },

  pushEvent(e) {
    if (e.seq) {
      if (this.seenSeq.has(e.seq)) return // 双通道去重：WS 已实时展示，轮询增量跳过
      this.seenSeq.add(e.seq)
    }
    this.events.push(e)
    if (e.kind === 'tool') this.toolCalls.push(e)
    // 内存展示窗口 2000 条（后端 bbolt 全量持久化，无上限；刷新按 seq 回填）
    if (this.events.length > 2000) {
      const dropped = this.events.splice(0, this.events.length - 2000)
      for (const d of dropped) if (d.seq) this.seenSeq.delete(d.seq)
    }
  },

  // 全量回填（初始加载与重连）：清空后从 seq=0 拉取权威序列。
  // 不清 seenSeq：回填响应必含会话内全部已见 seq，保留它才能挡住在途 WS 事件与回填双投。
  async backfill(projectId) {
    const epoch = this._epoch
    const j = await api(`/api/projects/${projectId}/stream`)
    if (epoch !== this._epoch) return // 回包在途期间已切换项目：丢弃
    this.events = []; this.toolCalls = []
    for (const e of (j.events || [])) this.pushEvent(e)
    this.lastSeq = j.last || 0
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
