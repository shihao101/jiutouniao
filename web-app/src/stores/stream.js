import { reactive } from 'vue'
import { api } from '../api.js'

// 统一执行流时间线：msg(ai/user) / tool / log 全部来自后端 stream（持久化），
// WS 实时事件追加，断线重连后清空并全量回填（seq 权威，避免重复）
export const stream = reactive({
  events: [],          // {kind, role, stage, text, tool, args, result, ts, seq}
  toolCalls: [],       // 工具调用单独索引（Inspector 用）
  lastSeq: 0,
  connected: false,

  $reset() {
    this.events = []; this.toolCalls = []; this.lastSeq = 0
  },

  pushEvent(e) {
    this.events.push(e)
    if (e.kind === 'tool') this.toolCalls.push(e)
    // 内存展示窗口 2000 条（后端 bbolt 全量持久化，无上限；刷新按 seq 回填）
    if (this.events.length > 2000) this.events.splice(0, this.events.length - 2000)
  },

  // 全量回填（初始加载与重连）：清空后从 seq=0 拉取权威序列
  async backfill(projectId) {
    const j = await api(`/api/projects/${projectId}/stream`)
    this.$reset()
    for (const e of (j.events || [])) this.pushEvent(e)
    this.lastSeq = j.last || 0
  },

  // 增量补拉（重连窗口兜底，seq 权威去重）
  async pollIncrement(projectId) {
    const j = await api(`/api/projects/${projectId}/stream?after=${this.lastSeq}`)
    for (const e of (j.events || [])) {
      if (e.seq > this.lastSeq) { this.pushEvent(e); this.lastSeq = e.seq }
    }
  },

  // WS 实时事件分发；返回 true 表示已消费（消息/工具/日志类），false 交由调用方刷新 detail
  onWS(type, data) {
    switch (type) {
      case 'stage_msg':
        this.pushEvent({ kind: 'msg', role: data.role || 'assistant', stage: data.stage, text: data.text, ts: new Date().toISOString() })
        return true
      case 'stage_tool':
      case 'chat_tool':
        this.pushEvent({ kind: 'tool', stage: data.stage, tool: data.tool, args: data.args, result: data.result, ts: new Date().toISOString() })
        return true
      case 'log':
        if (data.text) this.pushEvent({ kind: 'log', stage: data.stage, text: data.text, ts: data.ts })
        return true
      default:
        return false
    }
  }
})
