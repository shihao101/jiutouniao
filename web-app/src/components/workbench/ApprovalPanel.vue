<template>
  <div>
    <!-- 待答提问 -->
    <template v-if="asks.length">
      <div class="sec-title" style="color:var(--gold)">待你回答（{{ asks.length }}）</div>
      <div v-for="q in asks" :key="q.id" class="ap-card">
        <div class="ap-head">阶段 {{ q.stage || 'chat' }} · {{ fmtDateTime(q.created_at) }}</div>
        <div class="ap-act">{{ q.question }}</div>
        <div style="display:flex;gap:6px;margin-top:7px">
          <input v-model="answers[q.id]" style="flex:1" placeholder="一句话回答…" @keyup.enter="answer(q.id)">
          <button class="small primary" @click="answer(q.id)">回答</button>
        </div>
      </div>
    </template>

    <!-- 待审批 -->
    <div class="sec-title">◆ 待人工审批（{{ aps.length }}）</div>
    <div v-if="!aps.length" class="empty">无待审批工单</div>
    <div v-for="a in aps" :key="a.id" class="ap-card">
      <div class="ap-head">[{{ a.risk }}] 阶段 {{ a.stage }} · {{ fmtDateTime(a.requested_at) }} 发起</div>
      <div class="ap-act">{{ a.action }}</div>
      <div style="display:flex;gap:8px;margin-top:7px">
        <button class="small primary" @click="decide(a.id, true)">批准</button>
        <button class="small danger" @click="decide(a.id, false)">拒绝</button>
      </div>
    </div>

    <!-- 决策留痕 -->
    <div class="sec-title" style="margin-top:12px">决策留痕（人工 ◆ / 自动，含只读 L0）</div>
    <div v-for="a in history" :key="a.id" class="ap-card done">
      <template v-if="a.risk === 'L0'">
        <div class="mono" style="font-size:11px;color:var(--text2)">
          L0 自动执行 · {{ fmtDateTime(a.decided_at || a.requested_at) }}<br>{{ (a.action || '').replace(/^执行命令:\s*/, '').split('\n')[0].slice(0, 110) }}
        </div>
      </template>
      <template v-else>
        <div class="ap-head">
          <b>[{{ a.risk }}] {{ APPROVAL_CN[a.status] }}</b>
          <span style="color:var(--cyan)">{{ a.mode === 'auto' ? '自动批准' : '◆ 人工批准' }}</span>
          <span style="color:var(--muted)">{{ a.decided_by }} · {{ fmtDateTime(a.decided_at) }}</span>
        </div>
        <div class="ap-act" style="max-height:64px;overflow:hidden">{{ a.action.slice(0, 120) }}</div>
      </template>
    </div>
  </div>
</template>

<script setup>
import { reactive, computed } from 'vue'
import { projects } from '../../stores/projects.js'
import { session } from '../../stores/session.js'
import { api } from '../../api.js'
import { APPROVAL_CN, fmtDateTime } from '../../labels.js'

const answers = reactive({})
const aps = computed(() => projects.pendingApprovals)
const asks = computed(() => projects.pendingAsks)
const history = computed(() => (projects.detail?.approvals || []).filter(a => a.status !== 'pending').slice(0, 12))

async function decide(id, ok) {
  try { await api(`/api/approvals/${id}/decide`, 'POST', { approve: ok }); await projects.refresh() }
  catch (e) { session.showToast(e.message) }
}
async function answer(id) {
  const a = (answers[id] || '').trim()
  if (!a) return session.showToast('请输入回答')
  try { await api(`/api/asks/${id}/answer`, 'POST', { answer: a }); answers[id] = ''; await projects.refresh() }
  catch (e) { session.showToast(e.message) }
}
</script>

<style scoped>
.sec-title{font-size:12px;color:var(--muted);margin:6px 0 8px;font-weight:600}
.ap-card{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:9px 11px;margin-bottom:8px}
.ap-card.done{opacity:.82}
.ap-head{font-size:11px;color:var(--muted);display:flex;gap:8px;flex-wrap:wrap;margin-bottom:4px}
.ap-act{font-size:12px;white-space:pre-wrap;word-break:break-all}
</style>
