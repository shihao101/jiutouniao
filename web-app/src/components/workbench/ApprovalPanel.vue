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

    <!-- 决策留痕（v7.5.1：全量展示——engine 档下自动裁决占多数，cap 12 的旧口径留痕不全） -->
    <div class="sec-title" style="margin-top:12px">
      决策留痕（{{ history.length }} 条{{ historyCap ? '，仅显示最近 80' : '' }}）
      <span class="flt" :class="{on: flt==='all'}" @click="flt='all'">全部</span>
      <span class="flt" :class="{on: flt==='engine'}" @click="flt='engine'">引擎 {{ cnt.engine }}</span>
      <span class="flt" :class="{on: flt==='auto'}" @click="flt='auto'">自动 {{ cnt.auto }}</span>
      <span class="flt" :class="{on: flt==='manual'}" @click="flt='manual'">人工 {{ cnt.manual }}</span>
      <span class="flt" :class="{on: flt==='rejected'}" @click="flt='rejected'">拒绝 {{ cnt.rejected }}</span>
    </div>
    <div v-for="a in history" :key="a.id" class="ap-card done">
      <template v-if="a.risk === 'L0'">
        <div class="mono" style="font-size:11px;color:var(--text2)">
          L0 自动执行 · {{ fmtDateTime(a.decided_at || a.requested_at) }}<br>{{ (a.action || '').replace(/^执行命令:\s*/, '').split('\n')[0].slice(0, 110) }}
        </div>
      </template>
      <template v-else>
        <div class="ap-head">
          <b>[{{ a.risk }}] {{ APPROVAL_CN[a.status] }}</b>
          <span :style="{color: decColor(a)}">{{ decType(a) }}</span>
          <span style="color:var(--muted)" :title="a.decided_by">{{ a.decided_by }} · {{ fmtDateTime(a.decided_at) }}</span>
        </div>
        <div class="ap-act" style="max-height:64px;overflow:hidden">{{ a.action.slice(0, 120) }}</div>
      </template>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref, computed } from 'vue'
import { projects } from '../../stores/projects.js'
import { session } from '../../stores/session.js'
import { api } from '../../api.js'
import { APPROVAL_CN, fmtDateTime } from '../../labels.js'

const answers = reactive({})
const aps = computed(() => projects.pendingApprovals)
const asks = computed(() => projects.pendingAsks)
const flt = ref('all')
// v7.5.1 修复：留痕全量——旧实现 slice(0,12) 在 engine 档（每次 L1+ 均有工单留痕）下
// 丢弃绝大多数决策记录；现展示最近 80 条并按决策方分类过滤。
const history = computed(() => {
  const all = (projects.detail?.approvals || []).filter(a => a.status !== 'pending')
  const filtered = all.filter(a => {
    if (flt.value === 'all') return true
    if (flt.value === 'engine') return String(a.decided_by || '').startsWith('engine-adjudicator')
    if (flt.value === 'manual') return a.mode === 'manual'
    if (flt.value === 'rejected') return a.status === 'rejected' || a.status === 'expired'
    return a.mode === 'auto' && !String(a.decided_by || '').startsWith('engine-adjudicator')
  })
  historyCap.value = all.length > 80
  return filtered.slice(0, 80)
})
const historyCap = ref(false)
const cnt = computed(() => {
  const all = projects.detail?.approvals || []
  let engine = 0, auto = 0, manual = 0, rejected = 0
  for (const a of all) {
    if (a.status === 'pending') continue
    const db = String(a.decided_by || '')
    if (db.startsWith('engine-adjudicator')) engine++
    else if (a.mode === 'manual') manual++
    else auto++
    if (a.status === 'rejected' || a.status === 'expired') rejected++
  }
  return { engine, auto, manual, rejected }
})
function decType(a) {
  const db = String(a.decided_by || '')
  if (db.startsWith('engine-adjudicator')) return '🤖 引擎裁决'
  if (db.startsWith('pre-approved')) return '⚙ 预批准'
  if (a.mode === 'manual') return '◆ 人工'
  return '⚙ 自动批准'
}
function decColor(a) {
  const db = String(a.decided_by || '')
  if (db.startsWith('engine-adjudicator')) return 'var(--accent2)'
  if (a.mode === 'manual') return 'var(--gold)'
  return 'var(--cyan)'
}

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
.flt{display:inline-block;margin-left:6px;padding:1px 7px;border:1px solid var(--border);border-radius:9px;font-size:10px;color:var(--text2);cursor:pointer;user-select:none}
.flt.on{color:var(--accent2);border-color:var(--accent2);font-weight:600}
</style>
