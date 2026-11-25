<template>
  <div>
    <div class="sec-title">自主决策账本（v7.1.0 PAE：LLM 提议 → 引擎裁决 → 升维/保守降级，全程无人工裁决点）</div>
    <div v-if="loading" class="empty">加载中…</div>
    <template v-else>
      <div class="stats-row">
        <div class="stat"><div class="num">{{ stats.total || 0 }}</div><div class="lab">总提案</div></div>
        <div class="stat"><div class="num ok">{{ stats.approved || 0 }}</div><div class="lab">批准</div></div>
        <div class="stat"><div class="num bad">{{ verdictCount('denied') }}</div><div class="lab">拒绝</div></div>
        <div class="stat"><div class="num">{{ stats.escalations || 0 }}</div><div class="lab">升维</div></div>
        <div class="stat"><div class="num">{{ stats.approved_with_outcome || 0 }}</div><div class="lab">结果回写</div></div>
        <div class="stat"><div class="num ok">{{ conversionPct }}</div><div class="lab">转化率</div></div>
      </div>
      <div v-if="!records.length" class="empty">暂无自主提案——阶段头经 propose 工具提交后在此留痕（提议→裁决→结果全程可见）</div>
      <div v-for="r in records" :key="r.id" class="pr-card">
        <div class="pr-head">
          <span class="pr-id">{{ r.id }}</span>
          <span class="chip kind">{{ r.kind }}</span>
          <span class="chip" :class="verdictClass(r.verdict)">{{ verdictLabel(r.verdict) }}</span>
          <span class="pr-stage chip">{{ r.stage }}</span>
          <span class="pr-time">{{ fmtTime(r.created_at) }}</span>
        </div>
        <div class="pr-why">{{ r.rationale }}</div>
        <div v-if="r.focus" class="pr-line">聚焦：{{ r.focus }} <span v-if="r.cost_note" style="color:var(--muted)">｜成本：{{ r.cost_note }}</span></div>
        <div v-if="r.evidence_refs?.length" class="pr-line">证据：{{ r.evidence_refs.join('；') }}</div>
        <div class="pr-line reason"><b>裁决：</b>{{ r.reason }}</div>
        <div v-if="r.outcome" class="pr-line outcome"><b>结果：</b>{{ r.outcome }}</div>
        <div v-if="r.rule_hits?.length" class="pr-rules">规则：{{ r.rule_hits.join(' · ') }}</div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '../../api.js'
import { projects } from '../../stores/projects.js'

const records = ref([])
const stats = ref({})
const loading = ref(true)

const conversionPct = computed(() => {
  const c = Number(stats.value.conversion || 0)
  return Math.round(c * 100) + '%'
})

function verdictCount(v) { return (stats.value.verdicts || {})[v] || 0 }
function verdictLabel(v) {
  return { approved: '批准', modified: '改参批准', denied: '拒绝', conservative_fallback: '保守降级', shadow_recorded: 'shadow 记录', cancelled: '熔断取消' }[v] || v
}
function verdictClass(v) {
  if (v === 'approved' || v === 'modified') return 'ok'
  if (v === 'denied') return 'bad'
  return 'mid'
}
function fmtTime(t) { return t ? String(t).replace('T', ' ').slice(0, 16) + 'Z' : '' }

async function load() {
  if (!projects.currentId) return
  loading.value = true
  try {
    const j = await api(`/api/projects/${projects.currentId}/autonomy`)
    records.value = j.records || []
    stats.value = j.stats || {}
  } catch (e) { /* 静默：面板级刷新不打断工作台 */ }
  loading.value = false
}
onMounted(() => {
  load()
  // v7.2.0 核对修复（审计 G）：运行中自动刷新——提案/裁决在阶段推进中持续产生，
  // 仅挂载时加载会让「留痕可见」退化为手动刷新；15s 兜底轮询（与工作台簿记轮询同频，
  // 页面隐藏时跳过），卸载清理。
  poll = setInterval(() => {
    if (!projects.currentId || document.hidden) return
    load()
  }, 15000)
})
import { watch, onUnmounted } from 'vue'
watch(() => projects.currentId, () => load())
let poll = null
onUnmounted(() => clearInterval(poll))
defineExpose({ reload: load })
</script>

<style scoped>
.sec-title{font-size:12px;color:var(--muted);margin:2px 0 8px;font-weight:600}
.stats-row{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap}
.stat{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:4px 10px;text-align:center;min-width:58px}
.stat .num{font-size:15px;font-weight:700;color:var(--text)}
.stat .num.ok{color:#3fb96f}.stat .num.bad{color:#e05252}
.stat .lab{font-size:10px;color:var(--muted)}
.pr-card{border:1px solid var(--border);border-radius:6px;padding:7px 9px;margin-bottom:7px;background:var(--bg3)}
.pr-head{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.pr-id{font-weight:700;font-size:12px;color:var(--accent2)}
.chip{font-size:10px;padding:1px 6px;border-radius:8px;background:var(--bg2);border:1px solid var(--border)}
.chip.ok{color:#3fb96f;border-color:rgba(63,185,111,.4)}
.chip.bad{color:#e05252;border-color:rgba(224,82,82,.4)}
.chip.mid{color:#d29922;border-color:rgba(210,153,34,.4)}
.chip.kind{color:var(--accent)}
.pr-stage{color:var(--muted)}
.pr-time{margin-left:auto;font-size:10px;color:var(--muted)}
.pr-why{font-size:12px;margin:4px 0 2px;white-space:pre-wrap}
.pr-line{font-size:11px;color:var(--text2);margin:1px 0;word-break:break-all}
.pr-line.reason{color:var(--text)}
.pr-line.outcome{color:#3fb96f}
.pr-rules{font-size:10px;color:var(--muted);margin-top:2px;word-break:break-all}
</style>
