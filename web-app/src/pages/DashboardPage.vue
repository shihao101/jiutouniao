<template>
  <div class="page">
    <div v-if="!projects.current" class="empty">选择项目后显示仪表盘</div>
    <template v-else-if="!projects.detail">
      <div class="skeleton" style="height:96px;margin-bottom:14px"></div>
      <div class="stats">
        <div v-for="i in 9" :key="i" class="skeleton" style="height:78px"></div>
      </div>
    </template>
    <template v-else>
      <AppCard title="项目概述" :icon="FolderKanban" class="dash-overview">
        <div class="kv-row"><span class="k">编号</span><b class="mono">{{ projects.current.id }}</b></div>
        <div class="kv-row"><span class="k">目标</span><span class="ellipsis">{{ projects.current.target }}</span></div>
        <div class="kv-row"><span class="k">工作区</span>
          <span class="ellipsis">宿主机 <b class="mono">projects/{{ projects.current.id }}/</b>
          <span class="hint">（容器内 /app/projects/{{ projects.current.id }}/）——导入 APP / 小程序包时放入此目录，智能体下一轮自动可见</span></span>
        </div>
      </AppCard>

      <div class="stats">
        <AppStat v-for="s in statList" :key="s.label" :value="s.value" :label="s.label" :tone="s.tone" :icon="s.icon" />
      </div>

      <div class="grid2" style="margin-top:14px">
        <AppCard title="漏洞等级分布" :icon="Bug">
          <AppChart v-if="sevRows.length" :option="sevChart" height="218px" aria-label="漏洞等级分布环形图" />
          <div v-else class="empty">暂无漏洞</div>
        </AppCard>
        <AppCard title="命令风险分布" :icon="ShieldAlert">
          <AppChart v-if="riskRows.length" :option="riskChart" height="218px" aria-label="命令风险分布环形图" />
          <div v-else class="empty">暂无命令执行</div>
        </AppCard>
      </div>

      <AppCard title="阶段耗时（分钟）" :icon="Timer" style="margin-top:14px">
        <AppChart v-if="stageChart" :option="stageChart" height="230px" aria-label="阶段耗时条形图" />
        <div v-else class="empty">暂无阶段数据</div>
      </AppCard>

      <AppCard title="阶段进度" :icon="ListChecks" style="margin-top:14px">
        <div v-for="[sid, st] in projects.stageEntries" :key="sid" class="kv-row">
          <span><AppBadge :status="st.status" :text="STATUS_CN[st.status] || st.status" :dot="st.status === 'running'" />
            {{ sid.startsWith('spec') ? '专项' : '阶段' }} {{ sid.replace(/^s/, '').replace('spec', '') }} · {{ STAGE_NAMES[sid] || sid }}</span>
          <span class="hint">{{ dur(st) }}<template v-if="(st.deliverables || []).length"> · 产出 {{ st.deliverables.length }}</template></span>
        </div>
      </AppCard>

      <AppCard title="最近活动" :icon="Activity" style="margin-top:14px">
        <div v-if="!(projects.detail?.timeline || []).length" class="empty">暂无活动</div>
        <div v-for="t in (projects.detail?.timeline || []).slice(-8).reverse()" :key="t.id" class="kv-row">
          <span class="ellipsis" style="flex:1">{{ t.event }}：{{ t.detail }}</span>
          <span class="hint">{{ fmtTime(t.created_at) }}</span>
        </div>
      </AppCard>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { Bug, ShieldAlert, ListChecks, Activity, FolderKanban, Timer, CircleCheck, Boxes, Gauge, TerminalSquare, Hourglass, Database, Award, Coins } from 'lucide-vue-next'
import AppCard from '../components/ui/AppCard.vue'
import AppStat from '../components/ui/AppStat.vue'
import AppBadge from '../components/ui/AppBadge.vue'
import AppChart from '../components/ui/AppChart.vue'
import { projects } from '../stores/projects.js'
import { STATUS_CN, STAGE_NAMES, fmtTime } from '../labels.js'

const now = ref(Date.now())
let tick = null
onMounted(() => {
  tick = setInterval(() => { now.value = Date.now() }, 1000) // v2.6：运行时长每秒刷新
  if (projects.currentId && !projects.detail) projects.select(projects.currentId)
  if (projects.currentId) projects.loadBoard(projects.currentId).catch(() => {}) // v3.7.0 黑板/战利品计数
})
onUnmounted(() => clearInterval(tick))

// v2.6：任务运行时长（XhYmZs）——运行中实时递增，终态冻结为总耗时；旧项目回退 created_at
function fmtDur(ms) {
  const s = Math.max(0, Math.floor(ms / 1000))
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60
  return (h ? h + 'h' : '') + m + 'm' + ss + 's'
}
const runtime = computed(() => {
  const p = projects.detail?.project
  if (!p || (!p.started_at && !p.created_at)) return null
  const a = new Date(p.started_at || p.created_at).getTime()
  const b = p.finished_at ? new Date(p.finished_at).getTime() : now.value
  return { text: fmtDur(b - a), done: !!p.finished_at }
})

const statList = computed(() => {
  const d = projects.detail; if (!d) return []
  const ss = projects.stageEntries
  const done = ss.filter(([, s]) => s.status === 'done').length
  const run = ss.filter(([, s]) => s.status === 'running').length
  const cmds = (d.evidence || []).filter(e => e.type === 'command' || e.type === 'hexstrike')
  const aps = (d.approvals || []).filter(a => a.status === 'pending').length
  const u = d.usage || {}
  const cov = projects.coverage
  const findings = (d.findings || []).length
  const high = (d.findings || []).filter(f => f.severity === '高').length
  return [
    { label: '运行时长', value: runtime.value ? (runtime.value.done ? '⏱ ' : '▶ ') + runtime.value.text : '—', tone: 'info', icon: Timer },
    { label: '阶段进度', value: `${done}/${ss.length}${run ? `（${run} 运行中）` : ''}`, tone: run ? 'warn' : 'ok', icon: ListChecks },
    { label: '漏洞', value: findings, tone: high ? 'danger' : (findings ? 'warn' : 'ok'), icon: Bug },
    { label: '资产', value: (d.assets || []).length, tone: 'info', icon: Boxes },
    { label: '覆盖单元', value: cov.length ? `${cov.filter(c => !['needs_follow_up', 'skipped'].includes(c.status)).length}/${cov.length}` : '—', tone: 'block', icon: Gauge },
    { label: '命令执行', value: cmds.length, tone: 'neutral', icon: TerminalSquare },
    { label: '待审批', value: aps, tone: aps ? 'warn' : 'ok', icon: Hourglass },
    { label: '黑板事实', value: (projects.facts || []).length, tone: 'neutral', icon: Database },
    { label: '战利品', value: (projects.loot || []).length, tone: (projects.loot || []).length ? 'ok' : 'neutral', icon: Award },
    { label: 'Token', value: u.total_tokens ? u.total_tokens.toLocaleString() : '—', tone: 'info', icon: Coins },
    { label: '估算成本', value: '$' + projects.cost(), tone: 'info', icon: Coins },
  ]
})
const sevRows = computed(() => {
  const c = { '高': 0, '中': 0, '低': 0, '信息': 0 }
  for (const f of (projects.detail?.findings || [])) c[f.severity] = (c[f.severity] || 0) + 1
  return rows(c, { '高': 'var(--red)', '中': 'var(--gold)', '低': 'var(--accent2)', '信息': 'var(--muted)' })
})
const riskRows = computed(() => {
  const c = {}
  for (const e of (projects.detail?.evidence || [])) if (e.type === 'command' || e.type === 'hexstrike') { const r = e.risk || '未分级'; c[r] = (c[r] || 0) + 1 }
  return rows(c, { L0: 'var(--green)', L1: 'var(--gold)', L2: 'var(--red)', FORBIDDEN: 'var(--red)' })
})
// P1 图表 option（ECharts 双主题经 AppChart 统一注入文本/tooltip 色）
const CHART_COLORS = { '高': '#f85149', '中': '#d29922', '低': '#58a6ff', '信息': '#6e7681' }
const sevChart = computed(() => ({
  tooltip: { trigger: 'item', formatter: '{b}：{c} 条（{d}%）' },
  legend: { bottom: 0, icon: 'circle', itemWidth: 8, textStyle: { fontSize: 11 } },
  series: [{
    type: 'pie', radius: ['46%', '72%'], center: ['50%', '42%'],
    itemStyle: { borderColor: 'rgba(0,0,0,0)', borderWidth: 2 },
    label: { show: false }, emphasis: { scaleSize: 6 },
    data: sevRows.value.map(r => ({ name: r.k, value: r.v, itemStyle: { color: CHART_COLORS[r.k] || r.color } })),
  }],
}))
const RISK_COLORS = { L0: '#3fb950', L1: '#d29922', L2: '#f85149', FORBIDDEN: '#bc8cff', '未分级': '#6e7681' }
const riskChart = computed(() => ({
  tooltip: { trigger: 'item', formatter: '{b}：{c} 次（{d}%）' },
  legend: { bottom: 0, icon: 'circle', itemWidth: 8, textStyle: { fontSize: 11 } },
  series: [{
    type: 'pie', radius: ['46%', '72%'], center: ['50%', '42%'],
    itemStyle: { borderColor: 'rgba(0,0,0,0)', borderWidth: 2 },
    label: { show: false },
    data: riskRows.value.map(r => ({ name: r.k, value: r.v, itemStyle: { color: RISK_COLORS[r.k] || r.color } })),
  }],
}))
const stageChart = computed(() => {
  const nowMs = now.value
  const items = projects.stageEntries.map(([sid, st]) => {
    if (!st.started_at) return null
    const a = new Date(st.started_at).getTime()
    const b = st.ended_at ? new Date(st.ended_at).getTime() : nowMs
    const m = Math.max(1, Math.round((b - a) / 60000))
    return { name: (STAGE_NAMES[sid] || sid), value: m, running: st.status === 'running' }
  }).filter(Boolean)
  if (!items.length) return null
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: ps => `${ps[0].name}：${ps[0].value} 分${ps[0].data.running ? '（运行中…）' : ''}` },
    grid: { left: 96, right: 46, top: 8, bottom: 20 },
    xAxis: { type: 'value', axisLabel: { fontSize: 10 }, splitLine: { lineStyle: { opacity: .25 } } },
    yAxis: { type: 'category', inverse: true, data: items.map(i => i.name), axisLabel: { fontSize: 11 }, axisTick: { show: false } },
    series: [{
      type: 'bar', barWidth: 12,
      data: items.map(i => ({ value: i.value, running: i.running, itemStyle: { color: i.running ? '#d29922' : '#58a6ff', borderRadius: [0, 6, 6, 0] } })),
    }],
  }
})
function rows(c, colors) {
  const vals = Object.values(c); const max = Math.max(...vals, 1)
  return Object.entries(c).filter(([, v]) => v > 0).map(([k, v]) => ({ k, v, pct: Math.max(4, v / max * 100), color: colors[k] || 'var(--accent2)' }))
}
function dur(st) {
  if (!st.started_at) return '—'
  const a = new Date(st.started_at), b = st.ended_at ? new Date(st.ended_at) : new Date()
  const m = Math.round((b - a) / 60000)
  return m >= 60 ? `${Math.floor(m / 60)}h${m % 60}m` : m + 'm'
}
</script>

<style scoped>
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.bar-row{display:flex;align-items:center;gap:9px;margin:7px 0}
.bar-label{width:56px;font-size:12px;color:var(--text2)}
.bar-track{flex:1;height:9px;background:var(--bg3);border-radius:5px;overflow:hidden}
.bar-fill{height:100%;border-radius:5px;transition:width var(--tr)}
.bar-num{width:24px;text-align:right;font-variant-numeric:tabular-nums}
.kv-row{display:flex;justify-content:space-between;gap:10px;padding:5px 2px;font-size:12.5px}
.kv-row .k{color:var(--muted)}
.hint{color:var(--muted);font-size:var(--fs-xs)}
.ellipsis{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dash-overview{margin-bottom:14px}
@media (max-width:900px){.stats{grid-template-columns:repeat(2,1fr)}}
</style>
