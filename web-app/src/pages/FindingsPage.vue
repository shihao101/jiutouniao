<template>
  <div class="page">
    <div v-if="!projects.current" class="empty">选择项目后显示漏洞</div>
    <template v-else-if="!projects.detail">
      <div class="skeleton" style="height:150px;margin-bottom:14px"></div>
      <div v-for="i in 5" :key="i" class="skeleton" style="height:40px;margin-bottom:8px"></div>
    </template>
    <template v-else>
    <AppCard title="等级 × 置信度矩阵" :icon="ScatterChartIcon" style="margin-bottom:14px">
      <AppChart v-if="matrixData.length" :option="matrixChart" height="200px" aria-label="等级与置信度矩阵堆叠柱状图" />
      <div v-else class="empty">暂无漏洞数据</div>
    </AppCard>
    <div class="f-toolbar" role="search" aria-label="漏洞筛选">
      <input v-model="q" class="f-search" type="search" placeholder="搜索标题/详情…" aria-label="搜索漏洞" />
      <select v-model="sevF" aria-label="按等级筛选">
        <option value="">全部等级</option><option>高</option><option>中</option><option>低</option><option>信息</option>
      </select>
      <select v-model="confF" aria-label="按置信度筛选">
        <option value="">全部置信度</option><option>确证</option><option>疑似</option><option>待查</option>
      </select>
      <select v-model="sortKey" aria-label="排序方式">
        <option value="">排序：等级优先</option><option value="confidence">按置信度</option><option value="title">按标题</option><option value="stage">按阶段</option>
      </select>
      <span class="chip">{{ shown.length }} / {{ (projects.detail?.findings || []).length }} 条</span>
    </div>

    <!-- v5.3.6：漏洞名主行 + 折叠详情（默认全部收起）——折叠内：漏洞详细 / POC 展示 / 修复建议 -->
    <div v-if="!shown.length" class="empty f-card">{{ (projects.detail?.findings || []).length ? '当前筛选无匹配' : '暂无漏洞（record_finding 仅收录有证据支撑的漏洞）' }}</div>
    <div v-for="f in shown" :key="f.id" class="f-card">
      <div class="f-head" role="button" tabindex="0" :aria-expanded="!!open[f.id]"
           @click="open[f.id] = !open[f.id]" @keydown.enter="open[f.id] = !open[f.id]" @keydown.space.prevent="open[f.id] = !open[f.id]">
        <span :class="'sev-' + f.severity">{{ f.severity }}</span>
        <span class="conf-chip">{{ f.confidence || '待查' }}</span>
        <b class="f-title">{{ f.title }}</b>
        <span v-if="f.cwe" class="cwe-badge">{{ f.cwe }}</span>
        <span v-if="f.impact_rank || f.access" class="queue-badge" :title="'利用队列标注：access=' + (f.access || '-') + '，impact_rank=' + (f.impact_rank || '-')">{{ f.impact_rank ? 'rank' + f.impact_rank : '队列' }}{{ f.access ? ' · ' + f.access : '' }}</span>
        <span style="flex:1"></span>
        <span class="chip">{{ f.stage }}</span>
        <span class="f-chev">{{ open[f.id] ? '▾' : '▸' }}</span>
      </div>
      <div v-if="open[f.id]" class="f-body">
        <div class="f-sec">
          <div class="f-sec-label">漏洞详细</div>
          <div class="f-detail">{{ f.detail }}</div>
        </div>
        <div class="f-sec">
          <div class="f-sec-label">POC 展示（Burp 式请求 / 响应原文）</div>
          <template v-if="pocOf(f).length">
            <div v-for="(pr, i) in pocOf(f)" :key="i" class="burp-pair">
              <div class="burp-head">POC {{ pocOf(f).length > 1 ? '#' + (i + 1) : '' }}{{ pr.backfilled ? ' · 由证据记录回填（非模型原始誊写）' : '' }}</div>
              <div class="burp-block req"><div class="burp-label">请求原文</div><pre>{{ pr.request }}</pre></div>
              <div class="burp-block resp"><div class="burp-label">响应原文</div><pre>{{ pr.response }}</pre></div>
            </div>
          </template>
          <div v-else class="f-empty">无结构化 POC（原始记录可在证据面板按时间查看）</div>
        </div>
        <div class="f-sec">
          <div class="f-sec-label">修复建议</div>
          <div v-if="f.remediation" class="f-remediation">{{ f.remediation }}</div>
          <div v-else class="f-empty">未填写（v5.3.6 起由登记时的 LLM 提供；历史发现可在报告中查看修复口径）</div>
        </div>
      </div>
    </div>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { BarChart3 as ScatterChartIcon } from 'lucide-vue-next'
import AppCard from '../components/ui/AppCard.vue'
import AppChart from '../components/ui/AppChart.vue'
import { projects } from '../stores/projects.js'

// P1（用户定向调整）：等级 × 置信度矩阵=堆叠柱状图（x=等级，柱内按置信度堆叠，聚焦「高危且确证」）
const SEVS = ['高', '中', '低', '信息']
const CONFS = ['确证', '疑似', '待查']
const SEV_ORDER = { '高': 4, '中': 3, '低': 2, '信息': 1 }
const CONF_ORDER = { '确证': 3, '疑似': 2, '待查': 1 }
const q = ref(''); const sevF = ref(''); const confF = ref(''); const sortKey = ref('')
const open = reactive({}) // v5.3.6：折叠态（默认全部收起）
const shown = computed(() => {
  let fs = projects.detail?.findings || []
  const kw = q.value.trim().toLowerCase()
  if (kw) fs = fs.filter(f => (f.title || '').toLowerCase().includes(kw) || (f.detail || '').toLowerCase().includes(kw))
  if (sevF.value) fs = fs.filter(f => (f.severity || '信息') === sevF.value)
  if (confF.value) fs = fs.filter(f => (f.confidence || '待查') === confF.value)
  if (sortKey.value) {
    const k = sortKey.value
    fs = [...fs].sort((a, b) => {
      if (k === 'confidence') return (CONF_ORDER[b.confidence || '待查'] - CONF_ORDER[a.confidence || '待查']) || String(a.title).localeCompare(b.title)
      if (k === 'stage') return String(a.stage || '').localeCompare(String(b.stage || '')) || (SEV_ORDER[b.severity || '信息'] - SEV_ORDER[a.severity || '信息'])
      return String(a[k] || '').localeCompare(String(b[k] || ''))
    })
  } else {
    fs = [...fs].sort((a, b) => (SEV_ORDER[b.severity || '信息'] - SEV_ORDER[a.severity || '信息']) ||
      (CONF_ORDER[b.confidence || '待查'] - CONF_ORDER[a.confidence || '待查']) ||
      String(a.title).localeCompare(String(b.title)))
  }
  return fs
})
const matrixData = computed(() => {
  const fs = projects.detail?.findings || []
  return fs.map(f => ({ sevs: f.severity || '信息', conf: f.confidence || '待查' }))
})
const CONF_COLORS = { 确证: '#f85149', 疑似: '#d29922', 待查: '#58a6ff' }
const matrixChart = computed(() => {
  if (!matrixData.value.length) return null
  const counts = {}
  for (const d of matrixData.value) {
    const k = d.sevs + '|' + d.conf
    counts[k] = (counts[k] || 0) + 1
  }
  const series = CONFS.map((c, ci) => ({
    name: c, type: 'bar', stack: 'total', barWidth: 34,
    itemStyle: { color: CONF_COLORS[c], borderRadius: ci === CONFS.length - 1 ? [4, 4, 0, 0] : 0 },
    emphasis: { focus: 'series' },
    data: SEVS.map(s => counts[`${s}|${c}`] || 0),
  }))
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: ps =>
      `${ps[0].name}（共 ${ps.reduce((a, p) => a + p.value, 0)} 条）：` + ps.filter(p => p.value).map(p => `${p.seriesName} ${p.value}`).join(' / ') },
    legend: { bottom: 0, icon: 'circle', itemWidth: 8, textStyle: { fontSize: 11 } },
    grid: { left: 40, right: 20, top: 22, bottom: 36 },
    xAxis: { type: 'category', data: SEVS, axisTick: { show: false }, axisLabel: { fontSize: 12 } },
    yAxis: { type: 'value', minInterval: 1, axisLabel: { fontSize: 10 }, splitLine: { lineStyle: { opacity: .25 } } },
    series,
  }
})

onMounted(() => { if (projects.currentId && !projects.detail) projects.select(projects.currentId) })
const emap = computed(() => { const m = {}; for (const e of (projects.detail?.evidence || [])) m[e.id] = e; return m })

// v5.3.6 POC 数据源：模型原始 poc 优先；否则从真实关联的证据（auto-link）提取 Burp 对；
// 两者皆无 → 空数组（显示「无结构化 POC」）。服务端另有 backfillPOC 兜底（evidence 回填标记 backfilled）。
function pocOf(f) {
  if ((f.poc || []).length) return f.poc
  const pairs = []
  for (const eid of (f.evidence_ids || [])) {
    const pr = parseBurp(emap.value[eid])
    if (pr) pairs.push({ request: pr.request, response: pr.response, backfilled: true })
    if (pairs.length >= 2) break
  }
  return pairs
}

// v2.4.1 Burp 原文对照解析：从证据的 output 提取成对的请求原文/响应原文。
// 识别两种捕获形态：
//   A) curl -sv：`> ` 开头行为请求、`< ` 开头为响应头、其后为正文（CombinedOutput 已含 stderr）
//   B) curl -s -i：output 以 HTTP/ 响应头开始（请求侧回落为命令原文）
// 非 HTTP 证据返回 null（走无 POC 展示）。
function parseBurp(ev) {
  if (!ev || ev.type !== 'command') return null
  const out = String(ev.output || '')
  const cmd = String(ev.input || '')
  if (!/HTTP\/1\.[01]/.test(out) && !/curl/.test(cmd)) return null

  const lines = out.split('\n')
  let request = '', response = ''

  // 形态 A：curl -sv
  const reqLines = lines.filter(l => l.startsWith('> ')).map(l => l.slice(2))
  if (reqLines.length >= 1 && /^GET |^POST |^PUT |^HEAD |^DELETE |^OPTIONS /.test(reqLines[0])) {
    request = reqLines.join('\n')
    const dataM = cmd.match(/--data(?:-urlencode)?\s+'?([^']+)'?|--data(?:-urlencode)?\s+"([^"]+)"/)
    if (dataM) {
      const payload = (dataM[1] || dataM[2] || '').replace(/^string$/, '')
      const ct = /--data-urlencode/.test(cmd) ? 'application/x-www-form-urlencoded' : ''
      const enc = payload
      request += '\n\n' + (ct ? `Content-Type: ${ct}\n` : '') + `Content-Length: ${enc.length}\n\n${enc}`
    }
    const idx = lines.findIndex(l => l.startsWith('< HTTP/'))
    if (idx >= 0) {
      const respLines = []
      for (let i = idx; i < lines.length; i++) {
        const l = lines[i]
        respLines.push(l.startsWith('< ') ? l.slice(2) : l)
      }
      response = respLines.join('\n').replace(/\n{3,}/g, '\n\n').trim()
    } else {
      response = out.trim()
    }
    return { request: request.trim(), response: response || '(空响应)' }
  }

  // 形态 B：curl -s -i（输出即响应原文）
  const m = out.match(/HTTP\/1\.[01][^\n]*/)
  if (m && out.indexOf(m[0]) >= 0) {
    const at = out.indexOf(m[0])
    response = out.slice(at).trim()
    request = cmd.trim()
    return { request, response }
  }
  return null
}
</script>

<style scoped>
.f-toolbar{display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.f-search{min-width:220px}
.f-card{border:1px solid var(--border);border-radius:8px;background:var(--bg);margin-bottom:8px;overflow:hidden}
.f-head{display:flex;gap:8px;align-items:center;padding:9px 12px;cursor:pointer;user-select:none;flex-wrap:wrap}
.f-head:hover{background:var(--bg3)}
.f-head:focus-visible{outline:2px solid var(--accent2);outline-offset:-2px}
.f-title{word-break:break-all;min-width:200px}
.f-chev{color:var(--muted);font-size:13px}
.conf-chip{padding:1px 7px;border:1px solid var(--border);border-radius:4px;font-size:11px;color:var(--text2)}
.f-body{border-top:1px solid var(--border);padding:10px 14px;display:flex;flex-direction:column;gap:12px}
.f-sec-label{font-size:11px;color:var(--muted);margin-bottom:5px;letter-spacing:.5px}
.f-detail{white-space:pre-wrap;word-break:break-all;color:var(--text);line-height:1.6;font-size:13px}
.f-remediation{white-space:pre-wrap;word-break:break-all;color:var(--text);line-height:1.6;font-size:13px;border-left:3px solid var(--green);padding-left:10px}
.f-empty{color:var(--muted);font-size:12.5px}
/* v2.4.1 Burp 原文对照卡：上下两栏面板，绿=请求、蓝=响应 */
.burp-pair{border:1px solid var(--border);border-radius:8px;overflow:hidden;background:var(--bg)}
.burp-head{padding:5px 10px;font-size:11px;color:var(--muted);background:var(--bg3);border-bottom:1px solid var(--border)}
.burp-block pre{margin:0;padding:8px 10px;font-size:11.5px;line-height:1.5;white-space:pre-wrap;word-break:break-all;max-height:220px;overflow-y:auto}
.burp-block.req pre{color:#9ece6a;border-left:3px solid #9ece6a}
.burp-block.resp pre{color:#7aa2f7;border-left:3px solid #7aa2f7}
.burp-label{padding:3px 10px;font-size:10.5px;color:var(--muted);border-top:1px dashed var(--border)}
.burp-block.req .burp-label{border-top:none}

.cwe-badge{display:inline-block;margin-left:6px;padding:1px 6px;border:1px solid var(--accent2);border-radius:4px;font-size:10.5px;color:var(--accent2);vertical-align:middle}
.queue-badge{display:inline-block;margin-left:6px;padding:1px 6px;border:1px solid var(--accent);border-radius:4px;font-size:10.5px;color:var(--accent);vertical-align:middle}
</style>
