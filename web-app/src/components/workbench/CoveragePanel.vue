<template>
  <div>
    <div class="sec-title">覆盖度矩阵（{{ projects.coverage.length }} 单元）</div>
    <div v-if="!projects.coverage.length" class="empty">暂无覆盖记录——测完的 endpoint×参数×漏洞类会自动登记</div>
    <div v-for="(c, i) in projects.coverage" :key="i" class="cov-row">
      <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
        <b class="mono" style="font-size:11.5px">{{ c.endpoint }}</b>
        <span class="chip">{{ c.vuln_class }}{{ c.param ? '·' + c.param : '' }}</span>
        <span class="chip" :style="{color: covColor(c.status)}">{{ COV_CN[c.status] || c.status }} ×{{ c.count }}</span>
      </div>
      <div v-if="c.notes" style="font-size:11px;color:var(--muted);margin-top:2px;word-break:break-all">{{ c.notes }}</div>
    </div>

    <!-- v3.9.5 对账视图：自述面清单归宿 + 清单外发现（潜在 0day 面）计数 -->
    <div v-if="recon && recon.enabled" class="sec-title" style="margin-top:14px">自述面对账（{{ recon.total }} 条）</div>
    <div v-if="recon && recon.enabled" class="recon-stats">
      <span class="chip" style="color:var(--green)">已覆盖 {{ recon.covered }}</span>
      <span class="chip" style="color:var(--gold)">延期/排除 {{ recon.deferred }}</span>
      <span class="chip" :style="{color: recon.uncovered ? 'var(--red)' : 'var(--green)'}">未归宿 {{ recon.uncovered }}</span>
      <span class="chip" style="color:var(--red)">清单外发现 {{ recon.beyond }}</span>
      <span class="chip" style="color:var(--muted)">发现总数 {{ recon.findingsTotal }}</span>
    </div>
    <div v-for="(it, i) in (recon && recon.items) || []" :key="'r' + i" class="cov-row">
      <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
        <span class="chip mono" style="font-size:10.5px">{{ it.id || 'C?' }}</span>
        <b style="font-size:11.5px">{{ it.item }}</b>
        <span class="chip" :style="{color: reconColor(it.status)}">{{ RECON_CN[it.status] || it.status }}</span>
      </div>
      <div v-if="it.reason" style="font-size:11px;color:var(--muted);margin-top:2px;word-break:break-all">{{ it.reason }}</div>
    </div>
    <div v-if="recon && recon.enabled && !recon.items.length" class="empty">清单为空</div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { projects } from '../../stores/projects.js'
import { COV_CN } from '../../labels.js'

const recon = computed(() => projects.recon)
const covColor = s => ({ vulnerable: 'var(--red)', waf_blocked: 'var(--gold)', needs_follow_up: 'var(--gold)', ruled_out: 'var(--text2)', no_issue_found: 'var(--green)' }[s] || 'var(--muted)')
const reconColor = s => ({ covered: 'var(--green)', deferred: 'var(--gold)', excluded: 'var(--text2)', skipped: 'var(--text2)', out_of_scope: 'var(--text2)', uncovered: 'var(--red)' }[s] || 'var(--muted)')
const RECON_CN = { covered: '已覆盖', deferred: '延期', excluded: '排除', skipped: '跳过', out_of_scope: '范围外', uncovered: '未归宿' }
</script>

<style scoped>
.sec-title{font-size:12px;color:var(--muted);margin:6px 0 8px;font-weight:600}
.cov-row{border-bottom:1px dashed var(--border);padding:6px 0}
.recon-stats{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px}
</style>
