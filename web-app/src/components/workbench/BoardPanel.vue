<template>
  <div class="board">
    <!-- 在途子代理（v3.6.0 并行扇出的运行态） -->
    <div class="sec-title">子代理（在途 {{ running.length }}/{{ (subagents || []).length }}）</div>
    <div v-if="!(subagents || []).length" class="empty">未派发子代理（主头可用 spawn_subagent 并行扇出独立测试单元）</div>
    <div v-for="r in subagents" :key="r.id" class="b-card">
      <div class="b-head">
        <span class="chip" :class="'st-' + r.status">{{ SUB_ST[r.status] || r.status }}</span>
        <span class="mono dim">{{ r.id }}</span>
        <span class="dim">预算 {{ r.rounds }} 轮</span>
      </div>
      <div class="b-obj">{{ r.objective }}</div>
      <div v-if="r.summary" class="b-sum">{{ r.summary.slice(0, 300) }}</div>
    </div>

    <!-- 事实账本 -->
    <div class="sec-title" style="margin-top:12px">事实账本（{{ facts.length }}）——upsert_fact 维护；deprecated=已排除勿重试</div>
    <div v-if="!facts.length" class="empty">黑板暂无事实（智能体会在确证/排除时实时上板）</div>
    <div v-for="f in facts" :key="f.id" class="b-card" :class="'fc-' + f.confidence">
      <div class="b-head">
        <span class="chip" :class="'cf-' + f.confidence">{{ CF_CN[f.confidence] || f.confidence }}</span>
        <span class="mono b-key">{{ f.key }}</span>
      </div>
      <div class="b-obj">{{ f.value }}</div>
      <div v-if="f.links && f.links.length" class="dim" style="margin-top:3px">⟶ {{ f.links.join('，') }}</div>
      <div v-if="f.note" class="dim" style="margin-top:3px">{{ f.note }}</div>
    </div>

    <!-- 战利品 -->
    <div class="sec-title" style="margin-top:12px">战利品（{{ loot.length }}）——凭据/票据掩码登记，横向复用第一入口</div>
    <div v-if="!loot.length" class="empty">暂无战利品（record_loot 只登记掩码摘要，不存明文）</div>
    <table v-if="loot.length" class="b-table">
      <thead><tr><th>类型</th><th>目标</th><th>掩码</th><th>状态</th><th>来源</th></tr></thead>
      <tbody>
        <tr v-for="l in loot" :key="l.id">
          <td>{{ l.type }}</td>
          <td class="mono">{{ l.target }}</td>
          <td class="mono">{{ l.masked }}</td>
          <td><span class="chip" :class="'vf-' + l.verified">{{ VF_CN[l.verified] || l.verified }}</span></td>
          <td class="dim">{{ (l.source || '').slice(0, 60) }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { projects } from '../../stores/projects.js'

const SUB_ST = { running: '运行中', finished: '已结束', killed: '已终止', failed: '失败' }
const CF_CN = { confirmed: '已确证', tentative: '线索', deprecated: '已排除' }
const VF_CN = { unverified: '未验证', verified: '已验证', invalid: '无效' }

const facts = computed(() => projects.facts || [])
const loot = computed(() => projects.loot || [])
const subagents = computed(() => projects.subagents || [])
const running = computed(() => (projects.subagents || []).filter(r => r.status === 'running'))
</script>

<style scoped>
.sec-title{font-size:12px;color:var(--muted);margin:6px 0 8px;font-weight:600}
.empty{color:var(--muted);font-size:12px;padding:6px 0}
.b-card{border:1px solid var(--border);border-radius:6px;padding:7px 9px;margin-bottom:7px;background:var(--bg)}
.b-card.fc-deprecated{opacity:.55}
.b-head{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.b-key{font-size:11.5px;word-break:break-all}
.b-obj{font-size:12px;margin-top:4px;white-space:pre-wrap;word-break:break-word}
.b-sum{font-size:11.5px;color:var(--text2);margin-top:4px;border-top:1px dashed var(--border);padding-top:4px;white-space:pre-wrap}
.dim{color:var(--muted);font-size:11px}
.mono{font-family:var(--mono,monospace)}
.chip{font-size:10.5px;padding:1px 7px;border-radius:9px;border:1px solid var(--border)}
.cf-confirmed{color:#2e9e5b;border-color:#2e9e5b}
.cf-tentative{color:#c99a2e;border-color:#c99a2e}
.cf-deprecated{color:var(--muted)}
.st-running{color:#3b82c4;border-color:#3b82c4}
.st-finished{color:#2e9e5b;border-color:#2e9e5b}
.st-killed,.st-failed{color:#c0504d;border-color:#c0504d}
.vf-verified{color:#2e9e5b;border-color:#2e9e5b}
.vf-unverified{color:#c99a2e;border-color:#c99a2e}
.vf-invalid{color:var(--muted)}
.b-table{width:100%;border-collapse:collapse;font-size:11.5px}
.b-table th,.b-table td{border:1px solid var(--border);padding:4px 6px;text-align:left;word-break:break-all}
.b-table th{color:var(--muted);font-weight:600;background:var(--bg2)}
</style>
