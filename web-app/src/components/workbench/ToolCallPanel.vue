<template>
  <div>
    <div class="sec-title">全部工具调用（{{ filtered.length }}/{{ stream.toolCalls.length }}）——审计视图：展开看完整 args/result</div>
    <select v-model="toolFilter" class="tf" style="margin-bottom:6px">
      <option value="">全部工具</option>
      <option v-for="t in toolNames" :key="t" :value="t">{{ t }}（{{ counts[t] || 0 }}）</option>
    </select>
    <div v-if="!stream.toolCalls.length" class="empty">暂无工具调用</div>
    <div v-for="(e, i) in [...filtered].reverse()" :key="i" class="toolcard" :class="{open: opened.has(i)}">
      <div class="th" @click="toggle(i)">
        <span class="tn">{{ e.tool }}</span>
        <span style="color:var(--muted);font-size:11px">{{ e.stage || '' }} · {{ fmtTime(e.ts) }} · {{ opened.has(i) ? '收起' : '展开' }}</span>
      </div>
      <pre v-if="opened.has(i)">args: {{ e.args }}{{ e.result ? '\n─────\nresult: ' + e.result : '' }}</pre>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { stream } from '../../stores/stream.js'
import { fmtTime } from '../../labels.js'

const opened = ref(new Set())
// v3.7.0 审计视图筛选：与 MsgStream 内联时序视图差异化（此处定位为全量审计）
import { computed } from 'vue'
const toolFilter = ref('')
const toolNames = computed(() => [...new Set(stream.toolCalls.map(e => e.tool))].sort())
const counts = computed(() => { const m = {}; for (const e of stream.toolCalls) m[e.tool] = (m[e.tool] || 0) + 1; return m })
const filtered = computed(() => toolFilter.value ? stream.toolCalls.filter(e => e.tool === toolFilter.value) : stream.toolCalls)
const toggle = i => { const s = new Set(opened.value); s.has(i) ? s.delete(i) : s.add(i); opened.value = s }
</script>

<style scoped>
.sec-title{font-size:12px;color:var(--muted);margin:6px 0 8px;font-weight:600}
.tf{width:100%;font-size:11.5px;padding:3px 6px;border:1px solid var(--border);border-radius:5px;background:var(--bg);color:var(--text)}
</style>
