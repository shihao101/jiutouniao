<template>
  <div>
    <div class="sec-title">子任务计划与进度（plan_subtasks / update_subtask）</div>
    <div v-if="!subs.length && !arch.length" class="empty">暂无子任务——阶段头开工后会自动建立计划</div>
    <div v-for="g in grouped" :key="g.stage" style="margin-bottom:12px">
      <div class="sec-title" style="margin:0 0 6px;color:var(--accent2)">
        {{ g.stage === 'chat' ? '对话指挥' : '阶段 ' + g.stage }}（{{ g.items.length }}）
      </div>
      <div v-for="t in g.items" :key="t.id" class="st-row">
        <span class="st-icon" :style="{color: SUBTASK_COLOR[t.status]}">{{ SUBTASK_ICON[t.status] || '○' }}</span>
        <div style="flex:1;min-width:0">
          <div style="font-size:12.5px">{{ t.title }} <span class="chip">{{ t.status }}</span></div>
          <div v-if="t.result" style="font-size:11px;color:var(--muted);white-space:pre-wrap">{{ t.result.slice(0, 140) }}</div>
        </div>
      </div>
    </div>
    <!-- v7.4.3 重建归档：回环/重进阶段重建计划前的旧条目只挪不删，历史可追溯 -->
    <div v-if="arch.length" style="margin-top:4px">
      <div class="sec-title" style="cursor:pointer" @click="showArch = !showArch">
        {{ showArch ? '▾' : '▸' }} 历史计划归档（{{ arch.length }}）——被后续重建替换的旧条目
      </div>
      <div v-for="t in (showArch ? arch : arch.slice(0, 0))" :key="'a' + t.id" class="st-row" style="opacity:.65">
        <span class="st-icon">🗂</span>
        <div style="flex:1;min-width:0">
          <div style="font-size:12px">{{ t.title }} <span class="chip">archived</span>
            <span style="font-size:10.5px;color:var(--muted)">· 阶段 {{ t.stage }} · {{ fmtTime(t.archived_at) }}</span></div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { projects } from '../../stores/projects.js'
import { SUBTASK_ICON, SUBTASK_COLOR, fmtTime } from '../../labels.js'

const subs = computed(() => projects.detail?.subtasks || [])
const arch = computed(() => projects.detail?.subtasks_archived || [])
const showArch = ref(false)
const grouped = computed(() => {
  const m = new Map()
  for (const t of subs.value) {
    if (!m.has(t.stage)) m.set(t.stage, [])
    m.get(t.stage).push(t)
  }
  return [...m.entries()].map(([stage, items]) => ({ stage, items }))
})
</script>

<style scoped>
.sec-title{font-size:12px;color:var(--muted);margin:6px 0;font-weight:600}
.st-row{display:flex;gap:7px;padding:4px 2px;align-items:flex-start}
.st-icon{font-size:13px;width:16px;flex-shrink:0;text-align:center}
</style>
