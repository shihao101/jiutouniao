<template>
  <div>
    <div class="sec-title">子任务计划与进度（plan_subtasks / update_subtask）</div>
    <div v-if="!subs.length" class="empty">暂无子任务——阶段头开工后会自动建立计划</div>
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
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { projects } from '../../stores/projects.js'
import { SUBTASK_ICON, SUBTASK_COLOR } from '../../labels.js'

const subs = computed(() => projects.detail?.subtasks || [])
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
