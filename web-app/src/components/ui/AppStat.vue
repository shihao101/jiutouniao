<template>
  <div class="app-stat stat-grad" :style="{ '--tone': toneColor }">
    <div class="app-stat-v stat-num" :style="{ color: toneColor }">
      <component :is="icon" v-if="icon" :size="17" style="vertical-align:-3px;margin-right:6px" aria-hidden="true" />{{ value }}
    </div>
    <div class="app-stat-l">{{ label }}</div>
  </div>
</template>

<script setup>
// P0 基础组件：统计卡（等宽数字 + 语义色调 + 可选图标）
import { computed } from 'vue'
const props = defineProps({
  value: { type: [String, Number], required: true },
  label: { type: String, required: true },
  tone: { type: String, default: 'info' }, // ok/danger/warn/info/block/neutral
  icon: { type: [Object, Function], default: null },
})
const TONES = { ok: 'var(--state-ok)', danger: 'var(--state-danger)', warn: 'var(--state-run)', info: 'var(--state-info)', block: 'var(--state-block)', neutral: 'var(--text)' }
const toneColor = computed(() => TONES[props.tone] || TONES.info)
</script>

<style scoped>
.app-stat{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r-md);padding:var(--sp-4) var(--sp-4) var(--sp-3);box-shadow:var(--shadow-sm);transition:transform var(--tr-fast),box-shadow var(--tr),border-color var(--tr)}
.app-stat:hover{transform:translateY(-1px);box-shadow:var(--shadow-md);border-color:#3a4250}
.app-stat-v{display:flex;align-items:center}
.app-stat-l{font-size:var(--fs-xs);color:var(--muted);margin-top:2px}
</style>
