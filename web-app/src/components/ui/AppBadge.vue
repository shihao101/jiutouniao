<template>
  <span class="badge" :class="status"><span v-if="dot" class="dot" aria-hidden="true"></span>{{ text }}</span>
</template>

<script setup>
// P0 基础组件：状态徽章（可带呼吸圆点）
import { computed } from 'vue'
const props = defineProps({ status: { type: String, required: true }, text: { type: String, default: '' }, dot: { type: Boolean, default: false } })
const text = computed(() => props.text || props.status)
</script>

<style scoped>
.dot{width:6px;height:6px;border-radius:var(--r-full);background:currentColor;display:inline-block}
.badge.running .dot{animation:pulse 1.6s ease infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
</style>
