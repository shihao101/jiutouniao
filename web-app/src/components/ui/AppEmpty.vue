<template>
  <div class="app-empty">
    <component :is="icon" v-if="icon" :size="34" stroke-width="1.4" class="ae-icon" aria-hidden="true" />
    <div class="ae-title">{{ title }}</div>
    <div v-if="hint" class="ae-hint">{{ hint }}</div>
    <div v-if="$slots.default" class="ae-actions"><slot /></div>
  </div>
</template>

<script setup>
// P0 基础组件：空态（图标 + 主文案 + 副文案 + 动作插槽）
defineProps({ title: { type: String, required: true }, hint: { type: String, default: '' }, icon: { type: [Object, Function], default: null } })
</script>

<style scoped>
.app-empty{display:flex;flex-direction:column;align-items:center;gap:6px;padding:var(--sp-7) var(--sp-4);text-align:center}
.ae-icon{color:var(--muted);opacity:.8}
.ae-title{font-size:var(--fs-sm);color:var(--text2)}
.ae-hint{font-size:var(--fs-xs);color:var(--muted)}
.ae-actions{margin-top:var(--sp-2)}
</style>
