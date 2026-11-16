<template>
  <div class="app-card" :class="{ hover }">
    <div v-if="title || $slots.actions" class="app-card-head">
      <h4><component :is="icon" v-if="icon" :size="15" class="ac-icon" aria-hidden="true" />{{ title }}</h4>
      <div class="app-card-actions"><slot name="actions" /></div>
    </div>
    <slot />
  </div>
</template>

<script setup>
// P0 基础组件：卡片（标题 + 可选图标 + 右侧动作插槽）
defineProps({ title: { type: String, default: '' }, icon: { type: [Object, Function], default: null }, hover: { type: Boolean, default: false } })
</script>

<style scoped>
.app-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r-md);padding:var(--sp-4);box-shadow:var(--shadow-sm);transition:border-color var(--tr),box-shadow var(--tr)}
.app-card.hover:hover{border-color:#3a4250;box-shadow:var(--shadow-md)}
.app-card-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--sp-3)}
.app-card-head h4{display:flex;align-items:center;gap:6px;font-size:var(--fs-md);font-weight:650}
.ac-icon{color:var(--accent2)}
</style>
