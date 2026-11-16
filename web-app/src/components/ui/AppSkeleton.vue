<template>
  <div class="sk-wrap" :style="{ width }">
    <div v-for="i in rows" :key="i" class="skeleton" :style="{ height: h, width: i === rows && lastShort ? '62%' : '100%', marginBottom: i < rows ? gap : 0 }" aria-hidden="true"></div>
  </div>
</template>

<script setup>
// P0 基础组件：骨架屏（加载态占位，shimmer 动画在全局 .skeleton）
defineProps({ rows: { type: Number, default: 3 }, h: { type: String, default: '14px' }, gap: { type: String, default: '8px' }, width: { type: String, default: '100%' }, lastShort: { type: Boolean, default: true } })
</script>

<style scoped>
.sk-wrap{display:block}
</style>
