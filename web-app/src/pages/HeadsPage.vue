<template>
  <div class="page">
    <div class="grid2">
      <div v-for="h in heads" :key="h.id" class="card skill" @click="session.showModal('提示词 · ' + h.id + ' · ' + h.name, h.body)">
        <b class="mono">{{ h.id }}</b> · {{ h.name }}
        <span class="badge pending" style="margin-left:8px">{{ h.kind === 'stage' ? '阶段 ' + h.stage : h.kind === 'spec' ? '专项' : '主控' }}</span>
        <div style="color:var(--muted);font-size:11.5px;margin-top:6px">提示词 {{ (h.body || '').length }} 字 · 点击查看</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../api.js'
import { session } from '../stores/session.js'

const heads = ref([])
onMounted(async () => { heads.value = ((await api('/api/heads')) || []).sort((a, b) => (a.order || 99) - (b.order || 99)) })
</script>

<style scoped>
.skill{cursor:pointer}
.skill:hover{border-color:var(--accent2)}
</style>
