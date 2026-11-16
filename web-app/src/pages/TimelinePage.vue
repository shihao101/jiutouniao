<template>
  <div class="page">
    <div v-if="!projects.current" class="empty">选择项目后显示时间线</div>
    <table v-else>
      <thead><tr><th>时间</th><th>事件</th><th>详情</th></tr></thead>
      <tbody>
        <tr v-if="!(projects.detail?.timeline || []).length"><td colspan="3" class="empty">暂无事件</td></tr>
        <tr v-for="t in projects.detail?.timeline || []" :key="t.id">
          <td class="mono">{{ fmtTime(t.created_at) }}</td>
          <td>{{ t.event }}</td>
          <td style="color:var(--text2);word-break:break-all">{{ t.detail }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import { projects } from '../stores/projects.js'
import { fmtTime } from '../labels.js'
onMounted(() => { if (projects.currentId && !projects.detail) projects.select(projects.currentId) })
</script>
