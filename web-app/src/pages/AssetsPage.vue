<template>
  <div class="page">
    <div v-if="!projects.current" class="empty">选择项目后显示资产</div>
    <table v-else>
      <thead><tr><th>类型</th><th>资产值</th><th>详情</th><th>阶段</th></tr></thead>
      <tbody>
        <tr v-if="!(projects.detail?.assets || []).length"><td colspan="4" class="empty">暂无资产</td></tr>
        <tr v-for="a in projects.detail?.assets || []" :key="a.id">
          <td>{{ a.type }}</td>
          <td class="mono">{{ a.value }}</td>
          <td style="color:var(--text2);word-break:break-all">{{ a.detail }}</td>
          <td>{{ a.stage }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import { projects } from '../stores/projects.js'
onMounted(() => { if (projects.currentId && !projects.detail) projects.select(projects.currentId) })
</script>
