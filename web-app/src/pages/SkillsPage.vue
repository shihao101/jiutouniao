<template>
  <div class="page">
    <input v-model="q" placeholder="搜索技能（如：注入 / LLM / 横向 / 提权 / 报告）" style="max-width:420px;margin-bottom:12px">
    <div class="grid2">
      <div v-for="s in list" :key="s.id" class="card skill" @click="session.showModal('技能 · ' + s.id + ' · ' + s.title, s.body)">
        <b class="mono">{{ s.id }}</b> · {{ s.title }}
        <div style="margin-top:6px"><span v-for="t in (s.tags || [])" :key="t" class="chip">{{ t }}</span></div>
        <div style="color:var(--muted);font-size:11.5px;margin-top:6px">完整剧本 {{ (s.body || '').length }} 字 · 点击查看</div>
      </div>
    </div>

    <!-- v3.7.0 组织级教训（跨项目脱敏经验，record_lesson 登记）——与技能同属知识库 -->
    <div class="card" style="margin-top:14px">
      <h4>组织级教训（{{ lessons.length }}）—— 跨项目脱敏经验，智能体经 record_lesson 登记</h4>
      <div v-if="!lessons.length" style="color:var(--muted);font-size:12px;margin-top:6px">暂无教训（项目收口/失败复盘时由智能体登记，引擎自动校验脱敏）</div>
      <ul style="font-size:12.5px;line-height:1.8;margin-top:6px">
        <li v-for="l in lessons" :key="l.id">{{ l.text }}<span v-if="l.tags" class="chip" style="margin-left:6px">{{ l.tags }}</span></li>
      </ul>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '../api.js'
import { session } from '../stores/session.js'

const skills = ref([]), lessons = ref([]), q = ref('')
onMounted(async () => {
  skills.value = (await api('/api/skills')) || []
  try { lessons.value = (await api('/api/lessons')) || [] } catch (e) {}
})
const list = computed(() => skills.value.filter(s => !q.value || (s.title + s.id + (s.tags || []).join()).toLowerCase().includes(q.value.toLowerCase())))
</script>

<style scoped>
.skill{cursor:pointer}
.skill:hover{border-color:var(--accent2)}
</style>
