<template>
  <div class="page">
    <!-- v3.7.0 攻击路径图（交付视图）：graphviz 渲染的 SVG，缺省自动隐藏 -->
    <div class="card" v-if="graphSvg">
      <h4>攻击路径图（黑板事实缝合，attack-graph）</h4>
      <div style="overflow:auto;margin-top:8px" v-html="graphSvg"></div>
    </div>
    <div class="card">
      <h4>渗透测试报告（report.md，阶段 8 交付）</h4>
      <pre style="white-space:pre-wrap;word-break:break-all;font-size:12.5px;margin-top:10px">{{ content }}</pre>
    </div>
  </div>
</template>

<script setup>
import { ref, watch, onMounted } from 'vue'
import { projects } from '../stores/projects.js'
import { session } from '../stores/session.js'

const content = ref('报告尚未生成。')
const graphSvg = ref('')

// v3.7.0 攻击路径图：读 deliverables/attack-graph.svg（graphviz 渲染；无 graphviz 环境时自动隐藏）
async function loadGraph() {
  graphSvg.value = ''
  if (!projects.currentId) return
  try {
    const r = await fetch(`/api/projects/${projects.currentId}/file?path=deliverables/attack-graph.svg`, { headers: { Authorization: 'Bearer ' + session.token } })
    if (!r.ok) return
    const j = await r.json()
    const svg = j.content || ''
    if (svg.includes('<svg')) graphSvg.value = svg
  } catch (e) {}
}
async function load() {
  if (!projects.currentId) { content.value = '选择项目后显示报告。'; return }
  try {
    const r = await fetch(`/api/projects/${projects.currentId}/report`, { headers: { Authorization: 'Bearer ' + session.token } })
    if (!r.ok) { content.value = '报告尚未生成（阶段 8 交付）。'; return }
    const ct = r.headers.get('content-type') || ''
    if (ct.includes('application/json')) {
      const j = await r.json()
      content.value = j.exists && j.content ? j.content : '报告尚未生成（阶段 8 交付）。'
    } else {
      content.value = await r.text()
    }
  } catch (e) { content.value = '加载失败：' + e.message }
}
onMounted(() => { load(); loadGraph() })
watch(() => projects.currentId, () => { load(); loadGraph() })
</script>
