<template>
  <div class="page">
    <!-- v3.7.0 攻击路径图（交付视图）：graphviz 渲染的 SVG，缺省自动隐藏 -->
    <div class="card" v-if="graphSvg">
      <h4>攻击路径图（黑板事实缝合，attack-graph）</h4>
      <div style="overflow:auto;margin-top:8px" v-html="graphSvg"></div>
    </div>
    <div class="card">
      <h4>渗透测试报告（report.md，阶段 8 交付）</h4>
      <!-- v6.9.0（S8-⑧）导出区：findings.json / findings.sarif 结项导出物的一键下载——
           移交附件说明（S8-3）承诺的移交物此前仅通用 file API 可达，UI 层断链 -->
      <div style="margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <button class="small" @click="downloadExport('findings.json')">下载 findings.json</button>
        <button class="small" @click="downloadExport('findings.sarif')">下载 findings.sarif</button>
        <span style="font-size:var(--fs-xs);color:var(--text2)">{{ exportHint }}</span>
      </div>
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
const exportHint = ref('结项后自动导出（findings.json / findings.sarif 2.1.0）')

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
// v6.9.0（S8-⑧）导出下载：走通用 file API 取文本内容，Blob 触发浏览器下载；
// 结项前导出物未生成时如实提示（不伪造空文件）。
async function downloadExport(name) {
  if (!projects.currentId) return
  try {
    const r = await fetch(`/api/projects/${projects.currentId}/file?path=${encodeURIComponent(name)}`, { headers: { Authorization: 'Bearer ' + session.token } })
    if (!r.ok) {
      exportHint.value = `${name} 尚未导出（项目结项时自动生成）。`
      return
    }
    const j = await r.json()
    const blob = new Blob([j.content || ''], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = name
    a.click()
    URL.revokeObjectURL(url)
    exportHint.value = `${name} 已开始下载。`
  } catch (e) {
    exportHint.value = '下载失败：' + e.message
  }
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
