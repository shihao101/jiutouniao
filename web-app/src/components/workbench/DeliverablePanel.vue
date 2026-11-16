<template>
  <div>
    <div class="sec-title">交付物（共 {{ projects.filesTotal }} · 显示 {{ projects.files.length }}）</div>
    <div v-if="!projects.files.length" class="empty">暂无文件——各阶段结束会产出交付物</div>
    <template v-for="g in groups" :key="g.key">
      <div v-if="g.items.length" class="g-title">{{ g.label }}（{{ g.items.length }}）</div>
      <div v-for="f in g.items" :key="f.path" class="f-row" @click="view(f.path)">
        <span class="mono" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis">{{ shortName(f.path) }}</span>
        <span style="color:var(--muted);font-size:11px">{{ fmtSize(f.size) }}</span>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import { projects } from '../../stores/projects.js'
import { session } from '../../stores/session.js'
import { api } from '../../api.js'
import { fmtSize } from '../../labels.js'

// 分层白名单展示：结项产出置顶，反编译/解包噪声（apktool_out/jadx_out/assets_www 等）不再进入本面板
const groups = computed(() => {
  const fs = projects.files
  const by = pred => fs.filter(pred)
  return [
    { key: 'final', label: '结项产出', items: by(f => !f.path.includes('/')) },
    { key: 'deliverables', label: '阶段交付物', items: by(f => f.path.startsWith('deliverables/')) },
    { key: 'poc', label: 'PoC', items: by(f => f.path.startsWith('poc/')) },
    { key: 'packages', label: '测试对象', items: by(f => f.path.startsWith('packages/')) },
    { key: 'evidence', label: '证据链', items: by(f => f.path.startsWith('evidence/')) },
  ]
})
// 分组标题已表明层级，行内只显示文件名
function shortName(p) { return p.includes('/') ? p.slice(p.lastIndexOf('/') + 1) : p }
onMounted(() => projects.loadFiles())
async function view(path) {
  try {
    const j = await api(`/api/projects/${projects.currentId}/file?path=${encodeURIComponent(path)}`)
    session.showModal('交付物 · ' + path, j.content)
  } catch (e) { session.showToast(e.message) }
}
</script>

<style scoped>
.sec-title{font-size:12px;color:var(--muted);margin:6px 0 8px;font-weight:600}
.g-title{font-size:12px;color:var(--text2);margin:10px 0 4px;font-weight:600;border-top:1px solid var(--border);padding-top:8px}
.g-title:first-of-type{border-top:none;padding-top:0}
.f-row{display:flex;gap:8px;align-items:center;padding:6px 8px;border-radius:7px;cursor:pointer}
.f-row:hover{background:var(--bg3)}
</style>
