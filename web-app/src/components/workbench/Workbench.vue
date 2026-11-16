<template>
  <div v-if="!projects.current" class="page"><div class="empty">未选择项目——在顶栏选择或 <a href="#/create">新建项目</a></div></div>
  <div v-else class="wb-wrap">
    <!-- v3.7.4 重启恢复提醒：paused 项目此前无任何提示（实测 61 分钟无感知等待） -->
    <div v-if="projects.current?.status === 'paused'" class="paused-banner">
      ⏸ 本项目因引擎重启被暂停——在左侧「阶段流水线」点击当前阶段的「重跑」即可断点续测（已完成阶段不会重跑）
    </div>
    <div class="wb">
      <StageRail class="wb-left" />
      <MsgStream class="wb-center" />
      <Inspector class="wb-right" />
    </div>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, watch } from 'vue'
import { projects } from '../../stores/projects.js'
import StageRail from './StageRail.vue'
import MsgStream from './MsgStream.vue'
import Inspector from './Inspector.vue'

onMounted(async () => {
  // 直链进入时确保项目已选
  if (projects.currentId && !projects.detail) await projects.select(projects.currentId)
})

// v3.7.2 运行中数据兜底轮询：WS 事件驱动的定向刷新之外，每 15s 兜底刷
// 黑板/交付物/覆盖度——覆盖重连窗口与未映射事件，保证不刷新页面也能看到最新状态
let boardPoll = null
watch(() => projects.isRunning, running => {
  clearInterval(boardPoll); boardPoll = null
  if (running) boardPoll = setInterval(() => {
    if (!projects.currentId || document.hidden) return
    projects.loadBoard(projects.currentId).catch(() => {})
    projects.loadFiles().catch(() => {})
    projects.loadCoverage().catch(() => {})
  }, 15000)
}, { immediate: true })
onUnmounted(() => clearInterval(boardPoll))
</script>

<style scoped>
.wb-wrap{display:flex;flex-direction:column;height:calc(100vh - 46px);overflow:hidden}
.paused-banner{background:rgba(210,153,34,.12);border-bottom:1px solid rgba(210,153,34,.4);color:var(--text);font-size:12px;padding:6px 14px}
/* v2.3.0 三栏协调：左 208 / 中 flex / 右 368，统一 40px 面板头与列背景层次（左緅右浅，中为主） */
.wb{display:flex;flex:1;min-height:0;overflow:hidden}
.wb-left{width:208px;flex-shrink:0;border-right:1px solid var(--border);overflow-y:auto;background:var(--bg2)}
.wb-center{flex:1;min-width:0;display:flex;flex-direction:column;border-right:1px solid var(--border)}
.wb-right{width:368px;flex-shrink:0;display:flex;flex-direction:column;overflow:hidden;background:var(--bg2)}
@media (max-width:1280px){ .wb-right{width:320px} }
@media (max-width:1100px){ .wb-right{width:288px} .wb-left{width:172px} }
</style>
