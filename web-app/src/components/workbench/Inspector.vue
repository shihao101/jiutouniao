<template>
  <div class="insp">
    <div class="tabs">
      <template v-for="(t, i) in tabs" :key="t.id">
        <span v-if="i > 0" class="tsep">|</span>
        <div class="tab" :class="{active: cur === t.id}" @click="cur = t.id">
          {{ t.label }}<span v-if="t.badge" class="cnt">{{ fmtCnt(t.badge) }}</span>
        </div>
      </template>
    </div>
    <div class="insp-body">
      <ApprovalPanel v-show="cur === 'approval'" />
      <AutonomyPanel v-show="cur === 'autonomy'" />
      <SubtaskPanel v-show="cur === 'subtask'" />
      <ToolCallPanel v-show="cur === 'tools'" />
      <CoveragePanel v-show="cur === 'coverage'" />
      <DeliverablePanel v-show="cur === 'files'" />
      <BoardPanel v-show="cur === 'board'" />
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { projects } from '../../stores/projects.js'
import { stream } from '../../stores/stream.js'
import ApprovalPanel from './ApprovalPanel.vue'
import AutonomyPanel from './AutonomyPanel.vue'
import SubtaskPanel from './SubtaskPanel.vue'
import ToolCallPanel from './ToolCallPanel.vue'
import CoveragePanel from './CoveragePanel.vue'
import DeliverablePanel from './DeliverablePanel.vue'
import BoardPanel from './BoardPanel.vue'

// v3.7.4 BUG-001(B)：徽标压缩，>=100 显示 99+（6 Tab 窄面板下宽度可控）
function fmtCnt(n) { const v = Number(n); return v >= 100 ? '99+' : String(n) }
const cur = ref('approval')
const tabs = computed(() => [
  { id: 'approval', label: '审批/提问', badge: projects.pendingApprovals.length + projects.pendingAsks.length || '' },
  { id: 'autonomy', label: '自主决策' },
  { id: 'subtask', label: '子任务', badge: (projects.detail?.subtasks || []).length || '' },
  { id: 'tools', label: '工具调用', badge: stream.toolCalls.length || '' },
  { id: 'coverage', label: '覆盖度' },
  { id: 'files', label: '交付物', badge: (projects.files || []).length || '' },
  { id: 'board', label: '黑板', badge: (projects.facts || []).length + (projects.loot || []).length || '' }
])
// 有待审批时自动聚焦（仅首次）
import { watch } from 'vue'
watch(() => projects.pendingApprovals.length + projects.pendingAsks.length, n => { if (n > 0) cur.value = 'approval' })
</script>

<style scoped>
.insp{display:flex;flex-direction:column;min-height:0}
/* v2.3.0 页签等宽分布 + 40px 头，与左/中栏统一 */
.tabs{display:flex;height:40px;border-bottom:1px solid var(--border);flex-shrink:0;overflow-x:auto;overflow-y:hidden;scrollbar-width:thin}
.tab{flex:0 1 auto;min-width:0;display:flex;align-items:center;gap:5px;font-size:11.5px;color:var(--text2);cursor:pointer;white-space:nowrap;border-bottom:2px solid transparent;padding:0 6px;overflow:hidden}
.tsep{flex:0 0 auto;align-self:center;color:var(--border);font-size:11px;user-select:none}
.tab:hover{color:var(--text);background:var(--bg3)}
.tab.active{color:var(--accent2);border-bottom-color:var(--accent2);font-weight:600}
.tab .cnt{background:var(--red);color:#fff;border-radius:9px;padding:0 4px;font-size:9.5px;line-height:14px;flex-shrink:0}
.insp-body{flex:1;overflow-y:auto;padding:12px;min-height:0}
</style>
