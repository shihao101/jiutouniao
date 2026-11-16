<template>
  <div class="srail">
    <div class="panel-head">阶段流水线</div>
    <div class="srail-body">
      <div v-for="[sid, st] in projects.stageEntries" :key="sid" class="stage-item" :class="{active: selected === sid, [st.status]: true}"
           @click="selected = sid">
        <span class="bar"></span>
        <div style="flex:1;min-width:0">
          <div class="st-name">
            {{ sid.startsWith('spec') ? '专项' : '阶段' }} {{ sid.replace(/^s/, '').replace('spec', '') }} · {{ STAGE_NAMES[sid] || sid }}
          </div>
          <div class="st-meta">
            <span class="st-status" :style="{color: dotColor(st.status)}">{{ dotIcon(st.status) }} {{ STATUS_CN[st.status] || st.status }}</span>
            <template v-if="st.iterations"> · {{ st.iterations }} 轮</template>
            <template v-if="(st.deliverables || []).length"> · 交付物 {{ st.deliverables.length }}</template>
          </div>
        </div>
      </div>
      <div class="panel-sub">项目概要</div>
      <div class="kv"><span>目标</span><span class="mono" :title="projects.current?.target">{{ (projects.current?.target || '-').split('\n')[0] }}</span></div>
      <div class="kv"><span>类型</span><span>{{ projects.current?.test_type || '黑盒' }}</span></div>
      <div class="kv"><span>专项</span><span>{{ (projects.current?.specializations || []).join(',') || '无' }}</span></div>
      <div class="kv"><span>资产</span><span>{{ (projects.detail?.assets || []).length }}</span></div>
      <div class="kv"><span>漏洞</span><span>{{ (projects.detail?.findings || []).length }}</span></div>
      <div class="kv"><span>证据</span><span>{{ (projects.detail?.evidence || []).length }}</span></div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { projects } from '../../stores/projects.js'
import { STAGE_NAMES, STATUS_CN } from '../../labels.js'

const selected = ref('')
const dotIcon = s => ({ pending: '○', created: '○', running: '◐', done: '●', failed: '✗', killed: '✗', skipped: '⊘' }[s] || '○')
const dotColor = s => ({ running: 'var(--gold)', done: 'var(--green)', failed: 'var(--red)', killed: 'var(--red)' }[s] || 'var(--muted)')
</script>

<style scoped>
/* v2.3.0 与中/右栏统一 40px 面板头 */
.panel-head{height:40px;display:flex;align-items:center;padding:0 12px;font-weight:600;font-size:12.5px;border-bottom:1px solid var(--border);flex-shrink:0}
.panel-sub{color:var(--muted);font-size:11px;margin:12px 4px 6px}
.srail-body{padding:8px}
.stage-item{display:flex;gap:8px;align-items:stretch;padding:7px 8px 7px 6px;border-radius:8px;cursor:pointer;margin-bottom:3px;position:relative}
.stage-item:hover{background:var(--bg3)}
.stage-item.active{background:rgba(88,166,255,.1)}
.stage-item .bar{width:3px;border-radius:2px;background:var(--border);flex-shrink:0}
.stage-item.running .bar{background:var(--gold)}
.stage-item.done .bar{background:var(--green)}
.stage-item.failed .bar,.stage-item.killed .bar{background:var(--red)}
.st-name{font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.st-meta{font-size:10.5px;color:var(--muted);margin-top:1px}
.st-status{font-weight:500}
.kv{display:flex;justify-content:space-between;gap:6px;padding:3px 6px;color:var(--text2);font-size:11.5px}
.kv span:first-child{color:var(--muted)}
.kv span:last-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:110px}
</style>
