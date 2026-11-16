<template>
  <div v-if="!session.token" class="h-full"><router-view /></div>
  <div v-else class="h-full" style="display:flex;flex-direction:column">
    <TopBar />
    <div style="flex:1;min-height:0;display:flex">
      <NavRail />
      <div style="flex:1;min-width:0;overflow:hidden" role="main"><router-view /></div>
    </div>
  </div>
  <!-- 全局 Toast -->
  <div v-if="session.toast.show" class="toast">{{ session.toast.text }}</div>
  <!-- 全局 Modal -->
  <div v-if="session.modal.show" class="modal-mask" @click.self="session.modal.show = false">
    <div class="modal">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
        <b>{{ session.modal.title }}</b>
        <button class="small ghost" @click="session.modal.show = false">关闭</button>
      </div>
      <pre style="max-height:60vh;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:12px">{{ session.modal.body }}</pre>
    </div>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import TopBar from './components/TopBar.vue'
import NavRail from './components/NavRail.vue'
import { session } from './stores/session.js'
import { projects } from './stores/projects.js'
import { api } from './api.js'

const router = useRouter()
const sessionRef = session

// P2 快捷键：g 前缀两段式（g d 仪表盘 / g w 工作台 / g f 漏洞 / g a 资产 / g t 时间线 / g r 报告 / g s 设置），输入框聚焦时不劫持
const KEYMAP = { d: '/', w: '/workbench', f: '/findings', a: '/assets', t: '/timeline', r: '/report', s: '/settings' }
let gPending = false, gTimer = null
function onKey(e) {
  const tag = (e.target && e.target.tagName || '').toLowerCase()
  if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable) return
  if (gPending) {
    const dest = KEYMAP[e.key.toLowerCase()]
    gPending = false; clearTimeout(gTimer)
    if (dest) { e.preventDefault(); router.push(dest) }
    return
  }
  if (e.key.toLowerCase() === 'g') {
    gPending = true
    clearTimeout(gTimer); gTimer = setTimeout(() => { gPending = false }, 900)
  }
}
onMounted(() => window.addEventListener('keydown', onKey))
onUnmounted(() => window.removeEventListener('keydown', onKey))

onMounted(async () => {
  if (!session.token) return
  // 恢复会话：验证令牌并拉取基础数据
  try {
    await api('/api/projects')
    session.pubinfo = await fetch('/api/public/info').then(r => r.json()).catch(() => null)
    await projects.loadList()
    const last = localStorage.getItem('jt_last_project')
    if (last && projects.list.some(p => p.id === last)) {
      await projects.select(last)
      router.push('/workbench')
    }
  } catch (e) { /* 401 已跳登录 */ }
})
</script>

<style>
/* .toast/.modal 样式已上收全局 style.css（P0 令牌化） */
.h-full{height:100%}
</style>
