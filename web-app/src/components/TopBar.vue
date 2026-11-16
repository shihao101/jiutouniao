<template>
  <div class="topbar">
    <b style="color:var(--accent2);letter-spacing:1px">九头鸟（鬼車）</b>
    <span class="chip" title="实际运行版本">{{ session.pubinfo?.version ? 'v' + session.pubinfo.version : '' }}</span>

    <select style="max-width:260px" :value="projects.currentId" @change="onSelect($event.target.value)" title="切换项目">
      <option value="">— 选择项目 —</option>
      <option v-for="p in projects.list" :key="p.id" :value="p.id">{{ p.id }} · {{ p.name }}（{{ STATUS_CN[p.status] || p.status }}）</option>
    </select>

    <span v-if="projects.current" class="badge" :class="projects.current.status">{{ STATUS_CN[projects.current.status] || projects.current.status }}</span>
    <span v-if="projects.current" class="chip" style="cursor:pointer" title="点击复制工作区相对路径（宿主机 ./projects/ 下同名目录；导入 APP/小程序包放入此处，智能体下一轮自动可见）" @click="copyWs">编号 {{ projects.current.id }} ｜ 工作区 projects/{{ projects.current.id }}/</span>

    <span style="flex:1"></span>

    <template v-if="projects.current">
      <span v-if="wsState" class="chip" :style="{color: stream.connected ? 'var(--green)' : 'var(--gold)'}">{{ wsState }}</span>
      <span class="chip" title="审批策略">策略: {{ POLICY_CN[projects.current.auto_approve || 'l1'] }}</span>
      <button class="small danger" @click="kill">熔断</button>
      <button class="small danger" :disabled="projects.isRunning"
              :title="projects.isRunning ? '运行中项目不可删除——请先熔断' : '彻底删除项目记录与工作区（不可恢复）'"
              @click="delProject">删除</button>
    </template>

    <span v-if="tokenText" class="chip" :style="{color:'var(--purple)'}">{{ tokenText }}</span>
    <button class="small ghost tb-icon" @click="session.toggleTheme()" :title="session.theme === 'dark' ? '切换浅色主题' : '切换深色主题'" :aria-label="session.theme === 'dark' ? '切换浅色主题' : '切换深色主题'">
      <component :is="session.theme === 'dark' ? Moon : Sun" :size="14" aria-hidden="true" /><span class="tb-txt">{{ session.theme === 'dark' ? '深色' : '浅色' }}</span>
    </button>
    <span class="chip"><UserRound :size="12" style="vertical-align:-2px" aria-hidden="true" /> {{ session.user }}</span>
    <button class="small ghost" @click="logout"><LogOut :size="13" style="vertical-align:-2px" aria-hidden="true" /> 退出</button>
  </div>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { Moon, Sun, LogOut, UserRound } from 'lucide-vue-next'
import { session } from '../stores/session.js'
import { projects } from '../stores/projects.js'
import { stream } from '../stores/stream.js'
import { STATUS_CN, POLICY_CN } from '../labels.js'
import { api } from '../api.js'

const router = useRouter()

// 版本号加载兜底：App.vue 仅在「带会话刷新」时拉取 pubinfo，
// 登录页进入时从不加载，导致顶栏版本 chip 恒为空（Bug#1 表现①）
onMounted(async () => {
  if (!session.pubinfo) {
    session.pubinfo = await fetch('/api/public/info').then(r => r.json()).catch(() => null)
  }
})
const wsState = computed(() => {
  if (!projects.currentId) return ''
  const u = projects.detail?.usage
  const tok = u?.total_tokens ? `${u.total_tokens.toLocaleString()} tok · $${projects.cost()}` : ''
  return (stream.connected ? '● ' : '● 断连 ') + (tok || '实时')
})
const tokenText = computed(() => {
  const u = projects.detail?.usage
  return u?.total_tokens ? null : ''
})

async function onSelect(id) {
  if (!id) return router.push('/')
  await projects.select(id)
  router.push('/workbench')
}
async function kill() {
  const reason = prompt('熔断原因：') || '人工熔断'
  try {
    await api(`/api/projects/${projects.currentId}/kill`, 'POST', { reason })
    session.showToast('已一键熔断')
    await projects.refresh()
  } catch (e) { session.showToast(e.message) }
}
// v5.3.5：彻底删除项目（记录+工作区）——两步确认，运行中禁用（后端同样拒绝）
async function delProject() {
  const id = projects.currentId
  if (!id) return
  if (!confirm(`彻底删除项目 ${id}？\n\n将同时删除全部记录（发现/证据/时间线/覆盖/子任务/用量等）与工作区目录（deliverables/evidence/报告）。\n此操作不可恢复！`)) return
  const typed = prompt(`二次确认：请输入项目编号 ${id} 以执行删除`)
  if (typed !== id) { session.showToast('编号不一致，已取消删除'); return }
  try {
    await api(`/api/projects/${id}`, 'DELETE')
    session.showToast('项目已彻底删除')
    await projects.loadList()
    await projects.select('')
    router.push('/')
  } catch (e) { session.showToast(e.message) }
}
// v2.7.1：一键复制工作区路径——导入 APP/小程序包时按编号找到宿主机 projects/<编号>/ 目录
async function copyWs() {
  const t = `projects/${projects.current.id}`
  try { await navigator.clipboard.writeText(t) } catch {
    const ta = document.createElement('textarea'); ta.value = t; document.body.appendChild(ta); ta.select()
    document.execCommand('copy'); ta.remove()
  }
  session.showToast('已复制：' + t + '（放入 APP/小程序包后，智能体下一轮自动可见）')
}
async function logout() {
  try { await api('/api/logout', 'POST') } catch (e) {}
  session.logout(); location.hash = '#/login'; location.reload()
}
</script>

<style scoped>
.topbar{height:46px;display:flex;align-items:center;gap:10px;padding:0 14px;border-bottom:1px solid var(--border);background:var(--bg2)}
.tb-icon{display:inline-flex;align-items:center;gap:4px}
.tb-txt{font-size:var(--fs-xs)}
</style>
