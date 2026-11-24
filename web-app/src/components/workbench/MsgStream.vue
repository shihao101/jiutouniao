<template>
  <div class="ms">
    <div class="ms-head">
      <b>执行流 · 对话工作台</b>
      <span class="chip">{{ stream.events.length }} 条</span>
      <span class="chip" v-if="projects.runningStage">阶段 {{ projects.runningStage }} 运行中</span>
      <span style="flex:1"></span>
      <label style="font-size:11px;color:var(--muted);display:flex;align-items:center;gap:4px">
        <input type="checkbox" v-model="showLog" style="width:auto"> 日志
        <span style="display:inline-flex;gap:4px;margin-left:8px">
          <button v-for="kf in [['all','全部'],['msg','消息'],['tool','工具'],['log','日志']]" :key="kf[0]"
                  class="kf" :class="{on: kindFilter===kf[0]}" @click="kindFilter=kf[0]">{{ kf[1] }}</button>
        </span>
      </label>
    </div>

    <div class="ms-body" ref="boxEl">
      <div v-if="!stream.events.length" class="empty">
        {{ projects.current ? '暂无执行记录——启动流水线或在下方对话/下达指令' : '选择项目后显示统一执行流' }}
      </div>
      <template v-for="(e, i) in visible" :key="e.seq || i">
        <!-- 对话/阶段消息 -->
        <div v-if="e.kind === 'msg'" class="msg" :class="e.role === 'user' ? 'me' : 'ai'">
          <div class="avatar">{{ e.role === 'user' ? '我' : '九' }}</div>
          <div class="body">
            <div class="who">{{ e.role === 'user' ? (session.user || '我') : '九头鸟' }}
              <span v-if="e.stage && e.stage !== 'chat'" style="color:var(--gold)">· 阶段 {{ e.stage }}</span>
              · {{ fmtTime(e.ts) }}</div>
            <div class="bubble" v-html="md2html(e.text)"></div>
          </div>
        </div>
        <!-- 工具调用块 -->
        <div v-else-if="e.kind === 'tool'" class="msg sys">
          <div class="avatar">器</div>
          <div class="body" style="min-width:0">
            <div class="toolcard" :class="{open: opened.has(i), ['tc-' + toolTone(e.tool)]: true}">
              <div class="th" @click="toggle(i)">
                <span class="tn">{{ e.tool }}</span>
                <span style="color:var(--muted);font-size:11px">{{ e.stage || '' }} · {{ fmtTime(e.ts) }} · {{ opened.has(i) ? '收起' : '展开' }}</span>
              </div>
              <pre v-if="opened.has(i)">args: {{ e.args }}{{ e.result ? '\n─────\nresult: ' + e.result : '' }}</pre>
            </div>
          </div>
        </div>
        <!-- 引擎日志 -->
        <div v-else-if="e.kind === 'log' && showLog" class="msg sys">
          <div class="avatar">·</div>
          <div class="body">
            <div class="bubble">[{{ e.stage || '' }}] {{ e.text }} <span style="color:var(--muted)">{{ fmtTime(e.ts) }}</span></div>
          </div>
        </div>
      </template>
    </div>

    <div class="ms-input">
      <div class="chips" style="padding:0 12px 6px">
        <span v-for="c in chips" :key="c" class="chip" style="cursor:pointer" @click="input = c">{{ c }}</span>
      </div>
      <div style="display:flex;gap:8px;padding:0 12px 12px">
        <textarea v-model="input" rows="2" style="flex:1;resize:none"
                  :placeholder="projects.isRunning ? '项目运行中：输入将作为指令注入执行流（下一轮生效，Ctrl+Enter 发送）' : '向九头鸟提问或下达任务（Ctrl+Enter 发送）'"
                  @keydown.ctrl.enter.prevent="send" @keydown.meta.enter.prevent="send"></textarea>
        <button class="primary" style="align-self:flex-end" :disabled="busy || !input.trim()" @click="send">发送</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, nextTick, watch } from 'vue'
// P2：工具卡语义左边条（按工具名分型，纯前端映射零数据变更）
function toolTone(name) {
  const n = name || ''
  if (n === 'record_finding') return 'finding'
  if (n === 'record_loot' || n === 'upsert_fact') return 'loot'
  if (n === 'request_approval' || n === 'request_user_input') return 'approval'
  if (n === 'complete_stage' || n === 'loopback') return 'stage'
  if (n === 'run_command' || n === 'hexstrike_command' || n === 'run_async') return 'cmd'
  return 'plain'
}
import { stream } from '../../stores/stream.js'
import { projects } from '../../stores/projects.js'
import { session } from '../../stores/session.js'
import { api } from '../../api.js'
import { md2html, fmtTime } from '../../labels.js'

const input = ref(''), busy = ref(false), showLog = ref(true)
const boxEl = ref(null)
const opened = ref(new Set())
const toggle = i => { const s = new Set(opened.value); s.has(i) ? s.delete(i) : s.add(i); opened.value = s }
const chips = ['汇报当前进度', '继续推进测试', '列出待审批工单', '暂停新测试并收口本阶段', '把最新发现整理成 finding']

// v3.7.0 执行流类型过滤：全部/消息/工具/日志（原只有日志开关）
const kindFilter = ref('all')
const visible = computed(() => {
  let evs = stream.events
  if (!showLog.value) evs = evs.filter(e => e.kind !== 'log')
  if (kindFilter.value === 'msg') evs = evs.filter(e => e.kind === 'msg')
  else if (kindFilter.value === 'tool') evs = evs.filter(e => e.kind === 'tool')
  else if (kindFilter.value === 'log') evs = evs.filter(e => e.kind === 'log')
  return evs
})
const scrollBottom = () => { if (boxEl.value) boxEl.value.scrollTop = boxEl.value.scrollHeight }
watch(() => stream.events.length, () => nextTick(scrollBottom))

async function send() {
  const msg = input.value.trim()
  if (!msg || busy.value) return
  input.value = ''; busy.value = true
  try {
    const j = await api(`/api/projects/${projects.currentId}/chat`, 'POST', { message: msg })
    // 用户侧气泡与回复都由后端写入 stream（统一时间线），这里仅提示路由结果
    if (j.started) session.showToast('已触发断点续跑（工作台单一入口）')
    else if (j.routed) session.showToast('指令已送达执行流（下一轮注入，执行后可见回执）')
    // 未路由的对话回复稍后经 WS/回填自然出现；双时刻补拉增量加快反馈（600ms 拉用户气泡，2.8s 拉回复）
    setTimeout(() => stream.pollIncrement(projects.currentId).catch(() => {}), 600)
    setTimeout(() => stream.pollIncrement(projects.currentId).catch(() => {}), 2800)
  } catch (e) { session.showToast('发送失败：' + e.message) }
  busy.value = false
}
</script>

<style scoped>
.ms{display:flex;flex-direction:column;min-height:0}
.ms-head{height:40px;display:flex;align-items:center;gap:8px;padding:0 14px;border-bottom:1px solid var(--border);flex-shrink:0}
.ms-body{flex:1;overflow-y:auto;padding:6px 14px}
.ms-input{border-top:1px solid var(--border);background:var(--bg2);padding-top:8px}
textarea{max-height:110px}
.kf{font-size:10.5px;padding:1px 8px;border:1px solid var(--border);border-radius:9px;background:var(--bg);color:var(--muted);cursor:pointer}
.kf.on{color:var(--text);border-color:var(--text2)}
.toolcard{border-left-width:3px}
.toolcard.tc-finding{border-left-color:var(--red)}
.toolcard.tc-loot{border-left-color:var(--green)}
.toolcard.tc-approval{border-left-color:var(--purple)}
.toolcard.tc-stage{border-left-color:var(--accent2)}
.toolcard.tc-cmd{border-left-color:var(--border)}
</style>
