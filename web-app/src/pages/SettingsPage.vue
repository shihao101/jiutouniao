<template>
  <div class="page">
    <div class="grid2">
      <div class="card">
        <h4>模型配置（可配置多个，创建项目时选择）</h4>
        <div v-for="m in models" :key="m.id" class="model-row">
          <div style="flex:1">
            <b>{{ m.label || m.id }}</b> <span class="chip">{{ m.protocol }}</span>
            <div class="mono" style="font-size:11px;color:var(--muted)">{{ m.base_url }} · {{ m.model }} · Key {{ m.api_key_set ? '已配置' : '未配置' }}</div>
          </div>
          <button v-if="m.id !== def" class="small" @click="setDefault(m.id)">设为默认</button>
          <button class="small ghost" style="color:var(--red)" @click="del(m.id)">删除</button>
        </div>
        <details class="opt" open>
          <summary style="cursor:pointer;color:var(--accent2);font-size:12.5px">添加 / 修改模型</summary>
          <label class="fld">快速填充预设</label>
          <select v-model="preset" @change="applyPreset">
            <option value="">— 选择服务商 —</option>
            <option>火山方舟</option><option>OpenAI</option><option>Anthropic</option><option>DeepSeek</option><option>Ollama</option><option>自定义</option>
          </select>
          <div class="grid2">
            <div><label class="fld">显示名称</label><input v-model="form.label"></div>
            <div><label class="fld">模型名</label><input v-model="form.model" placeholder="deepseek-chat"></div>
          </div>
          <label class="fld">Base URL</label><input v-model="form.base" placeholder="https://api.deepseek.com/v1">
          <label class="fld">API Key（留空保持不变）</label><input v-model="form.key" type="password">
          <button class="primary" style="margin-top:10px" @click="save">保存模型</button>
        </details>

        <h4 style="margin-top:18px">成本单价（$/1M tokens，按所选模型计）</h4>
        <div class="grid2">
          <div><label class="fld">输入价</label><input v-model.number="price.in" type="number" step="0.01"></div>
          <div><label class="fld">输出价</label><input v-model.number="price.out" type="number" step="0.01"></div>
        </div>
        <button class="primary" style="margin-top:10px" @click="savePrice">保存单价</button>
      </div>

      <div class="card">
        <h4>空间测绘 Key（加密存储，注入执行环境）</h4>
        <label class="fld">Shodan API Key</label><input v-model="recon.shodan" type="password" :placeholder="ph.recon?.shodan">
        <label class="fld">FOFA Email</label><input v-model="recon.fofaEmail">
        <label class="fld">FOFA Key</label><input v-model="recon.fofa" type="password" :placeholder="ph.recon?.fofa">
        <label class="fld">Quake 360 Key</label><input v-model="recon.quake" type="password" :placeholder="ph.recon?.quake">
        <label class="fld">ZoomEye Key</label><input v-model="recon.zoomeye" type="password" :placeholder="ph.recon?.zoomeye">
        <button class="primary" style="margin-top:10px" @click="saveRecon">保存测绘 Key</button>
      </div>
    </div>

    <div class="card" style="margin-top:14px">
      <h4>代理配置（v5.0 · 支持 http/https/socks5，含认证 user:pass@host:port）</h4>
      <p style="margin:4px 0 10px;color:var(--text2);font-size:12px;line-height:1.9">
        三类流量分级：①<b>工具下载代理</b>——注入 $TOOL_PROXY 供智能体按需使用（apt/pip/git/curl 下载类），立即热生效；②<b>目标流量出口池</b>——写入 $JT_EXIT_POOL 供 W5 出口池（exit-pool.py）按需轮换，默认关闭（对目标流量默认直连口径不变，项目内显式启用）；③<b>LLM 出口</b>——跟随部署环境变量（只读）。端点加密存储，回显仅掩码。</p>
      <div class="grid2">
        <div>
          <label class="fld">工具下载代理（留空保持不变）</label>
          <input v-model="proxy.toolProxy" type="password" :placeholder="proxy.toolMasked || '如 http://192.168.1.10:7897 或 socks5://user:pass@host:1080'">
          <div style="font-size:11.5px;color:var(--muted);margin-top:4px">当前：{{ proxy.toolMasked || '未配置' }}</div>
          <button class="small" style="margin-top:6px" :disabled="!proxy.toolProxy || proxy.testing" @click="testProxy(proxy.toolProxy, 'tool')">{{ proxy.testing ? '测试中…' : '连通性测试' }}</button>
          <div v-if="proxy.testResult" class="mono" style="font-size:11.5px;margin-top:6px;white-space:pre-wrap">{{ proxy.testResult }}</div>
        </div>
        <div>
          <label class="fld" style="display:flex;align-items:center;gap:8px">
            <input type="checkbox" v-model="proxy.targetEnabled" style="width:auto"> 启用目标流量出口池（默认关闭——项目级显式使用，ROE 留痕）
          </label>
          <div v-for="(x, i) in proxy.exits" :key="i" class="model-row">
            <input v-model="x.name" placeholder="名称" style="width:90px">
            <select v-model="x.kind" style="width:90px"><option>http</option><option>https</option><option>socks5</option></select>
            <input v-model="x.endpoint" placeholder="host:port（或 scheme://user:pass@host:port）" style="flex:1">
            <button class="small ghost" style="color:var(--red)" @click="proxy.exits.splice(i, 1)">删</button>
          </div>
          <button class="small" @click="proxy.exits.push({ name: '', kind: 'http', endpoint: '' })">+ 添加出口</button>
          <div v-if="proxy.exits.length" style="margin-top:8px">
            <button class="small" :disabled="proxy.testing" @click="testProxy(proxy.exits[0].endpoint, 'exit')">测试首个出口连通性</button>
          </div>
        </div>
      </div>
      <div style="font-size:11.5px;color:var(--muted);margin-top:8px">LLM 出口（只读）：{{ proxy.llmEnv || '未设置（compose LLM_PROXY）' }}</div>
      <button class="primary" style="margin-top:10px" @click="saveProxy">保存代理配置</button>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { session } from '../stores/session.js'

const models = reactive([]), def = ref('')
const preset = ref('')
const form = reactive({ id: '', label: '', base: '', model: '', key: '' })
const recon = reactive({ shodan: '', fofaEmail: '', fofa: '', quake: '', zoomeye: '' })
const price = reactive({ in: 1, out: 4 })
const ph = reactive({ recon: {} })

const PRESETS = {
  '火山方舟': { protocol: 'openai', base: 'https://ark.cn-beijing.volces.com/api/v3', model: 'doubao-seed-1.6' },
  'OpenAI': { protocol: 'openai', base: 'https://api.openai.com/v1', model: 'gpt-4o' },
  'Anthropic': { protocol: 'anthropic', base: 'https://api.anthropic.com', model: 'claude-sonnet-4-5' },
  'DeepSeek': { protocol: 'openai', base: 'https://api.deepseek.com/v1', model: 'deepseek-chat' },
  'Ollama': { protocol: 'openai', base: 'http://host.docker.internal:11434/v1', model: 'qwen2.5:7b' }
}
function applyPreset() { const p = PRESETS[preset.value]; if (p) Object.assign(form, { base: p.base, model: p.model }) }

async function reload() {
  const j = await api('/api/settings/models')
  models.splice(0); models.push(...(j.models || [])); def.value = j.default || ''
}
async function save() {
  try {
    await api('/api/settings/models', 'POST', { id: form.id, label: form.label, protocol: preset.value === 'Anthropic' ? 'anthropic' : 'openai', base_url: form.base, model: form.model, api_key: form.key, default: !def.value || !form.id })
    session.showToast('模型已保存'); form.key = ''; await reload()
  } catch (e) { session.showToast(e.message) }
}
async function setDefault(id) {
  try {
    const m = models.find(x => x.id === id)
    await api('/api/settings/models', 'POST', { id, label: m.label, protocol: m.protocol, base_url: m.base_url, model: m.model, default: true })
    await reload(); session.showToast('默认模型已切换')
  } catch (e) { session.showToast(e.message) }
}
async function del(id) {
  if (!confirm('删除该模型配置？')) return
  try { await api(`/api/settings/models?id=${id}`, 'DELETE'); await reload() } catch (e) { session.showToast(e.message) }
}
async function saveRecon() {
  try { await api('/api/settings/recon', 'POST', { shodan: recon.shodan, fofa_email: recon.fofaEmail, fofa_key: recon.fofa, quake: recon.quake, zoomeye: recon.zoomeye }); session.showToast('测绘 Key 已保存并注入执行环境') }
  catch (e) { session.showToast(e.message) }
}
async function savePrice() {
  try { await api('/api/settings/price', 'POST', { in: price.in, out: price.out }); session.showToast('单价已保存') }
  catch (e) { session.showToast(e.message) }
}

// ---- v5.0 代理模块 ----
const proxy = reactive({ toolProxy: '', toolMasked: '', targetEnabled: false,
  exits: [], llmEnv: '', testing: false, testResult: '' })
async function loadProxy() {
  try {
    const j = await api('/api/settings/proxy')
    proxy.toolMasked = j.tool_proxy_masked || ''
    proxy.targetEnabled = !!j.target_enabled
    proxy.exits = (j.exits || []).map(x => ({ name: x.name, kind: x.kind, endpoint: '', masked: x.endpoint_masked }))
    proxy.llmEnv = j.llm_proxy_env || ''
  } catch (e) { /* 静默：未登录/接口不可用 */ }
}
async function saveProxy() {
  try {
    await api('/api/settings/proxy', 'POST', {
      tool_proxy: proxy.toolProxy, target_enabled: proxy.targetEnabled,
      exits: proxy.exits.map(x => ({ name: x.name, kind: x.kind, endpoint: x.endpoint }))
    })
    session.showToast('代理配置已保存并注入执行环境'); proxy.toolProxy = ''; await loadProxy()
  } catch (e) { session.showToast(e.message) }
}
async function testProxy(endpoint, tag) {
  if (!endpoint) { session.showToast('先填写代理端点'); return }
  proxy.testing = true; proxy.testResult = ''
  try {
    const j = await api('/api/settings/proxy/test', 'POST', { proxy: endpoint })
    proxy.testResult = (tag === 'tool' ? '工具代理' : '出口') + '测试: ' + (j.ok ? '✅ ' : '❌ ') + (j.output || j.error || '') + ' (' + j.duration_ms + 'ms)'
  } catch (e) { proxy.testResult = '❌ ' + e.message }
  finally { proxy.testing = false }
}
onMounted(async () => {
  await reload()
  const s = await api('/api/settings')
  ph.recon = { shodan: s.recon?.shodan ? '已配置（留空保持）' : '', fofa: s.recon?.fofa ? '已配置（留空保持）' : '', quake: s.recon?.quake ? '已配置（留空保持）' : '', zoomeye: s.recon?.zoomeye ? '已配置（留空保持）' : '' }
  if (s.recon?.fofa_email) recon.fofaEmail = s.recon.fofa_email
  if (s.pricing) { price.in = s.pricing.in; price.out = s.pricing.out }
; await loadProxy()})
</script>

<style scoped>
.model-row{display:flex;gap:8px;align-items:center;border-bottom:1px dashed var(--border);padding:8px 0}
.fld{display:block;color:var(--muted);font-size:12px;margin:8px 0 4px}
input,select{width:100%}
details.opt input, details.opt select{margin-bottom:2px}
</style>
