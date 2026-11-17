<template>
  <div class="page">
    <div class="grid2">
      <div class="card">
        <h4>模型配置（可配置多个，创建项目时选择）</h4>
        <div v-for="m in models" :key="m.id" class="model-row">
          <div style="flex:1">
            <b>{{ m.label || m.id }}</b> <span class="chip">{{ m.protocol }}</span>
            <div class="mono" style="font-size:11px;color:var(--muted)">{{ m.base_url }} · {{ m.model }} · Key {{ m.api_key_set ? '已配置' : '未配置' }}</div>
            <div v-if="m.testResult" class="mono" style="font-size:11px;margin-top:3px;white-space:pre-wrap" :style="{color: m.testResult.ok ? 'var(--green)' : 'var(--red)'}">{{ m.testResult.text }}</div>
          </div>
          <button class="small" :disabled="m.testing" @click="testSaved(m)">{{ m.testing ? '测试中…' : '测试' }}</button>
          <button class="small" @click="editModel(m)">编辑</button>
          <button v-if="m.id !== def" class="small" @click="setDefault(m.id)">设为默认</button>
          <button class="small ghost" style="color:var(--red)" @click="del(m.id)">删除</button>
        </div>
        <details class="opt" open>
          <summary style="cursor:pointer;color:var(--accent2);font-size:12.5px">添加 / 修改模型</summary>
          <label class="fld">快速填充预设</label>
          <select v-model="preset" @change="applyPreset">
            <option value="">— 选择服务商 —</option>
            <option v-for="name in presetNames" :key="name">{{ name }}</option>
          </select>
          <div class="grid2">
            <div><label class="fld">显示名称</label><input v-model="form.label"></div>
            <div><label class="fld">协议</label><select v-model="form.protocol"><option value="openai">openai（绝大多数服务商）</option><option value="anthropic">anthropic</option></select></div>
          </div>
          <label class="fld">模型名（下拉选择 / 拉取 / 手填）</label>
          <div class="model-row" style="position:relative">
            <input v-model="form.model" autocomplete="off" placeholder="deepseek-chat" style="flex:1"
                   @focus="ddFilter = ''; showModelDropdown = true"
                   @input="ddFilter = form.model; showModelDropdown = true"
                   @blur="hideModelDropdownLater()">
            <button class="small" v-if="modelChoices.length" :title="'显示全部 ' + modelChoices.length + ' 个候选'" @click.prevent="showModelDropdown = !showModelDropdown">▾</button>
            <button class="small" :disabled="fetchingModels || (!form.base || (!form.key && !form.id))" @click="fetchModels" :title="(!form.base || (!form.key && !form.id)) ? '需先填 Base URL 和 API Key（编辑已存模型可留空 key）' : ''">{{ fetchingModels ? '拉取中…' : '拉取模型列表' }}</button>
            <!-- v5.4.1 自定义下拉：原生 datalist 会按输入值过滤候选（输入已有模型名时其它候选被滤掉，
                 实测 DeepSeek 拉取 2 个只显示 1 个）——改为聚焦显示全部、输入时过滤、点击填入 -->
            <div v-if="showModelDropdown && filteredModelChoices.length" class="model-dropdown">
              <div v-for="n in filteredModelChoices" :key="n" class="model-dd-item" @mousedown.prevent="pickModel(n)">{{ n }}</div>
            </div>
          </div>
          <div style="font-size:11px;color:var(--muted);margin-top:3px">模型清单来源：{{ modelChoicesSource }}</div>
          <label class="fld">Base URL</label><input v-model="form.base" placeholder="https://api.deepseek.com/v1">
          <label class="fld">API Key（留空保持不变）</label><input v-model="form.key" type="password">
          <div class="model-row" style="margin-top:10px">
            <button class="primary" @click="save">保存模型</button>
            <button class="small" :disabled="formTesting" @click="testForm">{{ formTesting ? '测试中…' : '先测试连接' }}</button>
          </div>
          <div v-if="formTestResult" class="mono" style="font-size:11.5px;margin-top:6px;white-space:pre-wrap" :style="{color: formTestResult.ok ? 'var(--green)' : 'var(--red)'}">{{ formTestResult.text }}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:6px">测试为中性探针真实调用（约几十 token）——可验证密钥/模型名/欠费；不覆盖业务内容风控（个别供应商对渗透语义内容有拦截）</div>
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
import { onMounted, reactive, ref, computed } from 'vue'
import { api } from '../api.js'
import { session } from '../stores/session.js'

const models = reactive([]), def = ref('')
const preset = ref('')
const form = reactive({ id: '', label: '', protocol: 'openai', base: '', model: '', key: '' })
const modelChoices = reactive([])
const modelChoicesSource = ref('（选择服务商后填入常见清单；填好 Base URL + Key 可拉取实时清单）')
const fetchingModels = ref(false)
const showModelDropdown = ref(false)
const ddFilter = ref('') // v5.4.1：仅输入时过滤——聚焦/选择后显示全部（原 datalist 与首版下拉都栽在"按输入值过滤"上）
const filteredModelChoices = computed(() => {
  const q = (ddFilter.value || '').trim().toLowerCase()
  if (!q) return modelChoices
  return modelChoices.filter(n => n.toLowerCase().includes(q))
})
function pickModel(n) { form.model = n; ddFilter.value = ''; showModelDropdown.value = false }
function hideModelDropdownLater() { setTimeout(() => { showModelDropdown.value = false }, 180) }
const formTesting = ref(false)
const formTestResult = ref(null)
const recon = reactive({ shodan: '', fofaEmail: '', fofa: '', quake: '', zoomeye: '' })
const price = reactive({ in: 1, out: 4 })
const ph = reactive({ recon: {} })

// v5.4.0 服务商预设扩容：全部为 OpenAI 兼容层 / Anthropic 原生端点（引擎仅支持 openai/anthropic 双协议）。
// models 为静态兜底清单（服务商不支持列举接口或拉取失败时使用）；支持列举的服务商可点「拉取模型列表」取实时清单。
const PRESETS = {
  'DeepSeek': { protocol: 'openai', base: 'https://api.deepseek.com/v1', model: 'deepseek-chat', models: ['deepseek-chat', 'deepseek-reasoner'] },
  'OpenAI': { protocol: 'openai', base: 'https://api.openai.com/v1', model: 'gpt-4o', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4.1', 'gpt-4.1-mini', 'o3', 'o4-mini'] },
  'Anthropic': { protocol: 'anthropic', base: 'https://api.anthropic.com', model: 'claude-sonnet-4-5', models: ['claude-sonnet-4-5', 'claude-opus-4-1', 'claude-haiku-4-5', 'claude-3-5-haiku-latest'] },
  '火山方舟': { protocol: 'openai', base: 'https://ark.cn-beijing.volces.com/api/v3', model: 'doubao-seed-1.6', models: ['doubao-seed-1.6', 'doubao-1-5-pro-32k-250115', 'deepseek-v3-241224'] },
  '火山方舟 Coding': { protocol: 'openai', base: 'https://ark.cn-beijing.volces.com/api/coding/v3', model: 'glm-5.3-flash', models: ['glm-5.3-flash', 'kimi-k2', 'deepseek-v3'] },
  '智谱 GLM': { protocol: 'openai', base: 'https://open.bigmodel.cn/api/paas/v4', model: 'glm-4.6', models: ['glm-4.6', 'glm-4.5', 'glm-4.5-air', 'glm-4-flash'] },
  'Kimi 月之暗面': { protocol: 'openai', base: 'https://api.moonshot.cn/v1', model: 'kimi-k2-0905-preview', models: ['kimi-k2-0905-preview', 'kimi-k2-turbo-preview', 'kimi-latest', 'moonshot-v1-128k'] },
  '阿里百炼': { protocol: 'openai', base: 'https://dashscope.aliyuncs.com/compatible-mode/v1', model: 'qwen-max', models: ['qwen-max', 'qwen-plus', 'qwen-turbo', 'qwen3-235b-a22b'] },
  '百度千帆': { protocol: 'openai', base: 'https://qianfan.baidubce.com/v2', model: 'ernie-4.5-turbo-128k', models: ['ernie-4.5-turbo-128k', 'ernie-4.5-8k', 'ernie-speed-8k'] },
  '腾讯混元': { protocol: 'openai', base: 'https://api.hunyuan.cloud.tencent.com/v1', model: 'hunyuan-turbos-latest', models: ['hunyuan-turbos-latest', 'hunyuan-t1-latest', 'hunyuan-large'] },
  'MiniMax': { protocol: 'openai', base: 'https://api.minimaxi.chat/v1', model: 'MiniMax-M2', models: ['MiniMax-M2', 'MiniMax-Text-01', 'abab6.5s-chat'] },
  '讯飞星火': { protocol: 'openai', base: 'https://spark-api-open.xf-yun.com/v1', model: '4.0Ultra', models: ['4.0Ultra', 'generalv3.5', 'max-32k'] },
  '硅基流动': { protocol: 'openai', base: 'https://api.siliconflow.cn/v1', model: 'deepseek-ai/DeepSeek-V3', models: ['deepseek-ai/DeepSeek-V3', 'deepseek-ai/DeepSeek-R1', 'Qwen/Qwen3-235B-A22B', 'Qwen/Qwen2.5-72B-Instruct'] },
  'Google Gemini': { protocol: 'openai', base: 'https://generativelanguage.googleapis.com/v1beta/openai', model: 'gemini-2.5-pro', models: ['gemini-2.5-pro', 'gemini-2.5-flash', 'gemini-2.0-flash'] },
  'xAI Grok': { protocol: 'openai', base: 'https://api.x.ai/v1', model: 'grok-4', models: ['grok-4', 'grok-3', 'grok-3-mini'] },
  'Mistral': { protocol: 'openai', base: 'https://api.mistral.ai/v1', model: 'mistral-large-latest', models: ['mistral-large-latest', 'mistral-medium-latest', 'mistral-small-latest'] },
  'Groq': { protocol: 'openai', base: 'https://api.groq.com/openai/v1', model: 'llama-3.3-70b-versatile', models: ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'qwen/qwen3-32b'] },
  'OpenRouter': { protocol: 'openai', base: 'https://openrouter.ai/api/v1', model: 'openai/gpt-4o', models: ['openai/gpt-4o', 'anthropic/claude-sonnet-4.5', 'deepseek/deepseek-chat'] },
  'Together': { protocol: 'openai', base: 'https://api.together.xyz/v1', model: 'deepseek-ai/DeepSeek-V3', models: ['deepseek-ai/DeepSeek-V3', 'Qwen/Qwen2.5-72B-Instruct', 'meta-llama/Llama-3.3-70B-Instruct-Turbo'] },
  'Ollama 本地': { protocol: 'openai', base: 'http://host.docker.internal:11434/v1', model: 'qwen2.5:7b', models: ['qwen2.5:7b', 'qwen2.5:14b', 'llama3.1:8b'] },
  'vLLM 本地': { protocol: 'openai', base: 'http://host.docker.internal:8000/v1', model: '', models: [] },
  'LM Studio 本地': { protocol: 'openai', base: 'http://host.docker.internal:1234/v1', model: '', models: [] },
  '自定义 / one-api 聚合': { protocol: 'openai', base: '', model: '', models: [] }
}
const presetNames = Object.keys(PRESETS)

function applyPreset() {
  const p = PRESETS[preset.value]
  if (!p) return
  Object.assign(form, { base: p.base, model: p.model, protocol: p.protocol })
  fillModelChoices(p.models || [], `预设清单（${preset.value}）· 建议拉取实时清单`)
}
function fillModelChoices(list, source) {
  modelChoices.splice(0); modelChoices.push(...list)
  modelChoicesSource.value = source
}
async function fetchModels() {
  if (!form.base || (!form.key && !form.id)) return
  fetchingModels.value = true
  try {
    const j = await api('/api/settings/models/available', 'POST', { protocol: form.protocol, base_url: form.base, model: form.model, api_key: form.key, id: (form.id && !form.key) ? form.id : '' })
    const list = j.models || []
    if (!list.length) throw new Error('服务商未返回任何模型')
    fillModelChoices(list, `实时拉取（${list.length} 个 · ${form.base}）`)
    showModelDropdown.value = true // v5.4.1：拉取成功立即展开全部候选（不被输入值过滤）
    session.showToast(`已拉取 ${list.length} 个模型，输入框下方可直接选择`)
  } catch (e) {
    const fb = (PRESETS[preset.value] || {}).models || []
    if (fb.length) {
      fillModelChoices(fb, `拉取失败，回退预设清单（${preset.value}）· 可手填任意模型名`)
      session.showToast('拉取失败：' + e.message + '（已回退预设清单）')
    } else {
      session.showToast('拉取失败：' + e.message + '（该服务商可能不支持列举，请手填模型名）')
    }
  } finally { fetchingModels.value = false }
}

// v5.4.0 连通性测试：已保存模型行「测试」按钮（按 id，服务端用已存 key）
async function testSaved(m) {
  m.testing = true; m.testResult = null
  try {
    const j = await api('/api/settings/models/test', 'POST', { id: m.id })
    m.testResult = j.ok
      ? { ok: true, text: `✅ ${Math.round(j.duration_ms / 100) / 10}s · ${j.total_tokens || '?'} tokens · 回复: ${j.reply || '(空)'}` }
      : { ok: false, text: `❌ ${Math.round(j.duration_ms / 100) / 10}s · ${j.error || '未知错误'}` }
  } catch (e) { m.testResult = { ok: false, text: '❌ ' + e.message } }
  finally { m.testing = false }
}
// 表单「先测试连接」：未保存字段直测（key 留空且在编辑已存模型时回退已存 key）
async function testForm() {
  if (!form.base || !form.model) return session.showToast('测试前请先填 Base URL 与模型名')
  formTesting.value = true; formTestResult.value = null
  try {
    const j = await api('/api/settings/models/test', 'POST', { id: form.id, protocol: form.protocol, base_url: form.base, model: form.model, api_key: form.key })
    formTestResult.value = j.ok
      ? { ok: true, text: `✅ ${j.model} · ${Math.round(j.duration_ms / 100) / 10}s · 回复: ${j.reply || '(空)'}` }
      : { ok: false, text: `❌ ${j.model} · ${j.error || '未知错误'}` }
  } catch (e) { formTestResult.value = { ok: false, text: '❌ ' + e.message } }
  finally { formTesting.value = false }
}
function editModel(m) {
  Object.assign(form, { id: m.id, label: m.label, protocol: m.protocol, base: m.base_url, model: m.model, key: '' })
  preset.value = ''
  fillModelChoices([m.model], `当前已存模型（${m.label || m.id}）`)
}

async function reload() {
  const j = await api('/api/settings/models')
  models.splice(0); models.push(...(j.models || [])); def.value = j.default || ''
}
async function save() {
  try {
    // v5.4.0：protocol 改为显式选择（原实现依赖预设名判断——选「自定义」无法指定协议）
    await api('/api/settings/models', 'POST', { id: form.id, label: form.label, protocol: form.protocol, base_url: form.base, model: form.model, api_key: form.key, default: !def.value || !form.id })
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
/* v5.4.1 模型名自定义下拉（替代原生 datalist——后者按输入值过滤候选） */
.model-dropdown{position:absolute;top:100%;left:0;right:0;z-index:30;max-height:220px;overflow-y:auto;
  background:var(--bg2);border:1px solid var(--border);border-radius:8px;
  box-shadow:var(--shadow-lg);margin-top:2px}
.model-dd-item{padding:7px 12px;font-size:12.5px;cursor:pointer;color:var(--text2)}
.model-dd-item:hover{background:rgba(88,166,255,.12);color:var(--text)}
</style>
