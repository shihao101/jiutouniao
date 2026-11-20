<template>
  <div class="page">
    <!-- v3.7.0 项目模板：一键填充通用型测试的常用口径（默认 ROE 为底，模板叠加专项条款，可再手动微调） -->
    <div class="card" style="margin-bottom:12px">
      <div style="font-size:12px;color:var(--muted);margin-bottom:6px">快速模板（填充授权范围 / 叠加专项 ROE / 切换测试类型，提交前请核对授权信息）</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        <button v-for="t in templates" :key="t.name" class="small" style="border:1px solid var(--border);background:var(--bg);color:var(--text)"
                @click="applyTemplate(t)">{{ t.name }}</button>
      </div>
    </div>
    <div class="grid2">
      <div class="card">
        <h4>目标与授权</h4>
        <label class="fld">项目名称 *</label>
        <input v-model="f.name" placeholder="如：XX 系统 Web 渗透测试">
        <label class="fld">目标（每行一个）*</label>
        <textarea v-model="f.target" rows="3" placeholder="demo.example.com&#10;10.70.160.234&#10;https://chat.example.com（LLM 应用入口）"></textarea>
        <label class="fld">授权范围（一句话写清目标与边界即可；v6.0.0 支持授权语义——内网资产不必事先枚举）<button class="small ghost" style="margin-left:8px" @click="resetScope">重置</button></label>
        <textarea v-model="f.scope" rows="2" placeholder="如：授权 test.example.com 全部子域与 80/443 端口，含立足点可达内网资产的受控横向（逐项审批）；第三方组件与生产数据库除外"></textarea>
        <label class="fld">测试规则 ROE（一句话写清禁区与纪律即可）<button class="small ghost" style="margin-left:8px" @click="resetRoe">重置</button></label>
        <textarea v-model="f.roe" rows="3"></textarea>
        <label class="fld">测试目的 / 成功标准（一句话即可）<button class="small ghost" style="margin-left:8px" @click="resetSuccess">重置</button></label>
        <textarea v-model="f.success" rows="2"></textarea>
        <label class="fld">认证会话（可选·登录后测试）</label>
        <textarea v-model="f.auth" rows="2" placeholder="测试账号 / Cookie / Token 说明（仅用于授权测试）"></textarea>
      </div>
      <div class="card">
        <h4>运行配置</h4>
        <div class="row2">
          <div>
            <label class="fld">测试类型</label>
            <select v-model="f.testType"><option>黑盒</option><option>灰盒</option><option>白盒</option></select>
          </div>
          <div>
            <label class="fld">模型</label>
            <select v-model="f.modelId"><option value="">默认模型</option><option v-for="m in models" :key="m.id" :value="m.id">{{ m.label || m.id }}（{{ m.model }}）</option></select>
          </div>
        </div>
        <label class="fld">九头编制（点击加载专项头；说明见 title 悬浮）</label>
        <div class="spec-row">
          <div class="spec-chip" :class="{on: f.specs.has('A')}" @click="toggle('A')"
               title="专项 A · AI(LLM)：提示注入 / 越狱 / 系统提示提取 / Agent 工具滥用（A1-A11），OWASP LLM Top10 + ATLAS">
            {{ f.specs.has('A') ? '☑' : '☐' }} 专项 A · AI(LLM)</div>
          <div class="spec-chip" :class="{on: f.specs.has('B1')}" @click="toggle('B1')"
               title="专项 B1 · APP 静态+动态：jadx 反编译审计 + Frida 运行时双链，OWASP MASTG">
            {{ f.specs.has('B1') ? '☑' : '☐' }} 专项 B1 · APP</div>
          <div class="spec-chip" :class="{on: f.specs.has('B2')}" @click="toggle('B2')"
               title="专项 B2 · 小程序全流程：wxapkg 解包 → 密钥审计 → 前端逻辑 → 接口与云侧（W1-W6）">
            {{ f.specs.has('B2') ? '☑' : '☐' }} 专项 B2 · 小程序</div>
        </div>
        <div class="row2">
          <div>
            <label class="fld">审批策略</label>
            <select v-model="f.policy" title="自动批准的操作全部落库留痕；FORBIDDEN 破坏性命令始终拒绝">
              <option value="l1">推荐：仅 L2 人工批准</option>
              <option value="manual">全部人工批准</option>
              <option value="all">全部自动批准</option>
            </select>
          </div>
          <div>
            <label class="fld">执行档</label>
            <select v-model="f.profile" title="引擎逐动作强制；违禁动作在任何通道执行前确定性拦截">
              <option value="production_safe">production_safe（默认·生产目标）</option>
              <option value="isolated_lab">isolated_lab（隔离靶场）</option>
            </select>
          </div>
        </div>
        <label v-if="f.profile==='isolated_lab'" class="checkline"><input type="checkbox" v-model="f.labAck" style="width:auto">隔离靶场确认（可快照回滚，收尾以快照恢复为准）</label>
        <label v-if="f.profile==='isolated_lab'" class="checkline" title="v6.0.0 预批准全通过：提权/横向等全部审批工单自动通过（含后续新增类别）；执行档/写门/范围门等确定性治理门照常前置，一个都绕不过。仅限授权充分的隔离靶场。"><input type="checkbox" v-model="f.preAll" style="width:auto">预批准全通过（靶场提权/横向免逐单审批）</label>
        <label class="checkline" title="S6：提权 / 横向 / 权限维持演示 / 云容器逃逸 / 存量排查；默认不执行，不勾选则 S5 后直接收尾报告（s6 标记范围决策跳过，可手动重跑）"><input type="checkbox" v-model="f.postExploit" style="width:auto">后渗透阶段 S6（默认不执行）</label>
        <label class="checkline" title="只测给定目标，范围外线索只记录不访问"><input type="checkbox" v-model="f.strict" style="width:auto">严格限定范围</label>
        <label class="checkline" title="九头按序自动推进"><input type="checkbox" v-model="f.autostart" style="width:auto">创建后立即启动</label>
        <label class="checkline auth-line" :class="{ok: f.authorized}" title="必勾，否则无法创建；测试风险与合规边界见审批矩阵"><input type="checkbox" v-model="f.authorized" style="width:auto">授权确认：已获<b>书面授权</b>（必勾）</label>
        <div class="guard-note">
          <b>审批矩阵</b>：L0 自动留痕 / L1·L2 按策略审批（全留痕）/ FORBIDDEN 拒绝 · 全程可一键熔断
        </div>
        <button class="primary" style="width:100%;margin-top:12px;padding:9px" :disabled="!f.authorized || creating" @click="create">{{ creating ? '创建中…' : (f.authorized ? '创建项目并授权开工' : '请先勾选授权确认') }}</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api.js'
import { session } from '../stores/session.js'
import { projects } from '../stores/projects.js'

const router = useRouter()

// v5.3.7 表单标准化：三个自由文本域统一为「编号小节」结构（可编辑、可一键重置）。
// 锁定短语（只登记移交/注册面只评估不注册/自建账号默认禁止/使用客户提供的测试账号）为合规口径，重写时不得丢失。
const DEFAULT_SCOPE = `授权目标：客户书面授权的域名/子域名、端口服务与 API 路径；范围外资产只记录不访问。`

const DEFAULT_ROE = `仅测试已授权目标；禁止破坏性写入、持久化、拒绝服务与批量下载；高危动作逐项审批；生产数据只做存在性证明；凭据只登记掩码；自建数据登记移交不删除；异常立即停止并上报。`

const DEFAULT_SUCCESS = `测试目的：发现并验证可利用漏洞；成功标准：每条结论有可复现 POC 证据与影响说明，如实披露未覆盖项。`

// v3.7.0 项目模板（通用型口径：不同目标类型的范围草稿 + 在通用 ROE 上叠加专项条款）
const templates = [
  { name: 'Web 应用（黑盒）', scope: '已确认授权的域名、子域名与端口（Web 服务全部路径）；范围外线索只记录、不继续访问。', roe: '登录/注册类测试使用客户提供的测试账号（注册面只评估不注册，自建账号默认禁止）；验证码走人机协同口径，不自动打码。', tt: '黑盒' },
  { name: 'APP / 小程序', scope: '已确认授权的 APP/小程序包及其后端 API 域名与端口；范围外线索只记录、不继续访问。', roe: '禁止破解分发、禁止拖取真实用户数据（只做存在性证明）；动态测试限授权设备与账号。', tt: '黑盒' },
  { name: '内网 / 主机（灰盒）', scope: '已确认授权的内网网段、主机与端口；凭据以授权发放为准；范围外资产只记录不访问。', roe: '横向移动类动作逐项审批；凭据只登记掩码摘要不落明文；限速探测避免影响业务。', tt: '灰盒' },
  { name: 'AI / LLM 应用', scope: '已确认授权的 LLM 应用入口、API 与其后端服务；提示注入测试仅针对授权实例。', roe: '不产出违法内容的越权滥用；输出中敏感信息只做存在性证明；注入载荷可清理、不持久化。', tt: '黑盒' },
]
function applyTemplate(t) {
  f.scope = t.scope
  f.roe = DEFAULT_ROE + ' 专项：' + t.roe
  f.testType = t.tt
}
// v5.3.7 一键重置：恢复标准结构（ROE 重置会丢弃已叠加的专项条款——快速模板可重新叠加）
function resetScope() { f.scope = DEFAULT_SCOPE }
function resetRoe() { f.roe = DEFAULT_ROE }
function resetSuccess() { f.success = DEFAULT_SUCCESS }

const f = reactive({ name: '', target: '', scope: '', roe: DEFAULT_ROE, success: '', auth: '', testType: '黑盒', specs: new Set(), modelId: '', policy: 'manual', profile: 'production_safe', labAck: false, preAll: false, postExploit: false, strict: true, autostart: true, authorized: false })
const models = reactive([])
const creating = ref(false) // 创建进行中防重复提交（双击会产出两个同内容项目并双双自动开工）

onMounted(async () => {
  try { models.push(...((await api('/api/settings/models')).models || [])) } catch (e) {}
  // v5.3.7 标准化预填：范围/成功标准空态时填入标准结构（ROE 常量初始已带标准结构）
  if (!f.scope) f.scope = DEFAULT_SCOPE
  if (!f.success) f.success = DEFAULT_SUCCESS
})
function toggle(s) { f.specs.has(s) ? f.specs.delete(s) : f.specs.add(s); f.specs = new Set(f.specs) }

async function create() {
  if (creating.value) return
  if (!f.name.trim() || !f.target.trim()) return session.showToast('项目名称与目标必填')
  if (!f.authorized) return session.showToast('请先勾选「授权确认」：未获书面授权不得开工')
  if (f.profile === 'isolated_lab' && !f.labAck) return session.showToast('isolated_lab 需勾选「隔离靶场确认」：仅限可快照回滚的专用靶场')
  creating.value = true
  try {
    const p = await api('/api/projects', 'POST', {
      name: f.name.trim(), target: f.target.trim(), scope: f.scope, roe: f.roe,
      success_criteria: f.success, test_type: f.testType, auth_info: f.auth,
      strict_scope: f.strict, model_id: f.modelId, auto_approve: f.policy,
      pre_approved: (f.profile === 'isolated_lab' && f.preAll) ? 'all' : 'none', // 切档后残留勾选不外泄（安全边界）
      execution_profile: f.profile,
      post_exploit: f.postExploit,
      authorized: f.authorized, specializations: [...f.specs]
    })
    session.showToast('项目已创建 ' + p.id)
    await projects.loadList()
    await projects.select(p.id)
    router.push('/workbench')
    if (f.autostart) {
      try { await api(`/api/projects/${p.id}/start`, 'POST'); session.showToast('流水线已启动，九头按序推进') }
      catch (e) { session.showToast('已创建；自动启动失败：' + e.message) }
    }
  } catch (e) { session.showToast('创建失败：' + e.message) } finally { creating.value = false }
}
</script>

<style scoped>
.fld{display:block;color:var(--muted);font-size:12px;margin:9px 0 4px}
input,select,textarea{width:100%}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.row2 select{width:100%}
.spec-row{display:flex;gap:6px;flex-wrap:wrap;margin:4px 0 2px}
.spec-chip{border:1px solid var(--border);border-radius:var(--r-full,999px);padding:4px 12px;font-size:12px;cursor:pointer;color:var(--text2);white-space:nowrap;user-select:none}
.spec-chip.on{border-color:var(--accent2);background:rgba(88,166,255,.10);color:var(--text)}
.checkline{display:flex;gap:7px;align-items:center;font-size:12.5px;margin:6px 0;color:var(--text2)}
.checkline.auth-line{border:1px dashed var(--border);border-radius:8px;padding:8px 10px;margin-top:10px}
.checkline.auth-line.ok{border-color:var(--green);background:rgba(63,185,80,.06)}
.guard-note{background:rgba(210,153,34,.07);border:1px solid rgba(210,153,34,.35);border-radius:8px;padding:9px 12px;font-size:12px;color:var(--text2);margin-top:10px}
</style>
