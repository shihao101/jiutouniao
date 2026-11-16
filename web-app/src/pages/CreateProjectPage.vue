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
        <textarea v-model="f.target" rows="4" placeholder="demo.example.com&#10;10.70.160.234&#10;https://chat.example.com（LLM 应用入口）"></textarea>
        <label class="fld">授权范围（明确 in-scope / out-of-scope 边界，可编辑）<button class="small ghost" style="margin-left:8px" @click="resetScope">重置标准范围</button></label>
        <textarea v-model="f.scope" rows="5" placeholder="标准结构：【授权目标 in-scope】域名与子域名 / 端口服务 / API 路径；【明确排除 out-of-scope】第三方组件等；【通用边界】范围外线索只记录不访问"></textarea>
        <label class="fld">测试规则 ROE（可编辑；快速模板在标准 ROE 基础上叠加【七、专项条款】）<button class="small ghost" style="margin-left:8px" @click="resetRoe">重置标准 ROE</button></label>
        <textarea v-model="f.roe" rows="9"></textarea>
        <label class="fld">测试目的 / 成功标准（可编辑）<button class="small ghost" style="margin-left:8px" @click="resetSuccess">重置标准口径</button></label>
        <textarea v-model="f.success" rows="4"></textarea>
        <label class="fld">认证会话（可选·登录后测试）</label>
        <textarea v-model="f.auth" rows="2" placeholder="测试账号 / Cookie / Token 说明（仅用于授权测试）"></textarea>
      </div>
      <div class="card">
        <h4>运行配置</h4>
        <label class="fld">测试类型</label>
        <select v-model="f.testType"><option>黑盒</option><option>灰盒</option><option>白盒</option></select>
        <label class="fld">九头编制（加载专项头）</label>
        <div class="spec-item" :class="{on: f.specs.has('A')}" @click="toggle('A')"><b>专项 A · AI(LLM) 目标测试</b><div class="d">提示注入 / 越狱 / 系统提示提取 / Agent 工具滥用（A1-A11），OWASP LLM Top10 + ATLAS</div></div>
        <div class="spec-item" :class="{on: f.specs.has('B1')}" @click="toggle('B1')"><b>专项 B1 · APP 静态+动态</b><div class="d">jadx 反编译审计 + Frida 运行时双链，OWASP MASTG</div></div>
        <div class="spec-item" :class="{on: f.specs.has('B2')}" @click="toggle('B2')"><b>专项 B2 · 小程序全流程</b><div class="d">wxapkg 解包 → 密钥审计 → 前端逻辑 → 接口与云侧（W1-W6）</div></div>
        <label class="fld">模型（设置页可配置多个）</label>
        <select v-model="f.modelId"><option value="">默认模型</option><option v-for="m in models" :key="m.id" :value="m.id">{{ m.label || m.id }}（{{ m.model }}）</option></select>
        <label class="fld">审批策略（自动批准的操作全部落库留痕；FORBIDDEN 破坏性命令始终拒绝）</label>
        <select v-model="f.policy">
          <option value="l1">推荐：仅高危利用/漏洞验证（L2）人工批准，其余自动执行并留痕</option>
          <option value="manual">全部人工批准（L1/L2 等待人工决策）</option>
          <option value="all">全部操作自动批准（含 L2，全留痕）</option>
        </select>
        <label class="fld">执行档（v5.3.1 引擎逐动作强制；违禁动作在任何通道执行前确定性拦截）</label>
        <select v-model="f.profile">
          <option value="production_safe">production_safe（默认·生产/真实业务目标）：禁植入/持久化/隧道/新增账号/上传可执行/批量导出/数据修改删除，只做存在性证明</option>
          <option value="isolated_lab">isolated_lab（须显式声明）：客户专用隔离靶场且可快照回滚，允许完整 PoC 链与受控写操作</option>
        </select>
        <label v-if="f.profile==='isolated_lab'" class="checkline" style="margin-top:8px"><input type="checkbox" v-model="f.labAck" style="width:auto">隔离靶场确认：目标环境为客户专用隔离靶场，具备快照恢复/环境重置能力，收尾以快照恢复为准</label>
        <label class="checkline" style="margin-top:8px"><input type="checkbox" v-model="f.postExploit" style="width:auto">后渗透阶段（S6：权限提升 / 横向移动 / 权限维持演示 / 云容器逃逸 / 存量排查）——<b>默认不执行</b>；不勾选则漏洞利用（S5）完成后直接进入收尾与报告，s6 标记为「范围决策跳过」，后续可在阶段流水线手动重跑</label>
        <label class="checkline"><input type="checkbox" v-model="f.strict" style="width:auto">严格限定范围（只测给定目标，范围外线索只记录不访问）</label>
        <label class="checkline"><input type="checkbox" v-model="f.autostart" style="width:auto">创建后立即启动全流程（九头按序自动推进）</label>
        <label class="checkline auth-line" :class="{ok: f.authorized}"><input type="checkbox" v-model="f.authorized" style="width:auto">授权确认：我确认本项目已获<b>书面授权</b>，并知悉测试风险与合规边界（必勾，否则无法创建）</label>
        <div class="guard-note">
          <b>审批矩阵</b>：只读侦察（L0）自动执行并留痕；写操作（L1）与利用/横向（L2）按「审批策略」走人工批准或自动批准（均留痕可查）；破坏性命令（FORBIDDEN）直接拒绝。运行全程可 <b>一键熔断</b>，所有命令自动留证。
        </div>
        <button class="primary" style="width:100%;margin-top:12px;padding:9px" :disabled="!f.authorized" @click="create">{{ f.authorized ? '创建项目并授权开工' : '请先勾选授权确认' }}</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api.js'
import { session } from '../stores/session.js'
import { projects } from '../stores/projects.js'

const router = useRouter()

// v5.3.7 表单标准化：三个自由文本域统一为「编号小节」结构（可编辑、可一键重置）。
// 锁定短语（只登记移交/注册面只评估不注册/自建账号默认禁止/使用客户提供的测试账号）为合规口径，重写时不得丢失。
const DEFAULT_SCOPE = `【授权目标（in-scope）】
- 域名及子域名：（客户书面授权的全部域名与子域名）
- 端口 / 服务：Web(80/443) 及已确认授权的其他端口
- API 与功能路径：全部路径
【明确排除（out-of-scope）】
- 第三方组件与外部 SaaS 服务
- （按需补充其他排除项）
【通用边界】范围外线索只记录、不继续访问；破坏性/影响业务连续性的操作一律不做。`

const DEFAULT_ROE = `【一、授权与范围】仅测试已确认授权的地址、端口和账号；范围外线索只记录、不继续访问。
【二、行为边界】禁止破坏性写入、持久化、拒绝服务和批量下载，仅做低影响验证；利用/横向/提权类高危操作走审批策略（默认 manual：L1+ 全部人工批准，可在运行配置调整）。
【三、数据与取证】生产数据只做存在性证明(截图/计数/哈希)，不下载不外传；复现结论以 POC 原始请求/响应对登记（record_finding poc 参数）。
【四、身份与账号】注册面只评估不注册（identity.auto_register=deny）：不自动创建任何账号，自建账号默认禁止，身份通过向客户索取测试账号获得（identity-bootstrapping 一a节索取闭环）；使用客户提供的测试账号；会话伪造仅基于已确证伪造漏洞（L5/L6），禁止窃取/重放真实用户活跃会话。
【五、清理与移交】自建数据（账号/文件/载荷/业务数据行）一律只登记移交、不执行删除/还原/清理——《需人工清理清单》四元组移交人工（v5.1.3 政策）；严禁任何波及测试前已存在数据的删除/修改/覆盖。
【六、沟通与应急】出现异常立即停止并上报应急联系人。`

const DEFAULT_SUCCESS = `【测试目的】
- 验证目标系统对外暴露面的实际安全水位：发现可被利用的漏洞、评估真实影响并支撑修复决策。
【成功标准】
- 每条结论有可复现证明（POC 请求/响应原文或等效证据）；
- 产出漏洞清单（等级/置信度/影响/修复建议）；
- 如实披露未覆盖项与限制（盲区不代表安全）。`

// v3.7.0 项目模板（通用型口径：不同目标类型的范围草稿 + 在通用 ROE 上叠加专项条款）
const templates = [
  { name: 'Web 应用（黑盒）', scope: '已确认授权的域名、子域名与端口（Web 服务全部路径）；范围外线索只记录、不继续访问。', roe: '登录/注册类测试使用客户提供的测试账号（注册面只评估不注册，自建账号默认禁止）；验证码走人机协同口径，不自动打码。', tt: '黑盒' },
  { name: 'APP / 小程序', scope: '已确认授权的 APP/小程序包及其后端 API 域名与端口；范围外线索只记录、不继续访问。', roe: '禁止破解分发、禁止拖取真实用户数据（只做存在性证明）；动态测试限授权设备与账号。', tt: '黑盒' },
  { name: '内网 / 主机（灰盒）', scope: '已确认授权的内网网段、主机与端口；凭据以授权发放为准；范围外资产只记录不访问。', roe: '横向移动类动作逐项审批；凭据只登记掩码摘要不落明文；限速探测避免影响业务。', tt: '灰盒' },
  { name: 'AI / LLM 应用', scope: '已确认授权的 LLM 应用入口、API 与其后端服务；提示注入测试仅针对授权实例。', roe: '不产出违法内容的越权滥用；输出中敏感信息只做存在性证明；注入载荷可清理、不持久化。', tt: '黑盒' },
]
function applyTemplate(t) {
  f.scope = t.scope
  f.roe = DEFAULT_ROE + '\n【七、专项条款】\n' + t.roe
  f.testType = t.tt
}
// v5.3.7 一键重置：恢复标准结构（ROE 重置会丢弃已叠加的专项条款——快速模板可重新叠加）
function resetScope() { f.scope = DEFAULT_SCOPE }
function resetRoe() { f.roe = DEFAULT_ROE }
function resetSuccess() { f.success = DEFAULT_SUCCESS }

const f = reactive({ name: '', target: '', scope: '', roe: DEFAULT_ROE, success: '', auth: '', testType: '黑盒', specs: new Set(), modelId: '', policy: 'manual', profile: 'production_safe', labAck: false, postExploit: false, strict: true, autostart: true, authorized: false })
const models = reactive([])

onMounted(async () => {
  try { models.push(...((await api('/api/settings/models')).models || [])) } catch (e) {}
  // v5.3.7 标准化预填：范围/成功标准空态时填入标准结构（ROE 常量初始已带标准结构）
  if (!f.scope) f.scope = DEFAULT_SCOPE
  if (!f.success) f.success = DEFAULT_SUCCESS
})
function toggle(s) { f.specs.has(s) ? f.specs.delete(s) : f.specs.add(s); f.specs = new Set(f.specs) }

async function create() {
  if (!f.name.trim() || !f.target.trim()) return session.showToast('项目名称与目标必填')
  if (!f.authorized) return session.showToast('请先勾选「授权确认」：未获书面授权不得开工')
  if (f.profile === 'isolated_lab' && !f.labAck) return session.showToast('isolated_lab 需勾选「隔离靶场确认」：仅限可快照回滚的专用靶场')
  try {
    const p = await api('/api/projects', 'POST', {
      name: f.name.trim(), target: f.target.trim(), scope: f.scope, roe: f.roe,
      success_criteria: f.success, test_type: f.testType, auth_info: f.auth,
      strict_scope: f.strict, model_id: f.modelId, auto_approve: f.policy,
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
  } catch (e) { session.showToast('创建失败：' + e.message) }
}
</script>

<style scoped>
.fld{display:block;color:var(--muted);font-size:12px;margin:9px 0 4px}
input,select,textarea{width:100%}
.spec-item{border:1px solid var(--border);border-radius:8px;padding:8px 11px;margin:5px 0;cursor:pointer}
.spec-item.on{border-color:var(--accent2);background:rgba(88,166,255,.08)}
.spec-item .d{color:var(--muted);font-size:11px;margin-top:2px}
.checkline{display:flex;gap:7px;align-items:center;font-size:12.5px;margin:6px 0;color:var(--text2)}
.checkline.auth-line{border:1px dashed var(--border);border-radius:8px;padding:8px 10px;margin-top:10px}
.checkline.auth-line.ok{border-color:var(--green);background:rgba(63,185,80,.06)}
.guard-note{background:rgba(210,153,34,.07);border:1px solid rgba(210,153,34,.35);border-radius:8px;padding:9px 12px;font-size:12px;color:var(--text2);margin-top:10px}
</style>
