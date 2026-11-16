import { reactive } from 'vue'
import { api } from '../api.js'
import { session } from './session.js'
import { stream } from './stream.js'

// 项目域状态：列表 / 当前项目详情 / 阶段 / 子任务 / 审批 / 提问 / 覆盖度
export const projects = reactive({
  list: [],
  currentId: localStorage.getItem('jt_last_project') || '',
  detail: null,        // GET /api/projects/{id} 全量
  coverage: [],
  recon: null,
  files: [],
  filesTotal: 0,       // 交付物过滤后总数（X-Total-Count，截断前）
  skills: null,
  heads: null,
  facts: [], loot: [], subagents: [], // v3.7.0 黑板三件套
  loading: false,

  get current() { return this.detail?.project || null },
  get isRunning() { return ['running'].includes(this.current?.status) },
  get pendingApprovals() { return (this.detail?.approvals || []).filter(a => a.status === 'pending') },
  get pendingAsks() { return (this.detail?.asks || []).filter(a => a.status === 'pending') },
  get stageEntries() { return Object.entries(this.current?.stage_states || {}) },
  get runningStage() { return this.stageEntries.find(([, s]) => s.status === 'running')?.[0] || '' },

  async loadList() {
    this.list = (await api('/api/projects')) || []
    return this.list
  },
  async select(id) {
    this.currentId = id || ''
    if (id) localStorage.setItem('jt_last_project', id); else localStorage.removeItem('jt_last_project')
    this.detail = null; this.coverage = []; this.recon = null; this.files = []; this.filesTotal = 0
    stream.$reset()
    if (!id) return
    await Promise.all([this.refresh(), this.loadCoverage(), this.loadFiles(), this.loadBoard(id)])
    const { connectWS } = await import('../composables/useWS.js')
    connectWS(id)
  },
  // v3.7.0 黑板三件套（事实/战利品/子代理）：项目选定即加载；失败静默（Tab 内空态兜底）
  async loadBoard(id) {
    id = id || this.currentId
    if (!id) return
    const h = { Authorization: 'Bearer ' + session.token }
    const safe = (url) => fetch(url, { headers: h }).then(r => r.ok ? r.json() : []).catch(() => [])
    const [f, l, sa] = await Promise.all([
      safe(`/api/projects/${id}/facts`),
      safe(`/api/projects/${id}/loot`),
      safe(`/api/projects/${id}/subagents`),
    ])
    if (id === this.currentId) { this.facts = f || []; this.loot = l || []; this.subagents = sa || [] }
  },
  async refresh() {
    if (!this.currentId) return
    try {
      this.detail = await api('/api/projects/' + this.currentId)
    } catch (e) { /* 忽略轮询错误 */ }
  },
  async loadCoverage() {
    if (!this.currentId) return
    try { this.coverage = (await api(`/api/projects/${this.currentId}/coverage`)) || [] } catch (e) { this.coverage = [] }
    // v3.9.5 对账视图随覆盖度同步刷新（自述面归宿 + 清单外发现计数）
    try { this.recon = await api(`/api/projects/${this.currentId}/reconciliation`) } catch (e) { this.recon = null }
  },
  async loadFiles() {
    if (!this.currentId) return
    // 交付物白名单分两窗取数，避免证据链量大时把结项产出/阶段交付物挤出 80 窗口：
    // ① 根目录散落（结项三件套/上传目标包）+ 阶段交付物 + PoC + 目标包目录；② 证据链（独立窗口）
    // 反编译/解包噪声（apktool_out/jadx_out/assets_www/unpacked 等）不进入交付物语义
    const req = dirs => fetch(`/api/projects/${this.currentId}/files?dirs=${dirs}`, {
      headers: { Authorization: 'Bearer ' + session.token }
    })
    const pick = async pr => {
      const r = await pr
      if (r.status === 401) { session.logout(); throw new Error('未登录或会话过期') }
      return { total: parseInt(r.headers.get('X-Total-Count') || '0', 10) || 0, items: r.ok ? ((await r.json()) || []) : [] }
    }
    try {
      const [core, ev] = await Promise.all([pick(req('.,deliverables,poc,packages')), pick(req('evidence'))])
      this.filesTotal = core.total + ev.total
      this.files = [...core.items, ...ev.items]
    } catch (e) { this.files = []; this.filesTotal = 0 }
  },
  async loadSkills() { if (!this.skills) this.skills = (await api('/api/skills')) || [] },
  async loadHeads() { if (!this.heads) this.heads = (await api('/api/heads')) || [] },

  cost() {
    const u = this.detail?.usage || {}
    const pin = this.detail?.price_in || 0, pout = this.detail?.price_out || 0
    return ((u.in_tokens || 0) / 1e6 * pin + (u.out_tokens || 0) / 1e6 * pout).toFixed(4)
  }
})
