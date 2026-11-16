// 文案与映射（与后端枚举对应）
export const STATUS_CN = { pending: '待执行', running: '运行中', done: '已完成', failed: '失败', killed: '已熔断', created: '已创建', paused: '已暂停', skipped: '已跳过', waiting: '等待中', finished: '已完成', cancelled: '已取消' }
export const APPROVAL_CN = { pending: '待审批', approved: '已批准', rejected: '已拒绝', cancelled: '已取消', expired: '已过期（屏障超时）', timeout: '已超时' }
export const EVTYPE_CN = { command: '命令执行', file: '文件产出', stage: '阶段事件', approval: '审批', hexstrike: '远程工具', finding: '漏洞记录' }
export const COV_CN = { vulnerable: '存在漏洞', no_issue_found: '未发现问题', ruled_out: '已排除', waf_blocked: '被WAF拦截', needs_follow_up: '需跟进', skipped: '跳过' }
export const POLICY_CN = { manual: '全部人工批准', l1: '仅L2高危人工批准', all: '全部操作自动批准' }
export const STAGE_NAMES = { s1: '资产与范围', s2: '信息收集/侦察', s3: '威胁建模', s4: '漏洞发现', s5: '漏洞利用', s6: '后渗透/横向', s7: '影响证明/收尾', s8: '报告与建议', specA: '专项A·LLM目标', specB1: '专项B1·APP', specB2: '专项B2·小程序', chat: '对话指挥' }
export const SUBTASK_ICON = { created: '○', running: '◐', waiting: '◔', finished: '●', failed: '✗' }
export const SUBTASK_COLOR = { created: 'var(--muted)', running: 'var(--gold)', waiting: 'var(--purple)', finished: 'var(--green)', failed: 'var(--red)' }

export function fmtSize(n) { return n >= 1048576 ? (n / 1048576).toFixed(1) + 'MB' : n >= 1024 ? (n / 1024).toFixed(1) + 'KB' : (n || 0) + 'B' }
export function fmtTime(t) {
  if (!t) return ''
  // WS 实时事件为纯时间串（HH:MM:SS），new Date() 会得到 Invalid Date（F-07 修复）
  if (/^\d{2}:\d{2}:\d{2}$/.test(t)) return t
  const d = new Date(t)
  return isNaN(d) ? '' : d.toLocaleTimeString('zh-CN', { hour12: false })
}
export function fmtDateTime(t) {
  if (!t) return ''
  if (/^\d{2}:\d{2}:\d{2}$/.test(t)) return t
  const d = new Date(t)
  return isNaN(d) ? '' : d.toLocaleString('zh-CN', { hour12: false })
}

// 轻量 Markdown 渲染（与旧版 md2html 行为一致；F-06 新增 GFM 表格支持）
export function md2html(s) {
  const pres = []
  s = String(s || '').replace(/```([\s\S]*?)```/g, (m, c) => { pres.push(c.replace(/^\n+|\n+$/g, '')); return '\u0000P' + (pres.length - 1) + '\u0000' })
  // GFM 表格：| a | b |\n|---|---|\n| 1 | 2 |（含 :--- 对齐写法）→ 先提取占位，避免被行级规则打散
  const tables = []
  s = s.replace(/(^[^\n]*\|[^\n]*\n)[ \t]*\|?[ \t]*:?-{2,}:?[ \t]*(\|[ \t]*:?-{2,}:?[ \t]*)*\|?[ \t]*\n(?:((?:[^\n]*\|[^\n]*(?:\n|$))+))/gm, (m, head, _sep, body) => {
    const rows = (head + body).split('\n').filter(r => r.trim())
    if (rows.length < 1) return m
    const cells = r => r.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map(c => c.trim())
    const th = cells(rows[0])
    if (!th.some(c => c)) return m
    let h = '<table class="md"><thead><tr>' + th.map(c => `<th>${c}</th>`).join('') + '</tr></thead><tbody>'
    for (const r of rows.slice(1)) {
      const td = cells(r)
      h += '<tr>' + th.map((_, i) => `<td>${td[i] || ''}</td>`).join('') + '</tr>'
    }
    h += '</tbody></table>'
    tables.push(h)
    return '\u0000T' + (tables.length - 1) + '\u0000'
  })
  s = escapeHtml(s)
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>')
  s = s.replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>')
  s = s.replace(/^#{1,3} (.*)$/gm, '<b>$1</b>')
  s = s.replace(/^- (.*)$/gm, '• $1')
  s = s.replace(/\n/g, '<br>')
  s = s.replace(/\u0000T(\d+)\u0000/g, (m, i) => tables[+i] || '')
  s = s.replace(/\u0000P(\d+)\u0000/g, (m, i) => `<pre class="code">${escapeHtml(pres[+i])}</pre>`)
  return s
}
export function escapeHtml(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') }
