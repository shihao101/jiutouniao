// 统一 API 封装：Bearer 令牌、401 自动跳登录、错误抛出
import { session } from './stores/session.js'

export async function api(path, method = 'GET', body) {
  const opt = { method, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + session.token } }
  if (body) opt.body = JSON.stringify(body)
  const r = await fetch(path, opt)
  if (r.status === 401) {
    session.logout()
    throw new Error('未登录或会话过期')
  }
  // v5.7.4：非 JSON 响应守卫——服务端老版本对新增路由回纯文本 404（「404 page not found」）、
  // 网关/代理回 HTML 错误页时，裸 r.json() 会把 SyntaxError 原文（Unexpected non-whitespace
  // character after JSON at position 4）直接抛给用户，看不出根因（实证：v5.4.0 新增路由打到
  // 半升级部署的老服务端）。改为先 text 后 parse，失败抛含状态码与响应片段的友好提示。
  const text = await r.text()
  let j
  try {
    j = JSON.parse(text)
  } catch (e) {
    const snippet = text.slice(0, 80).replace(/\s+/g, ' ').trim() || '(空响应)'
    throw new Error(`服务端返回了非 JSON 响应（HTTP ${r.status}）——多为前端与服务端版本不一致（请升级服务端）或网关拦截；响应片段: ${snippet}`)
  }
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status))
  return j
}

export function wsUrl(projectId) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/ws?project=${projectId}&token=${encodeURIComponent(session.token)}`
}
