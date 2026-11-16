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
  const j = await r.json()
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status))
  return j
}

export function wsUrl(projectId) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/ws?project=${projectId}&token=${encodeURIComponent(session.token)}`
}
