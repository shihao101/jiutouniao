<template>
  <div class="login-wrap">
    <div class="login-card">
      <h2 style="text-align:center;margin-bottom:4px">九头鸟（鬼車）</h2>
      <p style="text-align:center;color:var(--muted);font-size:12px;margin-bottom:16px">渗透测试智能体 · 仅限书面授权使用</p>
      <label class="fld">账号</label>
      <input v-model="user" placeholder="请输入账号" autocomplete="username" @keyup.enter="login">
      <label class="fld">密码</label>
      <input v-model="pass" type="password" @keyup.enter="login">
      <label class="fld">验证码</label>
      <div style="display:flex;gap:8px;align-items:center">
        <input v-model="captcha" style="flex:1" @keyup.enter="login">
        <img v-if="captchaSvg" :src="captchaSvg" style="height:36px;border-radius:6px;cursor:pointer" title="点击刷新" @click="loadCaptcha">
      </div>
      <p v-if="err" style="color:var(--red);font-size:12px;margin-top:8px">{{ err }}</p>
      <button class="primary" style="width:100%;margin-top:14px;padding:9px" @click="login">登 录</button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { session } from '../stores/session.js'
import { projects } from '../stores/projects.js'

const router = useRouter()
const user = ref(''), pass = ref(''), captcha = ref(''), err = ref('')
const captchaSvg = ref('')
let captchaId = ''

async function loadCaptcha() {
  const j = await fetch('/api/captcha').then(r => r.json())
  captchaId = j.captcha_id
  captchaSvg.value = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(j.svg)))
  captcha.value = ''
}
async function login() {
  err.value = ''
  try {
    const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user.value, password: pass.value, captcha_id: captchaId, captcha_code: captcha.value }) })
    const j = await r.json()
    if (!r.ok) { err.value = j.error || '登录失败'; await loadCaptcha(); return }
    session.setAuth(j.token, j.user)
    await projects.loadList()
    const last = localStorage.getItem('jt_last_project')
    if (last && projects.list.some(p => p.id === last)) { await projects.select(last); router.push('/workbench') }
    else router.push('/')
  } catch (e) { err.value = e.message }
}
onMounted(loadCaptcha)
</script>

<style scoped>
.login-wrap{height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg)}
.login-card{width:360px;background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:26px}
.fld{display:block;color:var(--muted);font-size:12px;margin:10px 0 4px}
input{width:100%}
</style>
