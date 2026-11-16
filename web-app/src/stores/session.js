import { reactive } from 'vue'

// 会话与全局轻量状态
export const session = reactive({
  token: sessionStorage.getItem('jt_session') || '',
  user: sessionStorage.getItem('jt_user') || '',
  pubinfo: null,          // /api/public/info
  theme: localStorage.getItem('jt_theme') || 'dark',
  toast: { show: false, text: '' },
  modal: { show: false, title: '', body: '' },

  setAuth(token, user) {
    this.token = token; this.user = user
    sessionStorage.setItem('jt_session', token); sessionStorage.setItem('jt_user', user)
  },
  logout() {
    this.token = ''; this.user = ''
    sessionStorage.clear()
  },
  showToast(text) {
    this.toast.text = text; this.toast.show = true
    clearTimeout(this._tt)
    this._tt = setTimeout(() => { this.toast.show = false }, 2600)
  },
  showModal(title, body) { this.modal.title = title; this.modal.body = body; this.modal.show = true },
  toggleTheme() {
    this.theme = this.theme === 'dark' ? 'light' : 'dark'
    localStorage.setItem('jt_theme', this.theme)
    document.documentElement.dataset.theme = this.theme
  }
})
document.documentElement.dataset.theme = session.theme
