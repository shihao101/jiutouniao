// P3 i18n 脚手架：vue-i18n 实例（中文默认，en 预留；localStorage jt_locale 可切换）
import { createI18n } from 'vue-i18n'
import zh from './zh.js'
import en from './en.js'

export const i18n = createI18n({
  legacy: false,
  locale: localStorage.getItem('jt_locale') || 'zh',
  fallbackLocale: 'zh',
  messages: { zh, en },
})
