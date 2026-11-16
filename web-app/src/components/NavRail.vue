<template>
  <nav class="rail" aria-label="主导航">
    <div v-for="item in items" :key="item.path" class="rail-item" :class="{active: $route.path === item.path}"
         :title="item.label" role="link" :aria-label="item.label" tabindex="0"
         @click="$router.push(item.path)" @keydown.enter="$router.push(item.path)">
      <component :is="item.icon" :size="18" stroke-width="1.8" class="ic" aria-hidden="true" />
      <span class="lb">{{ item.label }}</span>
    </div>
  </nav>
</template>

<script setup>
// P0 图标化：lucide 真图标替换文本符号（tree-shakable，仅打包引用项）
import { LayoutDashboard, TerminalSquare, PlusCircle, Bug, Boxes, MonitorSmartphone, Clock3, Grid3x3, ScrollText, FileText, Settings2, History } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const items = [
  { path: '/', icon: LayoutDashboard, label: t('nav.dashboard') },
  { path: '/workbench', icon: TerminalSquare, label: t('nav.workbench') },
  { path: '/create', icon: PlusCircle, label: t('nav.create') },
  { path: '/findings', icon: Bug, label: t('nav.findings') },
  { path: '/assets', icon: Boxes, label: t('nav.assets') },
  { path: '/devices', icon: MonitorSmartphone, label: t('nav.devices') },
  { path: '/timeline', icon: Clock3, label: t('nav.timeline') },
  { path: '/skills', icon: Grid3x3, label: t('nav.skills') },
  { path: '/heads', icon: ScrollText, label: t('nav.heads') },
  { path: '/report', icon: FileText, label: t('nav.report') },
  { path: '/settings', icon: Settings2, label: t('nav.settings') },
  { path: '/changelog', icon: History, label: t('nav.changelog') }
]
</script>

<style scoped>
.rail{width:76px;border-right:1px solid var(--border);background:var(--bg2);display:flex;flex-direction:column;padding:8px 6px;gap:2px;overflow-y:auto}
.rail-item{display:flex;flex-direction:column;align-items:center;gap:4px;padding:9px 2px;border-radius:var(--r-sm);cursor:pointer;color:var(--text2);font-size:11px;transition:background var(--tr-fast),color var(--tr-fast)}
.rail-item:hover{background:var(--bg3);color:var(--text)}
.rail-item:focus-visible{outline:2px solid var(--accent2);outline-offset:-2px}
.rail-item.active{background:var(--grad-nav);color:var(--accent2);box-shadow:inset 0 0 0 1px rgba(88,166,255,.28)}
.rail-item .ic{line-height:1}
.rail-item.active .ic{filter:drop-shadow(0 0 6px rgba(88,166,255,.45))}
</style>
