import { createRouter, createWebHashHistory } from 'vue-router'
import { session } from './stores/session.js'

const routes = [
  { path: '/login', component: () => import('./pages/LoginPage.vue') },
  { path: '/', component: () => import('./pages/DashboardPage.vue') },
  { path: '/workbench', component: () => import('./components/workbench/Workbench.vue') },
  { path: '/create', component: () => import('./pages/CreateProjectPage.vue') },
  { path: '/findings', component: () => import('./pages/FindingsPage.vue') },
  { path: '/assets', component: () => import('./pages/AssetsPage.vue') },
  { path: '/devices', component: () => import('./pages/DevicesPage.vue') },
  { path: '/timeline', component: () => import('./pages/TimelinePage.vue') },
  { path: '/skills', component: () => import('./pages/SkillsPage.vue') },
  { path: '/heads', component: () => import('./pages/HeadsPage.vue') },
  { path: '/report', component: () => import('./pages/ReportPage.vue') },
  { path: '/settings', component: () => import('./pages/SettingsPage.vue') },
  { path: '/changelog', component: () => import('./pages/ChangelogPage.vue') },
  { path: '/:pathMatch(.*)*', redirect: '/' }
]

export const router = createRouter({ history: createWebHashHistory(), routes })

router.beforeEach(to => {
  if (!session.token && to.path !== '/login') return '/login'
  if (session.token && to.path === '/login') return '/'
  if (session.token && !['/login', '/settings', '/changelog', '/skills', '/heads', '/create', '/'].includes(to.path) && !projects_ready(to)) return '/'
  return true
})
function projects_ready(to) { return true } // 项目类页面在未选项目时自行显示空态
