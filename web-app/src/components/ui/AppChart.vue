<template>
  <div ref="el" class="app-chart" :style="{ height }" role="img" :aria-label="ariaLabel || '图表'"></div>
</template>

<script setup>
// P1 基础组件：ECharts 按需封装（双主题自适应 / ResizeObserver 自缩放 / 卸载回收）
import { onMounted, onBeforeUnmount, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { PieChart, BarChart, ScatterChart } from 'echarts/charts'
import { TooltipComponent, LegendComponent, GridComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { session } from '../../stores/session.js'

echarts.use([PieChart, BarChart, ScatterChart, TooltipComponent, LegendComponent, GridComponent, CanvasRenderer])

const props = defineProps({
  option: { type: Object, required: true },
  height: { type: String, default: '240px' },
  ariaLabel: { type: String, default: '' },
})
const el = ref(null)
let chart = null, ro = null

function themeColors() {
  const cs = getComputedStyle(document.documentElement)
  return {
    text: cs.getPropertyValue('--text2').trim() || '#9aa4b2',
    muted: cs.getPropertyValue('--muted').trim() || '#6e7681',
    bg: cs.getPropertyValue('--bg2').trim() || '#161b22',
  }
}
function render() {
  if (!el.value || !props.option) return
  if (!chart) chart = echarts.init(el.value)
  const t = themeColors()
  const base = {
    textStyle: { color: t.text, fontFamily: 'inherit' },
    tooltip: { backgroundColor: t.bg, borderColor: t.muted, textStyle: { color: t.text, fontSize: 12 } },
  }
  chart.setOption({ ...base, ...props.option }, true)
}
function dispose() { if (chart) { chart.dispose(); chart = null } }
onMounted(() => {
  render()
  ro = new ResizeObserver(() => chart && chart.resize())
  ro.observe(el.value)
})
watch(() => props.option, () => render(), { deep: true })
watch(() => session.theme, () => { dispose(); render() })
onBeforeUnmount(() => { ro && ro.disconnect(); dispose() })
</script>

<style scoped>
.app-chart{width:100%}
</style>
