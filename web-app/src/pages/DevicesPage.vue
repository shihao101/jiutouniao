<template>
  <div class="page">
    <!-- 卡片一：实时连接状态（真实执行 adb devices -l / frida-ls-devices） -->
    <div class="card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <h3 style="margin:0">实时连接状态</h3>
        <span class="chip" :style="{color: onlineCount > 0 ? 'var(--green)' : 'var(--muted)'}">
          {{ onlineCount > 0 ? `● ${onlineCount} 台在线` : '○ 无在线设备' }}
        </span>
        <span class="chip" :style="{color: d.adb_installed ? 'var(--green)' : 'var(--gold)'}">adb {{ d.adb_installed ? '已装' : '未装（动态阶段由智能体 install_tool 安装）' }}</span>
        <span class="chip" :style="{color: d.frida_installed ? 'var(--green)' : 'var(--gold)'}">frida {{ d.frida_installed ? '已装' : '未装' }}</span>
        <span style="flex:1"></span>
        <span class="chip" style="color:var(--muted)">采样 {{ checkedAt }}</span>
        <button class="small" @click="load" :disabled="loading">{{ loading ? '检测中…' : '立即检测' }}</button>
      </div>
      <table v-if="(d.adb_devices || []).length" style="width:100%;font-size:12.5px;border-collapse:collapse">
        <tr style="color:var(--muted);text-align:left">
          <th style="padding:4px 8px">序列号 / 地址</th><th>通道</th><th>状态</th><th>型号</th><th>transport_id</th>
        </tr>
        <tr v-for="dev in d.adb_devices" :key="dev.serial" style="border-top:1px solid var(--border)">
          <td style="padding:5px 8px;font-family:monospace">{{ dev.serial }}</td>
          <td>{{ dev.transport }}</td>
          <td><span class="badge" :class="dev.state === 'device' ? 'running' : ''" :style="dev.state==='device' ? 'color:var(--green)' : 'color:var(--gold)'">{{ STATE_CN[dev.state] || dev.state }}</span></td>
          <td>{{ dev.model || '—' }}</td>
          <td>{{ dev.transport_id || '—' }}</td>
        </tr>
      </table>
      <p v-else style="color:var(--muted);font-size:12.5px;margin:6px 0">
        当前无设备接入。设备侧开启「无线调试」后执行下方连接命令，点击「立即检测」即可看到真实状态（device=在线 / unauthorized=待确认指纹 / offline=需重连）。
      </p>
      <pre v-if="d.adb_raw" style="margin:10px 0 4px;font-size:11.5px;background:var(--bg3);padding:8px;border-radius:6px;overflow:auto">adb devices -l 原始输出：
{{ d.adb_raw }}</pre>
      <pre v-if="d.frida_devices" style="margin:4px 0;font-size:11.5px;background:var(--bg3);padding:8px;border-radius:6px;overflow:auto">frida-ls-devices（注入通道可见性）：
{{ d.frida_devices }}</pre>
      <p v-if="d.adb_error || d.frida_error" style="color:var(--gold);font-size:12px;margin:4px 0">检测异常：{{ d.adb_error || d.frida_error }}</p>
    </div>

    <!-- 卡片二：七种连接方式（v5.0 启用按钮：点击后台执行对应命令，结果实时回显） -->
    <div class="card">
      <h3 style="margin:0 0 4px">七种连接方式（启用按钮 → 后台执行，容器真实视角）</h3>
      <p style="margin:2px 0 10px;color:var(--text2);font-size:12px">确定性动作（配对/连接/探测/校验）由本页直接后台执行并留痕；多步编排（frida-server 推送/抓包链）由智能体在项目中按 D1-D6 执行。长驻进程一律 run_async。</p>
      <div v-for="s in scenes" :key="s.n" style="border-top:1px solid var(--border);padding:10px 4px">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span style="color:var(--muted);width:22px">{{ s.n }}</span>
          <b>{{ s.name }}</b>
          <span class="chip" :style="{color: s.enabled ? 'var(--green)' : 'var(--gold)'}">{{ s.enabled ? '可启用' : '受限' }}</span>
          <span style="flex:1"></span>
          <!-- 场景1：配对表单 -->
          <template v-if="s.n === 1">
            <input v-model="f1.ip" placeholder="设备IP" style="width:120px">
            <input v-model="f1.port" placeholder="配对端口" style="width:90px">
            <input v-model="f1.code" placeholder="6位配对码" style="width:90px" type="password">
            <button class="small primary" :disabled="busy.n===1" @click="act('wireless_pair', {ip: f1.ip, port: f1.port, code: f1.code}, 1)">{{ busy.n===1 ? '执行中…' : '启用（配对）' }}</button>
            <input v-model="f1.cport" placeholder="连接端口" style="width:90px">
            <button class="small" :disabled="busy.n===1" @click="act('wireless_connect', {ip: f1.ip, port: f1.cport}, 1)">连接</button>
          </template>
          <!-- 场景2：环境检测 + 连接 -->
          <template v-else-if="s.n === 2">
            <button class="small" :disabled="busy.n===2" @click="act('tcpip_env_check', {}, 2)">{{ busy.n===2 ? '检测中…' : '环境检测（有无 USB 序列号）' }}</button>
            <input v-model="f2.ip" placeholder="设备IP" style="width:120px">
            <input v-model="f2.port" placeholder="5555" style="width:70px">
            <button class="small primary" :disabled="busy.n===2 || !f2.ip" @click="act('wireless_connect', {ip: f2.ip, port: f2.port}, 2)">启用（连接）</button>
          </template>
          <!-- 场景3：热点反连探测 -->
          <template v-else-if="s.n === 3">
            <button class="small primary" :disabled="busy.n===3" @click="act('hotspot_probe', {}, 3)">{{ busy.n===3 ? '探测中…' : '启用（网段探测）' }}</button>
            <input v-model="f3.ip" placeholder="设备IP（探测后填）" style="width:140px">
            <button class="small" :disabled="busy.n===3 || !f3.ip" @click="act('wireless_connect', {ip: f3.ip, port: '5555'}, 3)">连接</button>
          </template>
          <!-- 场景4：共享宿主 adb server -->
          <template v-else-if="s.n === 4">
            <input v-model="f4.host" placeholder="宿主IP" style="width:130px">
            <input v-model="f4.port" placeholder="5037" style="width:70px">
            <button class="small primary" :disabled="busy.n===4 || !f4.host" @click="act('shared_adb_test', {host: f4.host, port: f4.port}, 4)">{{ busy.n===4 ? '校验中…' : '启用（校验共享 adb）' }}</button>
          </template>
          <!-- 场景5：禁用态 -->
          <template v-else-if="s.n === 5">
            <button class="small" disabled style="opacity:.5">禁用（privileged 权限面冲突）</button>
          </template>
          <!-- 场景6：隧道/直连 -->
          <template v-else-if="s.n === 6">
            <input v-model="f6.host" placeholder="隧道/设备IP" style="width:130px">
            <input v-model="f6.port" placeholder="5555" style="width:70px">
            <button class="small primary" :disabled="busy.n===6 || !f6.host" @click="act('tunnel_check', {host: f6.host, port: f6.port}, 6)">{{ busy.n===6 ? '检测中…' : '启用（隧道校验）' }}</button>
            <button class="small" :disabled="busy.n===6 || !f6.host" @click="act('frida_direct_test', {ip: f6.host, port: 27042}, 6)">frida -H 直连测试</button>
          </template>
          <!-- 场景7：云真机 -->
          <template v-else>
            <input v-model="f7.url" placeholder="平台地址 http://…" style="width:180px">
            <button class="small primary" :disabled="busy.n===7 || !f7.url" @click="act('cloud_platform_check', {url: f7.url}, 7)">{{ busy.n===7 ? '检测中…' : '启用（平台校验）' }}</button>
          </template>
        </div>
        <div style="font-size:11.5px;color:var(--text2);margin-top:4px">{{ s.note }}</div>
        <div v-if="results[s.n]" class="mono" :style="{fontSize:'11.5px', marginTop:'6px', color: results[s.n].ok ? 'var(--green)' : 'var(--gold)', whiteSpace:'pre-wrap'}">{{ results[s.n].ok ? '✅' : '❌' }} {{ results[s.n].output || results[s.n].error }}</div>
        <pre v-if="s.cmd && !results[s.n]" style="margin:4px 0 0;font-size:11px;white-space:pre-wrap;color:var(--muted)">{{ s.cmd }}</pre>
      </div>
    </div>

    <!-- 卡片三：智能体如何调用（specB1 动态链接入顺序） -->
    <div class="card">
      <h3 style="margin:0 0 8px">智能体如何调用设备（specB1 动态链 D1-D6 接入顺序）</h3>
      <ol style="margin:4px 0 10px 20px;font-size:12.5px;line-height:2">
        <li>建项时专项勾选 <b>B1</b>，流水线在 s4 后自动进入动态链；审批策略建议 <b>l1</b>（D1/D4 产生大量 L2 工单）。</li>
        <li>工具缺失由智能体 <code>install_tool</code> 自动补装（apt→pip→git 策略链，走 TOOL_PROXY，L1 留痕）：adb、frida-tools。</li>
        <li>按上表接好设备后，智能体执行 <code>adb devices</code> 确认 device 态 → <code>adb shell getprop ro.product.cpu.abi</code> 查架构 → push 对应版本 frida-server 并后台拉起。</li>
        <li>frida-server / mitmdump（容器 8080 已映射宿主，设备 WiFi 代理指向 <b>宿主IP:8080</b>）属长驻进程，智能体走 <code>run_async/poll_async</code>，流水线结束强制清理。</li>
        <li>抓包需要信任 CA：root 设备用 Magisk 移入系统证书区；Android 7+ 用户证书默认不被 APP 信任。</li>
        <li>本页状态为<b>引擎所在容器的真实视角</b>：这里看不到的设备，智能体同样连不上（容器无 USB 直通，USB 线设备需走「场景 4 共享宿主 adb server」）。</li>
      </ol>
      <p style="margin:0;color:var(--text2);font-size:12px">纪律：仅测试设备与测试账号；绕过/爆破限频；支付写操作先审批；测完 <code>adb usb</code> 切回、关闭 5555、卸载测试 APP 与 CA（S7 清理）。</p>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { api } from '../api.js'

const d = ref({})
const loading = ref(false)
let timer = null

const STATE_CN = { device: '在线', offline: '离线', unauthorized: '未授权', recovery: 'recovery', sideload: 'sideload', bootload: 'bootloader' }
const checkedAt = computed(() => (d.value.checked_at || '').slice(11, 19) || '—')
const onlineCount = computed(() => (d.value.adb_devices || []).filter(x => x.state === 'device').length)

// v5.0 启用按钮：动作执行 + 结果回显（POST /api/devices/action）
const f1 = reactive({ ip: '', port: '', code: '', cport: '' })
const f2 = reactive({ ip: '', port: '5555' })
const f3 = reactive({ ip: '' })
const f4 = reactive({ host: '', port: '5037' })
const f6 = reactive({ host: '', port: '5555' })
const f7 = reactive({ url: '' })
const busy = reactive({ n: 0 })
const results = reactive({})
async function act(action, params, n) {
  busy.n = n
  try {
    const j = await api('/api/devices/action', 'POST', { action, params })
    results[n] = j
    if (j.ok) setTimeout(load, 800)   // 成功后 0.8s 刷新实时状态
  } catch (e) { results[n] = { ok: false, error: e.message } }
  finally { busy.n = 0 }
}

const scenes = [
  { n: 1, name: '无线调试配对（Android 11+，首选）', cmd: 'adb pair <设备IP>:<配对端口>   # 设备上显示 6 位配对码\nadb connect <设备IP>:<连接端口>', note: '免 root 免 USB，TLS 配对安全；连接端口动态变化，重连后更新' },
  { n: 2, name: '经典 tcpip 5555（通用）', cmd: 'adb tcpip 5555                  # 需先插一次 USB（或 root）\nadb connect <设备IP>:5555', note: '老设备可用；5555 对全网段开放，测完务必 adb usb 切回' },
  { n: 3, enabled: true, name: '设备热点反连', cmd: '设备开热点 → 宿主机连热点\nadb connect <热点网段设备IP>:5555', note: '绕办公网 AP/客户端隔离；容器经宿主 NAT 出站可达' },
  { n: 4, enabled: true, name: 'USB 线 + 共享宿主 adb server', cmd: '# 宿主：以监听模式启动 adb server\nadb -a nodaemon server   # 5037\n# 容器：export ADB_SERVER_SOCKET=tcp:<宿主IP>:5037', note: '手头只有 USB 线时的标准解法：宿主管 USB 驱动，容器远程调用' },
  { n: 5, enabled: false, name: 'USB 直通容器', cmd: 'compose 加 devices: [/dev/bus/usb]\n# 或宿主 usbip export → 容器 attach', note: '会扩大容器权限面（privileged 级），与最小权限方针冲突，不推荐' },
  { n: 6, name: '跨网段/异地真机（隧道）', cmd: 'ssh -R 5555:localhost:5555 <宿主>\nadb connect 127.0.0.1:5555\n# 免 adb 备用：设备 frida-server -l 0.0.0.0:27042 → frida -H <IP>:27042', note: '异地设备拉回；frida -H 直连不依赖 adb' },
  { n: 7, enabled: true, name: '云真机/设备农场', cmd: '自建 Sonic / atxserver2 / STF\n# agent 集中插 USB，对外暴露 adb 接入点', note: 'B1 动态链多设备并行、多机型覆盖时用' }
]

async function load() {
  loading.value = true
  try { d.value = await api('/api/devices') } catch (e) { d.value = { adb_error: e.message } } finally { loading.value = false }
}
onMounted(() => { load(); timer = setInterval(load, 10000) })
onUnmounted(() => clearInterval(timer))
</script>
