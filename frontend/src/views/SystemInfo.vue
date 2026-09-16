<script setup lang="ts">
import { SITE_NAME, STUDIO_NAME } from '@/config/site'
import { ref, onMounted } from 'vue'
import {
  Monitor, Cpu, HardDrive, Wifi, RefreshCw, Globe, Gauge,
  MemoryStick, Touchpad, Smartphone, Languages
} from 'lucide-vue-next'
import AnimatedCloud from '@/components/AnimatedCloud.vue'

interface ScreenItem {
  id: number
  label: string
  isPrimary: boolean
  logicalWidth: number
  logicalHeight: number
  physicalWidth: number
  physicalHeight: number
  dpr: number
  colorDepth: number
  orientation: string
  position: string
  refreshRate: string
}

const screens = ref<ScreenItem[]>([])
const isLoading = ref(true)

const browserInfo = ref({
  browser: '未知',
  system: '未知',
  architecture: '未知',
  bitness: '未知',
  fullVersion: '未知',
  mobile: '未知',
  language: '未知',
  timezone: '未知',
  online: '未知'
})

const hardwareInfo = ref({
  cpuCores: '未知',
  memory: '未知',
  gpuRenderer: '未知',
  gpuVendor: '未知'
})

const networkInfo = ref({
  effectiveType: '未知',
  connectionType: '未知',
  downlink: '未知',
  rtt: '未知',
  saveData: '未知'
})

const viewportInfo = ref({
  width: 0,
  height: 0,
  dpr: 1,
  maxTouchPoints: '未知'
})

function orientationLabel(orientation: any): string {
  const type = orientation?.type || ''
  if (type.includes('landscape')) return type.includes('secondary') ? '横向（翻转）' : '横向'
  if (type.includes('portrait')) return type.includes('secondary') ? '纵向（翻转）' : '纵向'
  const angle = orientation?.angle
  if (angle === 90 || angle === 270) return '横向'
  if (angle === 180) return '纵向（翻转）'
  return '纵向'
}

function parseUaBrowser(ua: string): string {
  if (/edg/i.test(ua)) return 'Microsoft Edge'
  if (/opr\/|opera/i.test(ua)) return 'Opera'
  if (/chrome|crios/i.test(ua)) return 'Chrome'
  if (/firefox|fxios/i.test(ua)) return 'Firefox'
  if (/safari/i.test(ua)) return 'Safari'
  return ua || '未知'
}

function parseUaSystem(ua: string): string {
  if (/windows nt 10/i.test(ua)) return 'Windows 10/11'
  if (/windows nt 6\.3/i.test(ua)) return 'Windows 8.1'
  if (/windows/i.test(ua)) return 'Windows'
  if (/android/i.test(ua)) return 'Android'
  if (/iphone|ipad|ipod/i.test(ua)) return 'iOS / iPadOS'
  if (/mac os x/i.test(ua)) return 'macOS'
  if (/linux/i.test(ua)) return 'Linux'
  return '未知'
}

async function collectBrowserInfo() {
  const uaData = (navigator as any).userAgentData
  if (uaData && Array.isArray(uaData.brands) && uaData.brands.length) {
    browserInfo.value.browser = uaData.brands.map((b: any) => b.brand).filter(Boolean).join(' / ')
    browserInfo.value.system = uaData.platform || '未知'
    browserInfo.value.mobile = uaData.mobile ? '是' : '否'
    try {
      const he: any = await Promise.race([
        uaData.getHighEntropyValues(['architecture', 'bitness', 'fullVersionList', 'uaFullVersion']),
        new Promise((resolve) => setTimeout(() => resolve({}), 800))
      ])
      browserInfo.value.architecture = he?.architecture || '未知'
      browserInfo.value.bitness = he?.bitness || '未知'
      const list = he?.fullVersionList
      const main = Array.isArray(list) ? list.find((v: any) => v && v.brand && v.version) : null
      browserInfo.value.fullVersion = main ? `${main.brand} ${main.version}` : (he?.uaFullVersion || '未知')
    } catch {
      /* 浏览器未授权高熵信息时保留未知 */
    }
  } else {
    const ua = navigator.userAgent || ''
    browserInfo.value.browser = parseUaBrowser(ua)
    browserInfo.value.system = parseUaSystem(ua)
    browserInfo.value.mobile = /mobi/i.test(ua) ? '是' : '否'
  }
  browserInfo.value.language = navigator.language || '未知'
  browserInfo.value.online = navigator.onLine ? '在线' : '离线'
  try {
    browserInfo.value.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '未知'
  } catch {
    browserInfo.value.timezone = '未知'
  }
}

function collectGpuInfo() {
  try {
    const canvas = document.createElement('canvas')
    const gl: any = canvas.getContext('webgl') || canvas.getContext('experimental-webgl')
    if (!gl) return
    const ext = gl.getExtension('WEBGL_debug_renderer_info')
    if (!ext) return
    hardwareInfo.value.gpuRenderer = String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '未知')
    hardwareInfo.value.gpuVendor = String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '未知')
  } catch {
    /* WebGL 不可用时保留未知 */
  }
}

function collectHardwareInfo() {
  hardwareInfo.value.cpuCores = navigator.hardwareConcurrency ? `${navigator.hardwareConcurrency} 核` : '未知'
  const memory = (navigator as any).deviceMemory
  hardwareInfo.value.memory = typeof memory === 'number' ? `${memory} GB` : '未知'
  collectGpuInfo()
}

function collectNetworkInfo() {
  const conn = (navigator as any).connection || (navigator as any).mozConnection || (navigator as any).webkitConnection
  if (!conn) return
  networkInfo.value.effectiveType = conn.effectiveType || '未知'
  networkInfo.value.connectionType = conn.type || '未知'
  networkInfo.value.downlink = typeof conn.downlink === 'number' ? `${conn.downlink} Mbps` : '未知'
  networkInfo.value.rtt = typeof conn.rtt === 'number' ? `${conn.rtt} ms` : '未知'
  networkInfo.value.saveData = typeof conn.saveData === 'boolean' ? (conn.saveData ? '开启' : '关闭') : '未知'
}

function collectViewportInfo() {
  viewportInfo.value.width = window.innerWidth
  viewportInfo.value.height = window.innerHeight
  viewportInfo.value.dpr = window.devicePixelRatio || 1
  viewportInfo.value.maxTouchPoints = navigator.maxTouchPoints > 0 ? `${navigator.maxTouchPoints} 点触控` : '不支持'
}

function measureRefreshRate(durationMs = 1200): Promise<number | null> {
  return new Promise((resolve) => {
    let started = 0
    let last = 0
    const deltas: number[] = []
    function tick(now: number) {
      if (!started) started = now
      if (last > 0 && now - started > 250) {
        const delta = now - last
        if (delta > 0) deltas.push(delta)
      }
      last = now
      if (now - started >= durationMs) {
        if (deltas.length < 5) { resolve(null); return }
        const sorted = [...deltas].sort((a, b) => a - b)
        const median = sorted[Math.floor(sorted.length / 2)]
        resolve(Math.round(1000 / median))
        return
      }
      requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  })
}

function buildScreen(item: any, index: number, primary: boolean): ScreenItem {
  const dpr = item?.devicePixelRatio || window.devicePixelRatio || 1
  const logicalWidth = item?.width || item?.availWidth || screen.width
  const logicalHeight = item?.height || item?.availHeight || screen.height
  return {
    id: index + 1,
    label: primary ? '主显示器' : `显示器 #${index + 1}`,
    isPrimary: !!primary,
    logicalWidth,
    logicalHeight,
    physicalWidth: Math.round(logicalWidth * dpr),
    physicalHeight: Math.round(logicalHeight * dpr),
    dpr,
    colorDepth: item?.colorDepth || screen.colorDepth || 0,
    orientation: orientationLabel(item?.orientation || screen.orientation),
    position: `x=${item?.left ?? 0}, y=${item?.top ?? 0}`,
    refreshRate: '未知'
  }
}

async function collectScreens() {
  let raw: any[] = []
  try {
    const getDetails = (navigator as any).getScreenDetails
    if (typeof getDetails === 'function') {
      const details = await getDetails.call(navigator)
      if (details && Array.isArray(details.screens) && details.screens.length) {
        raw = details.screens.map((s: any) => s)
      }
    }
  } catch {
    /* 不支持多屏 API 时回退到单屏 */
  }
  if (!raw.length) raw = [window.screen]
  const primaryIndex = raw.findIndex((s: any) => s && s.isPrimary === true)
  screens.value = raw.map((s, i) => buildScreen(s, i, primaryIndex >= 0 ? i === primaryIndex : i === 0))

  const hz = await measureRefreshRate()
  if (hz) {
    const primary = screens.value.find(s => s.isPrimary) || screens.value[0]
    if (primary) primary.refreshRate = `实测 ${hz} Hz`
  }
}

async function refreshInfo() {
  isLoading.value = true
  try {
    collectHardwareInfo()
    collectNetworkInfo()
    collectViewportInfo()
    await collectBrowserInfo()
    await collectScreens()
  } catch (e) {
    console.error('获取系统信息失败:', e)
  } finally {
    isLoading.value = false
  }
}

onMounted(refreshInfo)
</script>

<template>
  <div class="min-h-screen relative overflow-hidden">
    <div class="fixed inset-0 z-0">
      <img
        src="/app-screenshot2.jpg"
        alt="背景"
        class="w-full h-full object-cover"
      />
      <div class="absolute inset-0 bg-gradient-to-b from-black/60 via-black/40 to-black/70"></div>
    </div>

    <nav class="fixed top-0 left-0 right-0 bg-white/10 backdrop-blur-lg shadow-sm z-50 border-b border-white/20">
      <div class="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <AnimatedCloud size="small" />
          <div>
            <h1 class="text-xl font-bold text-white">{{ SITE_NAME }}</h1>
          </div>
        </div>

        <div class="flex items-center gap-4">
          <router-link to="/" class="px-4 py-2 text-white/80 hover:text-white transition-all">首页</router-link>
          <router-link to="/about" class="px-4 py-2 text-white/80 hover:text-white transition-all">关于我们</router-link>
          <router-link to="/system" class="px-4 py-2 bg-white/20 text-white rounded-lg hover:bg-white/30 transition-all backdrop-blur">系统信息</router-link>
          <router-link to="/login" class="px-4 py-2 text-white/80 hover:text-white transition-all">登录</router-link>
          <router-link to="/register" class="px-4 py-2 bg-white text-primary-600 rounded-lg hover:bg-white/90 transition-all font-medium">注册</router-link>
        </div>
      </div>
    </nav>

    <section class="relative z-10 pt-32 pb-16 px-6">
      <div class="max-w-4xl mx-auto text-center">
        <div class="inline-flex items-center justify-center w-16 h-16 bg-white/20 backdrop-blur rounded-2xl mb-6">
          <Monitor class="w-8 h-8 text-white" />
        </div>
        <h2 class="text-4xl font-bold text-white mb-4">系统信息</h2>
        <p class="text-xl text-white/70">精准检测您的显示器、硬件与浏览器配置</p>
      </div>
    </section>

    <section class="relative z-10 py-8 px-6">
      <div class="max-w-4xl mx-auto">
        <div v-if="isLoading" class="text-center py-20">
          <div class="inline-flex items-center justify-center w-16 h-16 border-4 border-white/20 border-t-blue-500 rounded-full animate-spin mb-4"></div>
          <p class="text-white/70">正在检测系统信息...</p>
        </div>

        <div v-else class="space-y-6">
          <div class="bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20 p-8">
            <div class="flex items-center justify-between mb-6">
              <div class="flex items-center gap-4">
                <div class="w-12 h-12 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl flex items-center justify-center">
                  <Monitor class="w-6 h-6 text-white" />
                </div>
                <div>
                  <h3 class="text-xl font-bold text-white">显示器信息</h3>
                  <p class="text-white/60 text-sm">检测到 {{ screens.length }} 个屏幕</p>
                </div>
              </div>
              <button @click="refreshInfo" class="p-3 bg-white/10 rounded-xl hover:bg-white/20 transition-all">
                <RefreshCw class="w-5 h-5 text-white/70" />
              </button>
            </div>

            <div v-for="screenItem in screens" :key="screenItem.id"
              class="bg-white/5 rounded-2xl p-6 mb-4 last:mb-0 border border-white/10">
              <div class="flex items-center justify-between mb-5">
                <div class="flex items-center gap-3">
                  <span class="w-2.5 h-2.5 rounded-full" :class="screenItem.isPrimary ? 'bg-blue-400' : 'bg-slate-400'"></span>
                  <h4 class="text-white font-semibold">{{ screenItem.label }}</h4>
                  <span v-if="screenItem.isPrimary" class="px-2 py-0.5 rounded-full text-xs bg-blue-500/20 text-blue-300 border border-blue-500/30">主屏</span>
                </div>
                <span class="text-white/50 text-xs">{{ screenItem.position }}</span>
              </div>

              <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div class="bg-white/5 rounded-xl p-4">
                  <div class="text-white font-bold text-lg">{{ screenItem.logicalWidth }} × {{ screenItem.logicalHeight }}</div>
                  <div class="text-white/50 text-xs mt-1">逻辑分辨率</div>
                </div>
                <div class="bg-white/5 rounded-xl p-4">
                  <div class="text-white font-bold text-lg">{{ screenItem.physicalWidth }} × {{ screenItem.physicalHeight }}</div>
                  <div class="text-white/50 text-xs mt-1">物理像素</div>
                </div>
                <div class="bg-white/5 rounded-xl p-4">
                  <div class="text-white font-bold text-lg">{{ screenItem.dpr }}x</div>
                  <div class="text-white/50 text-xs mt-1">像素比</div>
                </div>
                <div class="bg-white/5 rounded-xl p-4">
                  <div class="text-white font-bold text-lg">{{ screenItem.refreshRate }}</div>
                  <div class="text-white/50 text-xs mt-1">刷新率</div>
                </div>
              </div>

              <div class="grid grid-cols-2 md:grid-cols-3 gap-4 mt-4">
                <div class="bg-white/5 rounded-xl p-4 flex items-center gap-3">
                  <Gauge class="w-5 h-5 text-white/60 shrink-0" />
                  <div>
                    <div class="text-white font-medium">{{ screenItem.orientation }}</div>
                    <div class="text-white/50 text-xs">屏幕方向</div>
                  </div>
                </div>
                <div class="bg-white/5 rounded-xl p-4 flex items-center gap-3">
                  <Monitor class="w-5 h-5 text-white/60 shrink-0" />
                  <div>
                    <div class="text-white font-medium">{{ screenItem.colorDepth }} 位</div>
                    <div class="text-white/50 text-xs">颜色深度</div>
                  </div>
                </div>
                <div class="bg-white/5 rounded-xl p-4 flex items-center gap-3">
                  <Touchpad class="w-5 h-5 text-white/60 shrink-0" />
                  <div>
                    <div class="text-white font-medium">{{ screenItem.isPrimary ? '主显示器' : '副显示器' }}</div>
                    <div class="text-white/50 text-xs">角色</div>
                  </div>
                </div>
              </div>
            </div>

            <p class="text-white/40 text-xs mt-4 leading-relaxed">
              说明：物理像素 = 逻辑分辨率 × 像素比；刷新率为浏览器动画帧在当前窗口所处屏幕上约 1.2 秒实测采样。浏览器出于隐私保护不提供屏幕物理尺寸（英寸）与副屏刷新率，无法获取的项目显示为未知，绝不估算伪造。
            </p>
          </div>

          <div class="bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20 p-8">
            <div class="flex items-center gap-4 mb-6">
              <div class="w-12 h-12 bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl flex items-center justify-center">
                <Globe class="w-6 h-6 text-white" />
              </div>
              <div>
                <h3 class="text-xl font-bold text-white">系统与浏览器</h3>
                <p class="text-white/60 text-sm">浏览器提供的真实环境信息</p>
              </div>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">浏览器</div>
                <div class="text-white font-medium break-words">{{ browserInfo.browser }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">操作系统</div>
                <div class="text-white font-medium">{{ browserInfo.system }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">架构 / 位数</div>
                <div class="text-white font-medium">{{ browserInfo.architecture }} / {{ browserInfo.bitness }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">完整版本</div>
                <div class="text-white font-medium break-words">{{ browserInfo.fullVersion }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">移动设备</div>
                <div class="text-white font-medium">{{ browserInfo.mobile }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">在线状态</div>
                <div class="text-white font-medium">{{ browserInfo.online }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">界面语言</div>
                <div class="text-white font-medium">{{ browserInfo.language }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">时区</div>
                <div class="text-white font-medium break-words">{{ browserInfo.timezone }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4 flex items-center gap-3">
                <Smartphone class="w-5 h-5 text-white/60 shrink-0" />
                <div>
                  <div class="text-white font-medium">{{ browserInfo.mobile === '是' ? '移动端' : '桌面端' }}</div>
                  <div class="text-white/50 text-xs">设备类型</div>
                </div>
              </div>
            </div>
          </div>

          <div class="bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20 p-8">
            <div class="flex items-center gap-4 mb-6">
              <div class="w-12 h-12 bg-gradient-to-br from-amber-500 to-orange-500 rounded-xl flex items-center justify-center">
                <Cpu class="w-6 h-6 text-white" />
              </div>
              <div>
                <h3 class="text-xl font-bold text-white">硬件信息</h3>
                <p class="text-white/60 text-sm">浏览器可访问的硬件能力</p>
              </div>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div class="bg-white/5 rounded-xl p-4 flex items-center gap-3">
                <Cpu class="w-5 h-5 text-white/60 shrink-0" />
                <div>
                  <div class="text-white font-medium">{{ hardwareInfo.cpuCores }}</div>
                  <div class="text-white/50 text-xs">逻辑处理器</div>
                </div>
              </div>
              <div class="bg-white/5 rounded-xl p-4 flex items-center gap-3">
                <MemoryStick class="w-5 h-5 text-white/60 shrink-0" />
                <div>
                  <div class="text-white font-medium">{{ hardwareInfo.memory }}</div>
                  <div class="text-white/50 text-xs">设备内存</div>
                </div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">GPU 渲染器</div>
                <div class="text-white font-medium break-words">{{ hardwareInfo.gpuRenderer }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">GPU 厂商</div>
                <div class="text-white font-medium break-words">{{ hardwareInfo.gpuVendor }}</div>
              </div>
            </div>
          </div>

          <div class="bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20 p-8">
            <div class="flex items-center gap-4 mb-6">
              <div class="w-12 h-12 bg-gradient-to-br from-green-500 to-emerald-500 rounded-xl flex items-center justify-center">
                <Wifi class="w-6 h-6 text-white" />
              </div>
              <div>
                <h3 class="text-xl font-bold text-white">网络信息</h3>
                <p class="text-white/60 text-sm">当前连接状态</p>
              </div>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">有效类型</div>
                <div class="text-white font-medium">{{ networkInfo.effectiveType }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">连接方式</div>
                <div class="text-white font-medium">{{ networkInfo.connectionType }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">下行速度</div>
                <div class="text-white font-medium">{{ networkInfo.downlink }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">往返延迟</div>
                <div class="text-white font-medium">{{ networkInfo.rtt }}</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white/60 text-xs mb-1">节省数据</div>
                <div class="text-white font-medium">{{ networkInfo.saveData }}</div>
              </div>
            </div>
          </div>

          <div class="bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20 p-8">
            <div class="flex items-center gap-4 mb-6">
              <div class="w-12 h-12 bg-gradient-to-br from-cyan-500 to-sky-500 rounded-xl flex items-center justify-center">
                <Touchpad class="w-6 h-6 text-white" />
              </div>
              <div>
                <h3 class="text-xl font-bold text-white">视口与触控</h3>
                <p class="text-white/60 text-sm">当前窗口显示能力</p>
              </div>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white font-bold text-lg">{{ viewportInfo.width }} × {{ viewportInfo.height }}</div>
                <div class="text-white/50 text-xs mt-1">视口大小</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white font-bold text-lg">{{ viewportInfo.dpr }}x</div>
                <div class="text-white/50 text-xs mt-1">像素比</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4">
                <div class="text-white font-bold text-lg">{{ viewportInfo.maxTouchPoints }}</div>
                <div class="text-white/50 text-xs mt-1">触控能力</div>
              </div>
              <div class="bg-white/5 rounded-xl p-4 flex items-center gap-3">
                <HardDrive class="w-5 h-5 text-white/60 shrink-0" />
                <div>
                  <div class="text-white font-medium">{{ browserInfo.online }}</div>
                  <div class="text-white/50 text-xs">网络在线</div>
                </div>
              </div>
            </div>
          </div>

          <div class="bg-white/5 backdrop-blur rounded-2xl border border-white/10 p-5 flex items-start gap-3">
            <Languages class="w-5 h-5 text-blue-300 shrink-0 mt-0.5" />
            <p class="text-white/50 text-xs leading-relaxed">
              隐私说明：本页只读取浏览器标准接口提供的真实信息，不会申请摄像头等任何权限，也不会通过分辨率反推屏幕尺寸。受浏览器隐私策略限制，部分项目可能显示为未知。
            </p>
          </div>
        </div>
      </div>
    </section>

    <footer class="relative z-10 py-12 px-6 bg-black/40 backdrop-blur-sm border-t border-white/10 mt-12">
      <div class="max-w-6xl mx-auto">
        <div class="flex flex-col md:flex-row justify-between items-center gap-6">
          <div class="flex items-center gap-3">
            <AnimatedCloud size="small" />
            <div>
              <h4 class="text-xl font-bold text-white">{{ SITE_NAME }}</h4>
              <p class="text-white/50 text-sm">安全可靠的云端存储服务</p>
            </div>
          </div>

          <div class="flex items-center gap-6">
            <router-link to="/about" class="text-white/60 hover:text-white transition-colors">关于我们</router-link>
            <router-link to="/terms" class="text-white/60 hover:text-white transition-colors">服务条款</router-link>
            <router-link to="/privacy" class="text-white/60 hover:text-white transition-colors">隐私政策</router-link>
            <router-link to="/system" class="text-white/60 hover:text-white transition-colors">系统信息</router-link>
          </div>
        </div>

        <div class="border-t border-white/10 mt-8 pt-8">
          <div class="flex flex-col items-center gap-4">
            <div v-if="STUDIO_NAME" class="studio-signature">
              <span class="studio-text">{{ STUDIO_NAME }}</span>
              <span class="studio-dot"></span>
              <span class="studio-tag">出品</span>
            </div>
            <p class="text-white/50">© 2026 {{ SITE_NAME }}. All rights reserved.</p>
          </div>
        </div>
      </div>
    </footer>
  </div>
</template>

<style scoped>
.studio-signature {
  display: flex;
  align-items: center;
  gap: 8px;
}

.studio-text {
  font-size: 16px;
  font-weight: 600;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
  background-size: 200% 200%;
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: studioGradient 3s ease-in-out infinite;
  letter-spacing: 2px;
}

.studio-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: linear-gradient(135deg, #667eea, #764ba2);
  animation: studioPulse 2s ease-in-out infinite;
}

.studio-tag {
  font-size: 12px;
  padding: 2px 8px;
  border-radius: 10px;
  background: linear-gradient(135deg, rgba(102, 126, 234, 0.2), rgba(118, 75, 162, 0.2));
  border: 1px solid rgba(102, 126, 234, 0.3);
  color: rgba(255, 255, 255, 0.8);
  animation: studioGlow 2.5s ease-in-out infinite;
}

@keyframes studioGradient {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

@keyframes studioPulse {
  0%, 100% { transform: scale(1); opacity: 1; box-shadow: 0 0 0 0 rgba(102, 126, 234, 0.7); }
  50% { transform: scale(1.2); opacity: 0.8; box-shadow: 0 0 0 6px rgba(102, 126, 234, 0); }
}

@keyframes studioGlow {
  0%, 100% { box-shadow: 0 0 5px rgba(102, 126, 234, 0.3), 0 0 10px rgba(118, 75, 162, 0.2); }
  50% { box-shadow: 0 0 15px rgba(102, 126, 234, 0.5), 0 0 25px rgba(118, 75, 162, 0.3); }
}
</style>
