<script setup lang="ts">
import { SITE_NAME } from '@/config/site'
import { R_ADMIN_SECURITY_ATTACKERS, R_ADMIN_SECURITY_ATTACKER_ID_REPORT, R_ADMIN_SECURITY_ATTACKS, R_ADMIN_SECURITY_BLOCK_IP, R_ADMIN_SECURITY_DECOY_PORTS_ROTATE, R_ADMIN_SECURITY_IP_GEO, R_ADMIN_SECURITY_SEGMENT_UNBLOCK, R_ADMIN_SECURITY_SERVER_SHIELD, R_ADMIN_SECURITY_SUMMARY, R_ADMIN_SECURITY_UNBLOCK, R_ADMIN_SECURITY_SHARE_DOWNLOAD_LIMITS, R_ADMIN_SECURITY_SHARE_DOWNLOAD_LIMITS_RESET } from '@/utils/routeCodes'

import { ref, computed, onMounted, onUnmounted } from 'vue'
import Layout from '@/components/Layout.vue'
import { request } from '@/utils/axios'
import { ShieldAlert, Shield, ShieldOff, Radar, Ban, Clock, RefreshCw, ChevronLeft, ChevronRight, Globe, Activity, Fish, Network, Bug, Fingerprint, Server, Layers, Lock, Database, MapPin } from 'lucide-vue-next'

const loading = ref(true)
const refreshing = ref(false)
const summary = ref<any>({})
const attacks = ref<any[]>([])
const attackers = ref<any[]>([])
const totalElements = ref(0)
const currentPage = ref(0)
const pageSize = 20
const defense = computed(() => summary.value.defense_engine || {})
const decoyPorts = computed(() => {
  const serverDecoys = serverShield.value?.decoy_ports?.layers
  return (serverDecoys && serverDecoys.length) ? serverDecoys : (defense.value.decoy_ports || [])
})
const decoyHits = computed(() => serverShield.value?.decoy_ports?.total_hits ?? 0)
const serverShield = ref<any>(null)
const shieldLoading = ref(false)
const reportOpen = ref(false)
const reportLoading = ref(false)
const reportIp = ref('')
const reportMarkdown = ref('')
const reportProfile = ref<any>({})
const copied = ref(false)
const confirmOpen = ref(false)
const confirmIp = ref(' ')

async function loadSummary() {
  try {
    const res = await request({ url: R_ADMIN_SECURITY_SUMMARY, method: 'GET' })
    summary.value = (res as any)?.data || {}
  } catch (e) { console.error(e) }
}

async function loadAttacks() {
  loading.value = true
  try {
    const res = await request({ url: R_ADMIN_SECURITY_ATTACKS, method: 'GET', params: { page: currentPage.value, size: pageSize } })
    const data = (res as any)?.data || {}
    attacks.value = data.content || []
    totalElements.value = data.totalElements || 0
  } catch (e) { console.error(e) }
  loading.value = false
}

async function unblock(ip: string) {
  try {
    await request({ url: R_ADMIN_SECURITY_UNBLOCK, method: 'POST', data: { ip } })
    await Promise.all([loadSummary(), loadAttacks()])
  } catch (e) { console.error(e) }
}

async function loadAttackers() {
  try {
    const res = await request({ url: R_ADMIN_SECURITY_ATTACKERS, method: 'GET' })
    attackers.value = (res as any)?.data || []
  } catch (e) { console.error(e) }
}

async function loadServerShield(force = true) {
  shieldLoading.value = true
  try {
    const res = await request({ url: R_ADMIN_SECURITY_SERVER_SHIELD, method: 'GET', params: { refresh: force } })
    serverShield.value = (res as any)?.data || null
  } catch (e) { console.error(e) }
  finally { shieldLoading.value = false }
}

async function unblockSegment(segment: string) {
  try {
    await request({ url: R_ADMIN_SECURITY_SEGMENT_UNBLOCK, method: 'POST', data: { segment } })
    await Promise.all([loadSummary(), loadAttackers()])
  } catch (e) { console.error(e) }
}

async function openReport(ip: string) {
  reportOpen.value = true
  reportIp.value = ip
  reportLoading.value = true
  reportMarkdown.value = ''
  reportProfile.value = {}
  try {
    const res = await request({ url: `${R_ADMIN_SECURITY_ATTACKER_ID_REPORT}/${ip}`, method: 'GET' })
    const data = (res as any)?.data || {}
    reportProfile.value = data.profile || {}
    reportMarkdown.value = data.report_markdown || ''
  } catch (e) { console.error(e) }
  reportLoading.value = false
}

async function copyReport() {
  try {
    await navigator.clipboard.writeText(reportMarkdown.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch (e) { console.error(e) }
}

function blockIp(ip: string) {
  confirmIp.value = ip
  confirmOpen.value = true
}

async function confirmBlock() {
  const ip = confirmIp.value
  confirmOpen.value = false
  try {
    await request({ url: R_ADMIN_SECURITY_BLOCK_IP, method: 'POST', data: { ip, minutes: 30 } })
    await Promise.all([loadSummary(), loadAttackers()])
  } catch (e) { console.error(e) }
}

function downloadReport() {
  try {
    const blob = new Blob([reportMarkdown.value], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `滥用报告-${reportIp.value}.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  } catch (e) { console.error(e) }
}

async function rotateDecoyPorts() {
  try {
    await request({ url: R_ADMIN_SECURITY_DECOY_PORTS_ROTATE, method: 'POST' })
    await loadSummary()
  } catch (e) { console.error(e) }
}

// IronWall v1.28.5: IP 自动定位
// IronWall v1.47.3: admin console for share download rate-limit buckets
const dlLimits = ref<any>({ clients: [], codes: [] })
const dlClients = computed(() => dlLimits.value?.clients || [])
const dlCodes = computed(() => dlLimits.value?.codes || [])

async function loadShareDownloadLimits() {
  try {
    const res = await request({ url: R_ADMIN_SECURITY_SHARE_DOWNLOAD_LIMITS, method: 'GET' })
    dlLimits.value = (res as any)?.data || { clients: [], codes: [] }
  } catch (e) { console.error(e) }
}

async function resetShareDownloadLimits(key?: string) {
  try {
    await request({ url: R_ADMIN_SECURITY_SHARE_DOWNLOAD_LIMITS_RESET, method: 'POST', data: key ? { key } : {} })
    await loadShareDownloadLimits()
  } catch (e) { console.error(e) }
}

const locatingIp = ref('')
async function locate(ip: string) {
  locatingIp.value = ip
  try {
    const res = await request({ url: R_ADMIN_SECURITY_IP_GEO, method: 'GET', params: { ip } })
    const geo = (res as any)?.data?.geo || null
    const blockedItem = (summary.value.blocked_ips || []).find((b: any) => b.ip === ip)
    if (blockedItem) blockedItem.geo = geo
    const logRow = attacks.value.find((a: any) => a.ip === ip)
    if (logRow) logRow.geo = geo
  } catch (e) { console.error(e) }
  locatingIp.value = ''
}

let geoTimer: any = null
onMounted(() => {
  // 位置情报后台预热后自动补全，30 秒轻量刷新一次
  loadShareDownloadLimits()
  geoTimer = setInterval(() => { loadSummary() }, 30000)
})
onUnmounted(() => { if (geoTimer) clearInterval(geoTimer) })

async function refresh() {
  refreshing.value = true
  try {
    await Promise.all([loadSummary(), loadAttacks(), loadAttackers(), loadServerShield(true), loadShareDownloadLimits()])
  } finally {
    refreshing.value = false
  }
}

function layerColor(status: string): string {
  const map: Record<string, string> = {
    ok: 'border-emerald-500/30 bg-emerald-500/10',
    warn: 'border-amber-500/30 bg-amber-500/10',
    off: 'border-slate-600/40 bg-slate-800/40',
  }
  return map[status] || map.off
}

function layerDot(status: string): string {
  const map: Record<string, string> = {
    ok: 'bg-emerald-400',
    warn: 'bg-amber-400',
    off: 'bg-slate-500',
  }
  return map[status] || map.off
}

function layerText(status: string): string {
  const map: Record<string, string> = {
    ok: 'text-emerald-400',
    warn: 'text-amber-400',
    off: 'text-slate-400',
  }
  return map[status] || map.off
}

function formatDate(d: string): string {
  if (!d) return '-'
  return d.replace('T', ' ').substring(0, 19)
}

function blockedUntil(d: string): string {
  if (!d) return '-'
  return d.replace('T', ' ').substring(0, 19)
}

function typeColor(type: string): string {
  const map: Record<string, string> = {
    'SQL注入': 'bg-red-500/20 text-red-400',
    'XSS攻击': 'bg-orange-500/20 text-orange-400',
    '路径穿越': 'bg-amber-500/20 text-amber-400',
    '命令注入': 'bg-rose-500/20 text-rose-400',
    'SSRF探测': 'bg-purple-500/20 text-purple-400',
    '扫描工具': 'bg-cyan-500/20 text-cyan-400',
    '爬虫扫描': 'bg-teal-500/20 text-teal-400',
    '路径异常探测': 'bg-yellow-500/20 text-yellow-400',
    '蜜罐诱捕': 'bg-pink-500/20 text-pink-400',
    'IP段封禁': 'bg-fuchsia-500/20 text-fuchsia-400',
  }
  return map[type] || 'bg-slate-500/20 text-slate-400'
}

function profileColor(profile: string): string {
  const map: Record<string, string> = {
    'SCANNER': 'bg-cyan-500/20 text-cyan-400',
    'PERSISTENT': 'bg-amber-500/20 text-amber-400',
    'TARGETED': 'bg-red-500/20 text-red-400',
    'SUSPECT': 'bg-yellow-500/20 text-yellow-400',
  }
  return map[profile] || 'bg-slate-500/20 text-slate-400'
}

function profileLabel(profile: string): string {
  const map: Record<string, string> = {
    'SCANNER': '扫描者',
    'PERSISTENT': '顽固攻击者',
    'TARGETED': '定向攻击者',
    'SUSPECT': '可疑攻击者',
    'UNKNOWN': '未知',
  }
  return map[profile] || profile || '未知'
}

onMounted(refresh)
</script>

<template>
  <Layout>
    <div class="p-4 sm:p-6 w-full space-y-6">
      <div class="flex items-center justify-between gap-4">
        <div>
          <h1 class="text-2xl font-bold text-white flex items-center gap-3">
            <ShieldAlert class="w-7 h-7 text-red-500" />
            安全预警
          </h1>
          <p class="text-slate-400 text-sm mt-1">
            铁壁安全引擎实时检测注入 / XSS / 穿越 / 扫描工具等攻击行为
          </p>
        </div>
        <button @click="refresh" :disabled="refreshing"
          class="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-sm font-medium transition-all border border-slate-700/50 disabled:opacity-50 disabled:cursor-not-allowed">
          <RefreshCw class="w-4 h-4" :class="refreshing ? 'animate-spin' : ''" />
          {{ refreshing ? '刷新中...' : '刷新' }}
        </button>
      </div>

      <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div class="bg-slate-800/60 rounded-2xl border border-slate-700/30 p-5">
          <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Shield class="w-4 h-4" />引擎状态</div>
          <div class="text-lg font-bold text-white">{{ summary.engine || `${SITE_NAME}铁壁安全引擎` }}</div>
          <div class="text-xs mt-1" :class="summary.enabled ? 'text-green-400' : 'text-red-400'">
            {{ summary.enabled ? '● 防护运行中' : '○ 已停用' }}
          </div>
        </div>
        <div class="bg-slate-800/60 rounded-2xl border border-slate-700/30 p-5">
          <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Activity class="w-4 h-4" />今日攻击</div>
          <div class="text-2xl font-bold text-red-400">{{ summary.today_attacks ?? 0 }}</div>
          <div class="text-xs text-slate-500 mt-1">已拦截并记录</div>
        </div>
        <div class="bg-slate-800/60 rounded-2xl border border-slate-700/30 p-5">
          <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Radar class="w-4 h-4" />累计攻击</div>
          <div class="text-2xl font-bold text-white">{{ summary.total_attacks ?? 0 }}</div>
          <div class="text-xs text-slate-500 mt-1">历史检测总量</div>
        </div>
        <div class="bg-slate-800/60 rounded-2xl border border-slate-700/30 p-5">
          <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Ban class="w-4 h-4" />封禁 IP</div>
          <div class="text-2xl font-bold text-amber-400">{{ summary.blocked_count ?? 0 }}</div>
          <div class="text-xs text-slate-500 mt-1">自动封禁生效中</div>
        </div>
      </div>

      <div class="bg-slate-800/60 rounded-2xl border border-slate-700/30 p-5">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-sm font-semibold text-white flex items-center gap-2">
            <Server class="w-4 h-4 text-cyan-400" />服务器前置护盾
            <span v-if="serverShield && serverShield.installed" class="px-2 py-0.5 rounded-lg text-xs font-mono bg-cyan-500/15 text-cyan-400">已接入</span>
            <span v-else class="px-2 py-0.5 rounded-lg text-xs font-mono bg-slate-600/30 text-slate-400">未接入</span>
          </h2>
          <div class="flex items-center gap-3 text-xs text-slate-500">
            <span v-if="serverShield && serverShield.generated_at">采集于 {{ (serverShield.generated_at || '').replace('T', ' ').substring(0, 19) }}</span>
            <button @click="loadServerShield(true)" :disabled="shieldLoading"
              class="px-3 py-1.5 bg-slate-700/50 hover:bg-slate-700 text-slate-300 rounded-lg transition-all disabled:opacity-50">
              {{ shieldLoading ? '刷新中...' : '刷新状态' }}
            </button>
          </div>
        </div>
        <div v-if="serverShield && serverShield.layers" class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3 mb-4">
          <div v-for="l in serverShield.layers" :key="l.name" class="rounded-xl border p-3" :class="layerColor(l.status)">
            <div class="flex items-center gap-2 text-xs font-semibold mb-1" :class="layerText(l.status)">
              <span class="w-1.5 h-1.5 rounded-full" :class="layerDot(l.status)"></span>
              {{ l.name }}
            </div>
            <div class="text-[11px] text-slate-400 mb-1.5">{{ l.desc }}</div>
            <div class="text-[11px]" :class="layerText(l.status)">{{ l.detail }}</div>
          </div>
        </div>
        <div v-if="!serverShield || !serverShield.installed" class="bg-slate-900/50 border border-slate-700/40 rounded-xl p-4 text-sm text-slate-400 leading-relaxed">
          服务器层护盾尚未接入：把后端的 server-guard 目录中 install-server-shield.sh 与 update-ironwall-shield.sh 上传到服务器，执行 bash install-server-shield.sh 即可点亮本面板（fail2ban / 防火墙 / SSH / MySQL 状态每 60 秒自动采集）。
        </div>
        <template v-if="serverShield && serverShield.installed">
          <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
            <div class="bg-slate-900/50 rounded-xl border border-slate-700/30 p-4">
              <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Layers class="w-4 h-4" />fail2ban</div>
              <div class="text-xl font-bold" :class="serverShield.fail2ban?.running ? 'text-emerald-400' : 'text-red-400'">
                {{ serverShield.fail2ban?.running ? '运行中' : '未运行' }}
              </div>
              <div class="text-xs text-slate-500 mt-1">全端口封禁 {{ serverShield.fail2ban?.total_banned ?? 0 }} 个 IP</div>
            </div>
            <div class="bg-slate-900/50 rounded-xl border border-slate-700/30 p-4">
              <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Lock class="w-4 h-4" />防火墙</div>
              <div class="text-xl font-bold" :class="serverShield.firewall?.active ? 'text-emerald-400' : 'text-amber-400'">
                {{ serverShield.firewall?.active ? '已开启' : '未开启' }}
              </div>
              <div class="text-xs text-slate-500 mt-1">公网监听 {{ (serverShield.listening_public || []).join(', ') || '-' }}</div>
            </div>
            <div class="bg-slate-900/50 rounded-xl border border-slate-700/30 p-4">
              <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Database class="w-4 h-4" />MySQL</div>
              <div class="text-xl font-bold" :class="serverShield.mysql?.local_only ? 'text-emerald-400' : 'text-amber-400'">
                {{ serverShield.mysql?.local_only ? '仅内网' : '暴露风险' }}
              </div>
              <div class="text-xs text-slate-500 mt-1">绑定 {{ serverShield.mysql?.bind_address || '-' }}</div>
            </div>
            <div class="bg-slate-900/50 rounded-xl border border-slate-700/30 p-4">
              <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Shield class="w-4 h-4" />SSH 加固</div>
              <div class="text-xl font-bold" :class="serverShield.ssh?.hardened ? 'text-emerald-400' : 'text-amber-400'">
                {{ serverShield.ssh?.hardened ? '已加固' : '待加固' }}
              </div>
              <div class="text-xs text-slate-500 mt-1">{{ serverShield.ssh?.password_auth === 'no' ? '密钥登录 · 端口 ' + serverShield.ssh?.port : '密码登录仍开启' }}</div>
            </div>
          </div>
          <div v-if="serverShield.portscan" class="mb-4 bg-slate-900/50 border border-purple-800/30 rounded-xl p-4">
            <div class="flex items-center gap-2 text-xs font-semibold text-purple-300 mb-2">
              <Radar class="w-4 h-4" />端口扫描检测
              <span class="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/15 text-emerald-400">{{ serverShield.portscan.jail?.enabled ? '已接入' : '未接入' }}</span>
            </div>
            <div class="flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-400">
              <span>当前探测源：<b class="text-purple-300">{{ serverShield.portscan.detections ?? 0 }}</b></span>
              <span>累计全端口封禁：<b class="text-red-400">{{ serverShield.portscan.total_banned ?? 0 }}</b></span>
            </div>
          </div>

          <div v-if="serverShield.fail2ban?.jails?.length" class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div v-for="j in serverShield.fail2ban.jails" :key="j.name"
              class="bg-slate-900/50 rounded-xl border p-4" :class="j.enabled ? 'border-emerald-500/20' : 'border-slate-700/40'">
              <div class="flex items-center justify-between mb-3">
                <span class="font-mono text-xs text-cyan-300">{{ j.name }}</span>
                <span class="text-xs" :class="j.enabled ? 'text-emerald-400' : 'text-slate-500'">{{ j.enabled ? '已启用' : '未启用' }}</span>
              </div>
              <div class="grid grid-cols-3 gap-2 text-center">
                <div>
                  <div class="text-lg font-bold text-white">{{ j.currently_banned }}</div>
                  <div class="text-[10px] text-slate-500 mt-0.5">封禁中</div>
                </div>
                <div>
                  <div class="text-lg font-bold text-amber-400">{{ j.currently_failed }}</div>
                  <div class="text-[10px] text-slate-500 mt-0.5">失败中</div>
                </div>
                <div>
                  <div class="text-lg font-bold text-slate-300">{{ j.total_banned }}</div>
                  <div class="text-[10px] text-slate-500 mt-0.5">累计封禁</div>
                </div>
              </div>
              <div v-if="j.banned_ips?.length" class="mt-3 flex flex-wrap gap-1">
                <span v-for="ip in j.banned_ips" :key="ip" class="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 font-mono text-[10px]">{{ ip }}</span>
              </div>
            </div>
          </div>
          <div v-if="serverShield.warnings?.length" class="mt-4 bg-amber-950/30 border border-amber-900/40 rounded-xl p-4">
            <div class="text-xs font-semibold text-amber-300 mb-2 flex items-center gap-2"><ShieldOff class="w-3.5 h-3.5" />服务器加固建议</div>
            <ul class="space-y-1">
              <li v-for="w in serverShield.warnings" :key="w" class="text-xs text-amber-200/80 leading-relaxed">· {{ w }}</li>
            </ul>
          </div>
        </template>
      </div>
      <div class="bg-slate-800/60 rounded-2xl border border-slate-700/30 p-5">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-sm font-semibold text-white flex items-center gap-2">
            <Shield class="w-4 h-4 text-emerald-400" />主动防御与威慑引擎
            <span class="px-2 py-0.5 rounded-lg text-xs font-mono bg-emerald-500/15 text-emerald-400">{{ defense.version || 'v1.48.0' }}</span>
          </h2>
          <span class="text-xs text-slate-500">对持续攻击者分级升级 · 拖延消耗 · 蜜罐诱捕 · IP 段封禁 · 溯源取证</span>
        </div>
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div class="bg-slate-900/50 rounded-xl border border-slate-700/30 p-4">
            <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Fish class="w-4 h-4" />蜜罐诱捕</div>
            <div class="text-xl font-bold text-pink-400">{{ defense.honeypot_hits ?? 0 }}</div>
            <div class="text-xs text-slate-500 mt-1">触碰仿真敏感路径次数</div>
          </div>
          <div class="bg-slate-900/50 rounded-xl border border-slate-700/30 p-4">
            <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Bug class="w-4 h-4" />Tarpit 拖延</div>
            <div class="text-xl font-bold text-amber-400">{{ defense.tarpit_active ?? 0 }}</div>
            <div class="text-xs text-slate-500 mt-1">正在被慢响应消耗的攻击者</div>
          </div>
          <div class="bg-slate-900/50 rounded-xl border border-slate-700/30 p-4">
            <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Network class="w-4 h-4" />IP 段封禁</div>
            <div class="text-xl font-bold text-fuchsia-400">{{ defense.segment_count ?? 0 }}</div>
            <div class="text-xs text-slate-500 mt-1">顽固攻击者 /24 网段封禁</div>
          </div>
          <div class="bg-slate-900/50 rounded-xl border border-slate-700/30 p-4">
            <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Fingerprint class="w-4 h-4" />威胁情报</div>
            <div class="text-xl font-bold" :class="defense.threat_intel_enabled ? 'text-emerald-400' : 'text-slate-400'">{{ defense.threat_intel_enabled ? '已启用' : '未启用' }}</div>
            <div class="text-xs text-slate-500 mt-1">攻击者溯源取证与滥用报告</div>
          </div>
          <div class="bg-slate-900/50 rounded-xl border border-slate-700/30 p-4">
            <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Globe class="w-4 h-4" />移动出口熔断</div>
            <div class="text-xl font-bold text-cyan-400">{{ defense.mobile_fuse?.block_cap_hits ?? 0 }}</div>
            <div class="text-xs text-slate-500 mt-1">运营商出口封禁时长压顶 · 段豁免 {{ defense.mobile_fuse?.segment_skips ?? 0 }}</div>
          </div>
          <div class="bg-slate-900/50 rounded-xl border border-slate-700/30 p-4">
            <div class="flex items-center gap-2 text-slate-500 text-xs mb-2"><Activity class="w-4 h-4" />用户级限速</div>
            <div class="text-xl font-bold text-sky-400">{{ summary.user_rate_limit?.limited_total ?? 0 }}</div>
            <div class="text-xs text-slate-500 mt-1">认证用户超限拦截 · 上限 {{ summary.user_rate_limit?.max_requests_per_minute ?? 1800 }}/分</div>
          </div>
        </div>

        <div class="mt-4 bg-slate-900/50 border border-purple-800/30 rounded-xl p-4">
          <div class="flex items-center justify-between mb-3">
            <div class="flex items-center gap-2 text-xs font-semibold text-purple-300">
<Radar class="w-4 h-4" />七层假端口陷阱（随机生成）
            </div>
            <button @click="rotateDecoyPorts"
              class="px-3 py-1.5 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/20 rounded-lg text-xs transition-all">
              轮换陷阱
            </button>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            <div v-for="d in decoyPorts" :key="d.layer"
              class="bg-slate-950/50 border border-slate-700/40 rounded-lg p-3">
              <div class="flex items-center justify-between mb-2">
                <span class="text-[11px] text-slate-400">L{{ d.layer }} · {{ d.service }}</span>
                <span class="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/15 text-emerald-400">已埋设</span>
              </div>
              <div class="flex flex-wrap gap-1">
                <span v-for="p in d.ports" :key="p" class="px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 font-mono text-[10px]">{{ p }}</span>
              </div>
            </div>
          </div>
          <p class="text-[11px] text-slate-500 mt-3">这些仿真端口由安全引擎自动生成；攻击者一旦连接，连接会被吞没并联动服务器层全端口封禁，只有入口没有出口。累计踩坑：<span class="text-purple-300 font-mono">{{ decoyHits }}</span> 次</p>
        </div>

        <div v-if="(defense.blocked_segments || []).length > 0" class="mt-4 space-y-2">
          <div v-for="s in defense.blocked_segments" :key="s.segment"
            class="flex items-center justify-between gap-3 bg-fuchsia-950/30 border border-fuchsia-900/40 rounded-xl px-4 py-3">
            <div class="flex items-center gap-3">
              <Network class="w-4 h-4 text-fuchsia-400 shrink-0" />
              <div>
                <div class="text-white font-mono text-sm">{{ s.segment }}</div>
                <div class="text-xs text-slate-500 mt-0.5">段内再犯 {{ s.block_count }} 次 · 封禁至 {{ blockedUntil(s.blocked_until) }}（剩余 {{ Math.round(s.blocked_seconds / 60) }} 分钟）</div>
              </div>
            </div>
            <button @click="unblockSegment(s.segment)"
              class="px-3 py-1.5 bg-slate-700/50 hover:bg-slate-700 text-slate-300 rounded-lg text-xs transition-all shrink-0">
              解除段封禁
            </button>
          </div>
        </div>

        <div v-if="attackers.length > 0" class="mt-4 overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-slate-700/50">
                <th class="text-left px-3 py-2 text-xs text-slate-500 font-medium">攻击者 IP</th>
                <th class="text-left px-3 py-2 text-xs text-slate-500 font-medium">威胁画像</th>
                <th class="text-left px-3 py-2 text-xs text-slate-500 font-medium">违规记分</th>
                <th class="text-left px-3 py-2 text-xs text-slate-500 font-medium">再犯次数</th>
                <th class="text-left px-3 py-2 text-xs text-slate-500 font-medium">处置状态</th>
                <th class="text-left px-3 py-2 text-xs text-slate-500 font-medium">溯源报告</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="a in attackers" :key="a.ip" class="border-b border-slate-700/20 hover:bg-slate-700/30 transition-colors">
                <td class="px-3 py-2.5 text-slate-300 font-mono">{{ a.ip }}</td>
                <td class="px-3 py-2.5">
                  <span :class="['px-2 py-0.5 rounded-lg text-xs font-medium', profileColor(a.threat_profile)]">{{ profileLabel(a.threat_profile) }}</span>
                </td>
                <td class="px-3 py-2.5 text-amber-400 font-semibold">{{ a.score }}</td>
                <td class="px-3 py-2.5 text-slate-400">{{ a.block_count }}</td>
                <td class="px-3 py-2.5">
                  <span v-if="a.segment_blocked" class="px-2 py-0.5 text-xs rounded-full font-medium bg-fuchsia-500/20 text-fuchsia-400">网段封禁</span>
                  <span v-else-if="a.tarpit" class="px-2 py-0.5 text-xs rounded-full font-medium bg-amber-500/20 text-amber-400">拖延消耗中</span>
                  <span v-else class="px-2 py-0.5 text-xs rounded-full font-medium bg-slate-500/20 text-slate-400">监控中</span>
                </td>
                <td class="px-3 py-2.5">
                  <div class="flex gap-2">
                    <button @click="openReport(a.ip)"
                      class="px-2.5 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 rounded-lg text-xs font-medium transition-all">
                      滥用报告
                    </button>
                    <button @click="blockIp(a.ip)"
                      class="px-2.5 py-1 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-lg text-xs font-medium transition-all">
                      封禁IP
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div v-if="(summary.blocked_ips || []).length > 0" class="bg-red-950/30 rounded-2xl border border-red-900/40 p-5">
        <h2 class="text-sm font-semibold text-red-300 mb-3 flex items-center gap-2">
          <ShieldOff class="w-4 h-4" />封禁名单
        </h2>
        <div class="space-y-2">
          <div v-for="b in summary.blocked_ips" :key="b.ip"
            class="flex items-center justify-between gap-3 bg-slate-900/60 border border-red-900/30 rounded-xl px-4 py-3">
            <div class="flex items-center gap-3">
              <Globe class="w-4 h-4 text-red-400 shrink-0" />
              <div>
                <div class="text-white font-mono text-sm">{{ b.ip }}</div>
                <div class="text-xs text-slate-500 mt-0.5">违规记分 {{ b.score }} · 封禁至 {{ blockedUntil(b.blocked_until) }}（剩余 {{ Math.round(b.blocked_seconds / 60) }} 分钟）</div>
                <div v-if="b.geo?.display" class="text-xs text-slate-400 mt-0.5 flex items-center gap-1"><MapPin class="w-3 h-3 text-indigo-400 shrink-0" />{{ b.geo.display }}</div>
                <div v-else class="text-xs text-slate-600 mt-0.5">位置识别中，稍后自动补全</div>
              </div>
            </div>
            <div class="flex items-center gap-2 shrink-0">
              <button @click="locate(b.ip)" :disabled="locatingIp===b.ip"
                class="px-3 py-1.5 bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 rounded-lg text-xs transition-all">
                {{ locatingIp===b.ip ? '识别中…' : '定位' }}
              </button>
              <button @click="unblock(b.ip)"
                class="px-3 py-1.5 bg-slate-700/50 hover:bg-slate-700 text-slate-300 rounded-lg text-xs transition-all">
                解除封禁
              </button>
            </div>
          </div>
        </div>
      </div>

      <div class="bg-slate-800/60 rounded-2xl border border-slate-700/30 overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/30 flex items-center justify-between">
          <h2 class="text-sm font-semibold text-white flex items-center gap-2">
            <Clock class="w-4 h-4 text-slate-400" />分享下载频控
          </h2>
          <div class="flex items-center gap-2">
            <span class="text-xs text-slate-500">窗口 60 秒 · 超限按真实剩余时间冷却</span>
            <button @click="loadShareDownloadLimits()" class="px-3 py-1.5 bg-slate-700/50 hover:bg-slate-700 text-slate-300 rounded-lg text-xs transition-all">刷新</button>
            <button @click="resetShareDownloadLimits()" class="px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 text-red-300 rounded-lg text-xs transition-all">全部重置</button>
          </div>
        </div>
        <div class="px-5 py-4 space-y-2">
          <div v-if="!dlClients.length && !dlCodes.length" class="text-sm text-slate-400">当前无活跃频控桶，正常用户不受影响</div>
          <div v-if="dlClients.length || dlCodes.length" class="text-xs text-slate-500">客户端桶 {{ dlClients.length }} · 分享桶 {{ dlCodes.length }}</div>
          <div v-for="c in dlClients" :key="c.key" class="flex items-center justify-between gap-3 bg-slate-900/60 border border-slate-700/40 rounded-xl px-4 py-2">
            <div class="text-xs text-slate-300 font-mono truncate flex-1">{{ c.key }}</div>
            <div class="text-xs text-slate-500 whitespace-nowrap">{{ c.count }}/{{ c.limit }} · {{ c.reset_in_seconds }} 秒后重置</div>
            <button @click="resetShareDownloadLimits(c.key)" class="px-3 py-1.5 bg-slate-700/50 hover:bg-slate-700 text-slate-300 rounded-lg text-xs transition-all">重置</button>
          </div>
          <div v-for="c in dlCodes" :key="'code-' + c.key" class="flex items-center justify-between gap-3 bg-slate-900/60 border border-slate-700/40 rounded-xl px-4 py-2">
            <div class="text-xs text-slate-300 font-mono truncate flex-1">{{ c.key }}</div>
            <div class="text-xs text-slate-500 whitespace-nowrap">{{ c.count }}/{{ c.limit }} · {{ c.reset_in_seconds }} 秒后重置</div>
            <button @click="resetShareDownloadLimits(c.key)" class="px-3 py-1.5 bg-slate-700/50 hover:bg-slate-700 text-slate-300 rounded-lg text-xs transition-all">重置</button>
          </div>
        </div>
      </div>

      <div class="bg-slate-800/60 rounded-2xl border border-slate-700/30 overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-700/30 flex items-center justify-between">
          <h2 class="text-sm font-semibold text-white flex items-center gap-2">
            <Clock class="w-4 h-4 text-slate-400" />攻击流水
          </h2>
          <span class="text-xs text-slate-500">共 {{ totalElements }} 条</span>
        </div>
        <div v-if="loading" class="text-center py-16 text-slate-400">
          <RefreshCw class="w-6 h-6 animate-spin mx-auto mb-3" />
          加载中...
        </div>
        <div v-else class="overflow-x-auto">
          <table class="w-full">
            <thead>
              <tr class="border-b border-slate-700/50 bg-slate-800/80">
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium w-40">时间</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium w-24">类型</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium w-36">IP</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">攻击载荷</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium w-20">记分</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium w-24">处置</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="a in attacks" :key="a.id" class="border-b border-slate-700/20 hover:bg-slate-700/30 transition-colors">
                <td class="px-4 py-3 text-sm text-slate-400 whitespace-nowrap">{{ formatDate(a.created_at) }}</td>
                <td class="px-4 py-3">
                  <span :class="['px-2 py-0.5 rounded-lg text-xs font-medium', typeColor(a.attack_type)]">{{ a.attack_type || '-' }}</span>
                </td>
                <td class="px-4 py-3 text-sm text-slate-300 font-mono whitespace-nowrap">{{ a.ip || '-' }}
                  <div v-if="a.geo?.display" class="text-xs text-slate-500 font-sans mt-0.5">{{ a.geo.display }}</div>
                </td>
                <td class="px-4 py-3 text-sm text-slate-400 max-w-[340px]">
                  <div class="truncate" :title="(a.path || '') + ' ' + (a.payload || '')">{{ a.payload || a.path || '-' }}</div>
                </td>
                <td class="px-4 py-3 text-sm text-amber-400 font-semibold">{{ a.score ?? '-' }}</td>
                <td class="px-4 py-3">
                  <span :class="['px-2 py-0.5 text-xs rounded-full font-medium',
                    a.action === 'BLOCKED' ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400']">
                    {{ a.action === 'BLOCKED' ? '已封禁' : '已警告' }}
                  </span>
                </td>
              </tr>
              <tr v-if="attacks.length === 0">
                <td colspan="6" class="text-center py-16 text-slate-500">
                  <ShieldAlert class="w-8 h-8 mx-auto mb-3 text-slate-600" />
                  暂无攻击记录，防护运行正常
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="flex items-center justify-between px-4 py-3 border-t border-slate-700/30">
          <span class="text-xs text-slate-500">第 {{ currentPage + 1 }} 页</span>
          <div class="flex gap-2">
            <button @click="currentPage--; loadAttacks()" :disabled="currentPage === 0"
              :class="['flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium transition-all',
                currentPage === 0 ? 'bg-slate-700/30 text-slate-500 cursor-not-allowed' : 'bg-slate-700/50 text-slate-300 hover:bg-slate-700']">
              <ChevronLeft class="w-3.5 h-3.5" />
              上一页
            </button>
            <button @click="currentPage++; loadAttacks()" :disabled="attacks.length < pageSize"
              :class="['flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium transition-all',
                attacks.length < pageSize ? 'bg-slate-700/30 text-slate-500 cursor-not-allowed' : 'bg-slate-700/50 text-slate-300 hover:bg-slate-700']">
              下一页
              <ChevronRight class="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      <div v-if="confirmOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" @click.self="confirmOpen = false">
        <div class="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-md">
          <div class="flex items-center justify-between px-5 py-4 border-b border-slate-700/50">
            <h3 class="text-sm font-semibold text-white flex items-center gap-2">
              <Ban class="w-4 h-4 text-red-400" />
              手动封禁确认
            </h3>
            <button @click="confirmOpen = false" class="text-slate-400 hover:text-white text-xl leading-none">×</button>
          </div>
          <div class="px-5 py-4 text-sm text-slate-300 leading-relaxed">
            确定手动封禁 <span class="font-mono text-red-400">{{ confirmIp }}</span> 30 分钟吗？
            封禁期间该 IP 仅可访问专属警示页，所有请求均会记录取证。
          </div>
          <div class="flex items-center justify-end gap-2 px-5 py-4 border-t border-slate-700/50">
            <button @click="confirmOpen = false"
              class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-sm transition-all">
              取消
            </button>
            <button @click="confirmBlock"
              class="px-4 py-2 bg-red-500/15 hover:bg-red-500/25 border border-red-500/30 text-red-400 rounded-xl text-sm font-medium transition-all">
              确认封禁 30 分钟
            </button>
          </div>
        </div>
      </div>

      <div v-if="reportOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" @click.self="reportOpen = false">
        <div class="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-3xl max-h-[85vh] flex flex-col">
          <div class="flex items-center justify-between px-5 py-4 border-b border-slate-700/50">
            <h3 class="text-sm font-semibold text-white flex items-center gap-2">
              <Fingerprint class="w-4 h-4 text-emerald-400" />
              攻击溯源与处置报告
              <span class="font-mono text-slate-400 text-xs">{{ reportIp }}</span>
            </h3>
            <button @click="reportOpen = false" class="text-slate-400 hover:text-white text-xl leading-none">×</button>
          </div>
          <div class="overflow-y-auto px-5 py-4 flex-1">
            <div v-if="reportLoading" class="text-center py-12 text-slate-400">正在生成报告...</div>
            <div v-else>
              <div v-if="reportProfile.geo" class="bg-slate-800/60 rounded-xl p-3 mb-3 flex flex-wrap gap-2">
                <span class="px-2 py-0.5 rounded-lg text-xs font-medium bg-emerald-500/15 text-emerald-400">
                  {{ reportProfile.geo.country }} {{ reportProfile.geo.regionName }} {{ reportProfile.geo.city }}
                </span>
                <span class="px-2 py-0.5 rounded-lg text-xs font-medium bg-cyan-500/15 text-cyan-400">
                  ISP: {{ reportProfile.geo.isp }}
                </span>
                <span class="px-2 py-0.5 rounded-lg text-xs font-medium bg-purple-500/15 text-purple-400">
                  ASN: {{ reportProfile.geo.as }}
                </span>
              </div>
              <pre class="whitespace-pre-wrap break-words text-xs text-slate-300 leading-relaxed font-mono">{{ reportMarkdown }}</pre>
            </div>
          </div>
          <div class="flex items-center justify-end gap-2 px-5 py-4 border-t border-slate-700/50">
            <button @click="downloadReport"
              class="px-4 py-2 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 rounded-xl text-sm transition-all">
              下载报告(.md)
            </button>
            <button @click="copyReport"
              class="px-4 py-2 bg-slate-700/50 hover:bg-slate-700 text-slate-300 rounded-xl text-sm transition-all">
              {{ copied ? '已复制' : '复制报告' }}
            </button>
            <button @click="reportOpen = false"
              class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-sm transition-all">
              关闭
            </button>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>
