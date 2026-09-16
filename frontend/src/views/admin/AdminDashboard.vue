<script setup lang="ts">
import { SITE_NAME } from '@/config/site'
import { R_ADMIN_SETTINGS } from '@/utils/routeCodes'

import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAdminStore } from '@/stores/admin'
import { request } from '@/utils/axios'
import Layout from '@/components/Layout.vue'
import {
  Users, Files, Share2, Server, RefreshCw, Loader2, HardDrive, CloudUpload,
  Megaphone, BarChart3, Shield, ScrollText, MessageSquareWarning, Link2,
  ArrowRight, Activity, Clock, FileUp, BadgeCheck
} from 'lucide-vue-next'

const adminStore = useAdminStore()
const serverInfo = ref({ version: '-', serverTime: '', uploadLimit: '-', siteName: SITE_NAME })
const recentUsers = ref<any[]>([])
const recentFiles = ref<any[]>([])
const loading = ref(true)
const refreshing = ref(false)
let autoTimer: any = null

const storageUsed = computed(() => adminStore.stats.storageUsed || 0)
const storageRemaining = computed(() => adminStore.stats.storageRemaining || 0)
// IronWall v1.47.4: 优先使用后端汇总总量（超配额时剩余为 0，前端推算会失真）
const storageTotal = computed(() => adminStore.stats.storageTotal && adminStore.stats.storageTotal > 0
  ? adminStore.stats.storageTotal
  : storageUsed.value + storageRemaining.value)
const storagePercent = computed(() => storageTotal.value ? Math.min(Math.round((storageUsed.value / storageTotal.value) * 100), 100) : 0)

const quickLinks = [
  { to: '/admin/users', label: '用户管理', desc: '账号、封禁与认证', icon: Users, color: 'from-blue-500 to-cyan-500' },
  { to: '/admin/files', label: '文件管理', desc: '全站文件审核', icon: Files, color: 'from-purple-500 to-violet-500' },
  { to: '/admin/shares', label: '分享管理', desc: '分享链接管控', icon: Link2, color: 'from-pink-500 to-rose-500' },
  { to: '/admin/announcements', label: '系统公告', desc: '公告发布与维护', icon: Megaphone, color: 'from-indigo-500 to-blue-500' },
  { to: '/admin/download-stats', label: '下载统计', desc: '下载数据与排行', icon: BarChart3, color: 'from-amber-500 to-orange-500' },
  { to: '/admin/security', label: '安全中心', desc: '铁壁引擎与攻击防护', icon: Shield, color: 'from-emerald-500 to-green-500' },
  { to: '/admin/logs', label: '操作日志', desc: '行为审计追踪', icon: ScrollText, color: 'from-slate-500 to-gray-500' },
  { to: '/admin/appeals', label: '申诉管理', desc: '误封申诉处理', icon: MessageSquareWarning, color: 'from-orange-500 to-amber-500' }
]

async function loadAll() {
  try {
    await adminStore.getDashboardStats()
    await adminStore.getUsers(0, 5)
    await adminStore.getFiles(0, 5)
    recentUsers.value = adminStore.users.slice(0, 5)
    recentFiles.value = adminStore.files.slice(0, 5)

    const res = await request<Record<string, string>>({ url: R_ADMIN_SETTINGS, method: 'GET' })
    if (res.success && res.data) {
      try {
        const sysInfo = JSON.parse(res.data.system_info || '{}')
        serverInfo.value.version = sysInfo.version || '-'
        serverInfo.value.uploadLimit = sysInfo.upload_max || '-'
      } catch { /* ignore */ }
      serverInfo.value.siteName = res.data.site_name || SITE_NAME
    }
    serverInfo.value.serverTime = new Date().toLocaleString('zh-CN', { hour12: false })
  } catch (e: any) { console.error(e) }
}

async function handleRefresh() {
  refreshing.value = true
  await loadAll()
  setTimeout(() => { refreshing.value = false }, 400)
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

function formatDate(dateStr: string): string {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleDateString('zh-CN')
}

onMounted(async () => {
  loading.value = true
  await loadAll()
  loading.value = false
  autoTimer = setInterval(() => { loadAll() }, 60000)
})

onUnmounted(() => {
  if (autoTimer) clearInterval(autoTimer)
})
</script>

<template>
  <Layout>
    <div class="space-y-6">
      <div class="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 class="text-3xl font-bold text-white flex items-center gap-3">
            <Activity class="w-7 h-7 text-blue-400" />仪表板概览
          </h1>
          <p class="text-slate-400 mt-2 flex items-center gap-2">
            <Clock class="w-3.5 h-3.5" />{{ serverInfo.serverTime || '系统运行状态与关键数据统计' }}
          </p>
        </div>
        <button @click="handleRefresh" :disabled="refreshing"
          class="flex items-center gap-2 px-4 py-2.5 bg-slate-800/70 hover:bg-slate-700/70 border border-slate-700/40 text-white rounded-xl transition-all text-sm font-medium">
          <RefreshCw :class="refreshing ? 'animate-spin' : ''" class="w-4 h-4 text-blue-400" />
          {{ refreshing ? '刷新中...' : '刷新数据' }}
        </button>
      </div>

      <div v-if="loading" class="text-center py-16 text-slate-400">
        <Loader2 class="w-8 h-8 animate-spin mx-auto mb-3" />
        <p class="text-sm">正在加载系统数据...</p>
      </div>

      <template v-else>
        <!-- 核心统计 -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
          <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-blue-500/40 transition-all group">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-3xl font-bold text-white">{{ adminStore.stats.totalUsers || 0 }}</p>
                <p class="text-sm text-slate-400 mt-1">注册用户</p>
                <p class="text-xs text-slate-500 mt-1 flex items-center gap-1"><BadgeCheck class="w-3 h-3" />活跃 {{ adminStore.stats.activeUsers || 0 }} 人</p>
              </div>
              <div class="w-14 h-14 bg-blue-500/20 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform">
                <Users class="w-7 h-7 text-blue-400" />
              </div>
            </div>
          </div>

          <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-purple-500/40 transition-all group">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-3xl font-bold text-white">{{ adminStore.stats.totalFiles || 0 }}</p>
                <p class="text-sm text-slate-400 mt-1">文件总数</p>
                <p class="text-xs text-slate-500 mt-1 flex items-center gap-1"><FileUp class="w-3 h-3" />今日上传 {{ adminStore.stats.todayUploads || 0 }} 个</p>
              </div>
              <div class="w-14 h-14 bg-purple-500/20 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform">
                <Files class="w-7 h-7 text-purple-400" />
              </div>
            </div>
          </div>

          <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-pink-500/40 transition-all group">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-3xl font-bold text-white">{{ adminStore.stats.totalShares || 0 }}</p>
                <p class="text-sm text-slate-400 mt-1">分享链接</p>
                <p class="text-xs text-slate-500 mt-1 flex items-center gap-1"><Link2 class="w-3 h-3" />今日创建 {{ adminStore.stats.todayShares || 0 }} 个</p>
              </div>
              <div class="w-14 h-14 bg-pink-500/20 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform">
                <Share2 class="w-7 h-7 text-pink-400" />
              </div>
            </div>
          </div>

          <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-cyan-500/40 transition-all group">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-3xl font-bold text-white">{{ serverInfo.version }}</p>
                <p class="text-sm text-slate-400 mt-1">系统版本</p>
                <p class="text-xs text-slate-500 mt-1 flex items-center gap-1"><CloudUpload class="w-3 h-3" />单文件上限 {{ serverInfo.uploadLimit }}</p>
              </div>
              <div class="w-14 h-14 bg-cyan-500/20 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform">
                <Server class="w-7 h-7 text-cyan-400" />
              </div>
            </div>
          </div>
        </div>

        <!-- 存储概览 -->
        <div class="bg-slate-800/60 rounded-2xl p-6 border border-slate-700/30">
          <div class="flex items-center justify-between mb-4 flex-wrap gap-3">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 bg-emerald-500/20 rounded-xl flex items-center justify-center">
                <HardDrive class="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h2 class="text-lg font-semibold text-white">存储空间使用情况</h2>
                <p class="text-xs text-slate-500 mt-0.5">全站用户已用 {{ formatBytes(storageUsed) }} / 共 {{ formatBytes(storageTotal) }}</p>
              </div>
            </div>
            <span class="text-sm text-emerald-400 font-medium">{{ storagePercent }}%</span>
          </div>
          <div class="h-3 bg-slate-700/40 rounded-full overflow-hidden">
            <div :class="storagePercent > 90 ? 'bg-gradient-to-r from-red-500 to-orange-500' : storagePercent > 70 ? 'bg-gradient-to-r from-amber-500 to-yellow-500' : 'bg-gradient-to-r from-emerald-500 to-green-500'"
              class="h-full rounded-full transition-all duration-700" :style="{ width: storagePercent + '%' }"></div>
          </div>
          <p class="text-xs text-slate-500 mt-3">剩余可用 {{ formatBytes(storageRemaining) }}，建议在 {{ storagePercent > 70 ? '已超过' : '达到' }} 70% 前扩容</p>
        </div>

        <!-- 快捷入口 -->
        <div>
          <h2 class="text-lg font-semibold text-white mb-4">快捷入口</h2>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <router-link v-for="link in quickLinks" :key="link.to" :to="link.to"
              class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-blue-500/40 hover:scale-[1.02] transition-all group flex items-start justify-between">
              <div>
                <div :class="['w-11 h-11 bg-gradient-to-br rounded-xl flex items-center justify-center mb-3 group-hover:scale-110 transition-transform', link.color]">
                  <component :is="link.icon" class="w-5 h-5 text-white" />
                </div>
                <p class="text-white font-medium">{{ link.label }}</p>
                <p class="text-slate-500 text-xs mt-1">{{ link.desc }}</p>
              </div>
              <ArrowRight class="w-4 h-4 text-slate-600 group-hover:text-blue-400 group-hover:translate-x-1 transition-all mt-1" />
            </router-link>
          </div>
        </div>

        <!-- 最近动态 -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30">
            <div class="flex items-center justify-between mb-4">
              <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                <Users class="w-5 h-5 text-blue-400" />最近注册用户
              </h2>
              <router-link to="/admin/users" class="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1">
                查看全部<ArrowRight class="w-3 h-3" />
              </router-link>
            </div>
            <div class="space-y-3">
              <div v-for="user in recentUsers" :key="user.id" class="flex items-center justify-between py-3 border-b border-slate-700/30 last:border-0">
                <div class="flex items-center gap-3 min-w-0">
                  <div class="w-10 h-10 bg-slate-600 rounded-lg flex items-center justify-center overflow-hidden shrink-0">
                    <img v-if="user.avatar" :src="user.avatar" class="w-full h-full object-cover" />
                    <Users v-else class="w-5 h-5 text-white" />
                  </div>
                  <div class="min-w-0">
                    <p class="text-white font-medium truncate">{{ user.username }}</p>
                    <p class="text-xs text-slate-400 truncate">{{ user.email }}</p>
                  </div>
                </div>
                <div class="text-right shrink-0">
                  <span :class="user.user_status === 'active' ? 'text-green-400' : user.user_status === 'banned' ? 'text-red-400' : 'text-slate-400'" class="text-xs">
                    {{ user.user_status === 'active' ? '正常' : user.user_status === 'banned' ? '封禁' : '禁用' }}
                  </span>
                  <p class="text-xs text-slate-500 mt-1">{{ formatDate(user.created_at) }}</p>
                </div>
              </div>
              <div v-if="recentUsers.length === 0" class="text-center py-8 text-slate-400 text-sm">暂无用户</div>
            </div>
          </div>

          <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30">
            <div class="flex items-center justify-between mb-4">
              <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                <Files class="w-5 h-5 text-purple-400" />最近上传文件
              </h2>
              <router-link to="/admin/files" class="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1">
                查看全部<ArrowRight class="w-3 h-3" />
              </router-link>
            </div>
            <div class="space-y-3">
              <div v-for="file in recentFiles" :key="file.id" class="flex items-center justify-between py-3 border-b border-slate-700/30 last:border-0">
                <div class="flex items-center gap-3 min-w-0">
                  <div class="w-10 h-10 bg-purple-600/30 rounded-lg flex items-center justify-center shrink-0">
                    <Files class="w-5 h-5 text-white" />
                  </div>
                  <div class="min-w-0">
                    <p class="text-white font-medium truncate max-w-[220px]">{{ file.original_name }}</p>
                    <p class="text-xs text-slate-400">{{ formatBytes(file.file_size) }}<span class="text-slate-600 ml-2">下载 {{ file.download_count || 0 }} 次</span></p>
                  </div>
                </div>
                <p class="text-xs text-slate-500 shrink-0">{{ formatDate(file.created_at) }}</p>
              </div>
              <div v-if="recentFiles.length === 0" class="text-center py-8 text-slate-400 text-sm">暂无文件</div>
            </div>
          </div>
        </div>
      </template>
    </div>
  </Layout>
</template>
