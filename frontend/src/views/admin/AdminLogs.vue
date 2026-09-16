<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useAdminStore } from '@/stores/admin'
import Layout from '@/components/Layout.vue'
import { Clock, Search, RotateCcw, Download, Upload, Trash2, Share2, FileText, Settings, User, LogIn, UserPlus, FolderPlus, RefreshCw, ChevronLeft, ChevronRight, ShieldCheck, ShieldOff, UserX, UserCheck, Megaphone, MegaphoneOff, FolderMinus } from 'lucide-vue-next'

const adminStore = useAdminStore()
const loading = ref(true)
const actionFilter = ref('all')
const keyword = ref('')
const currentPage = ref(0)
const pageSize = 50

const actionTypes = [
  { value: 'all', label: '全部', icon: Clock, color: 'text-slate-400' },
  { value: 'login', label: '登录', icon: LogIn, color: 'text-blue-400' },
  { value: 'register', label: '注册', icon: UserPlus, color: 'text-green-400' },
  { value: 'upload', label: '上传', icon: Upload, color: 'text-sky-400' },
  { value: 'download', label: '下载', icon: Download, color: 'text-indigo-400' },
  { value: 'share_download', label: '分享下载', icon: Share2, color: 'text-teal-400' },
  { value: 'delete_file', label: '删除', icon: Trash2, color: 'text-red-400' },
  { value: 'delete_permanent', label: '永久删除', icon: Trash2, color: 'text-rose-400' },
  { value: 'restore_file', label: '恢复', icon: RotateCcw, color: 'text-emerald-400' },
  { value: 'create_share', label: '创建分享', icon: Share2, color: 'text-violet-400' },
  { value: 'delete_share', label: '删除分享', icon: Share2, color: 'text-pink-400' },
  { value: 'create_folder', label: '新建文件夹', icon: FolderPlus, color: 'text-amber-400' },
  { value: 'update_profile', label: '修改资料', icon: User, color: 'text-cyan-400' },
  { value: 'change_password', label: '修改密码', icon: Settings, color: 'text-orange-400' },
  { value: 'update_settings', label: '系统设置', icon: Settings, color: 'text-yellow-400' },
  { value: 'verify_user', label: '认证用户', icon: ShieldCheck, color: 'text-emerald-400' },
  { value: 'unverify_user', label: '取消认证', icon: ShieldOff, color: 'text-gray-400' },
  { value: 'ban_user', label: '封禁用户', icon: UserX, color: 'text-red-400' },
  { value: 'unban_user', label: '解封用户', icon: UserCheck, color: 'text-green-400' },
  { value: 'update_user', label: '修改用户', icon: User, color: 'text-amber-400' },
  { value: 'admin_delete_user', label: '删除用户', icon: UserX, color: 'text-rose-400' },
  { value: 'delete_announcement', label: '删除公告', icon: MegaphoneOff, color: 'text-orange-400' },
  { value: 'create_announcement', label: '创建公告', icon: Megaphone, color: 'text-purple-400' },
  { value: 'delete_folder', label: '删除文件夹', icon: FolderMinus, color: 'text-pink-400' },
]

async function loadLogs() {
  loading.value = true
  try {
    await adminStore.getLogs(
      actionFilter.value === 'all' ? undefined : actionFilter.value,
      undefined,
      keyword.value || undefined,
      currentPage.value,
      pageSize
    )
  } catch (e: any) { console.error(e) }
  loading.value = false
}

async function filterByAction(action: string) {
  actionFilter.value = action
  currentPage.value = 0
  await loadLogs()
}

async function doSearch() {
  currentPage.value = 0
  await loadLogs()
}

async function nextPage() {
  currentPage.value++
  await loadLogs()
}

async function prevPage() {
  if (currentPage.value > 0) {
    currentPage.value--
    await loadLogs()
  }
}

function getActionLabel(action: string): string {
  const found = actionTypes.find(a => a.value === action)
  return found ? found.label : action
}

function getActionIcon(action: string) {
  const found = actionTypes.find(a => a.value === action)
  return found ? found.icon : FileText
}

function getActionColor(action: string): string {
  if (action === 'login') return 'bg-blue-500/20 text-blue-400'
  if (action === 'register') return 'bg-green-500/20 text-green-400'
  if (action === 'upload') return 'bg-sky-500/20 text-sky-400'
  if (action === 'download') return 'bg-indigo-500/20 text-indigo-400'
  if (action === 'share_download') return 'bg-teal-500/20 text-teal-400'
  if (action === 'delete_file' || action === 'delete_permanent') return 'bg-red-500/20 text-red-400'
  if (action === 'restore_file') return 'bg-emerald-500/20 text-emerald-400'
  if (action === 'create_share') return 'bg-violet-500/20 text-violet-400'
  if (action === 'delete_share') return 'bg-pink-500/20 text-pink-400'
  if (action === 'create_folder') return 'bg-amber-500/20 text-amber-400'
  if (action === 'update_profile') return 'bg-cyan-500/20 text-cyan-400'
  if (action === 'change_password') return 'bg-orange-500/20 text-orange-400'
  if (action === 'update_settings') return 'bg-yellow-500/20 text-yellow-400'
  if (action === 'verify_user') return 'bg-emerald-500/20 text-emerald-400'
  if (action === 'unverify_user') return 'bg-gray-500/20 text-gray-400'
  if (action === 'ban_user') return 'bg-red-500/20 text-red-400'
  if (action === 'unban_user') return 'bg-green-500/20 text-green-400'
  if (action === 'update_user') return 'bg-amber-500/20 text-amber-400'
  if (action === 'admin_delete_user') return 'bg-rose-500/20 text-rose-400'
  if (action === 'delete_announcement') return 'bg-orange-500/20 text-orange-400'
  if (action === 'create_announcement') return 'bg-purple-500/20 text-purple-400'
  if (action === 'delete_folder') return 'bg-pink-500/20 text-pink-400'
  return 'bg-gray-500/20 text-gray-400'
}

function formatDate(dateStr: string): string {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleString('zh-CN')
}

onMounted(async () => { await loadLogs() })

const totalLogs = computed(() => adminStore.logs.length)
</script>

<template>
  <Layout>
    <div class="space-y-6">
      <div>
        <h1 class="text-3xl font-bold text-white">系统日志</h1>
        <p class="text-slate-400 mt-2">记录所有用户操作行为，包括登录、上传、删除、分享等</p>
      </div>

      <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 space-y-4">
        <div class="flex flex-wrap gap-2">
          <button v-for="at in actionTypes" :key="at.value"
            @click="filterByAction(at.value)"
            :class="['flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium transition-all border',
              actionFilter === at.value ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' : 'bg-slate-700/30 text-slate-400 border-transparent hover:bg-slate-700/50 hover:text-slate-300']">
            <component :is="at.icon" :class="['w-3.5 h-3.5', at.color]" />
            {{ at.label }}
          </button>
        </div>

        <div class="flex gap-3">
          <div class="relative flex-1">
            <Search class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input v-model="keyword" @keyup.enter="doSearch"
              placeholder="搜索用户名、文件名、操作详情..."
              class="w-full pl-10 pr-4 py-2.5 bg-slate-800/50 border border-slate-700/30 rounded-xl text-white text-sm placeholder-slate-500 focus:outline-none focus:border-blue-500/50" />
          </div>
          <button @click="doSearch"
            class="px-4 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm font-medium transition-all">
            搜索
          </button>
        </div>
      </div>

      <div v-if="loading" class="text-center py-16 text-slate-400">
        <RefreshCw class="w-6 h-6 animate-spin mx-auto mb-3" />
        加载中...
      </div>

      <div v-else class="bg-slate-800/60 rounded-2xl border border-slate-700/30 overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full">
            <thead>
              <tr class="border-b border-slate-700/50 bg-slate-800/80">
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium w-40">时间</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium w-24">操作</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium w-24">用户</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">详情</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium w-36">IP</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium w-20">状态</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="log in adminStore.logs" :key="log.id"
                class="border-b border-slate-700/20 hover:bg-slate-700/30 transition-colors">
                <td class="px-4 py-3 text-sm text-slate-400 whitespace-nowrap">{{ formatDate(log.time) }}</td>
                <td class="px-4 py-3">
                  <span :class="['inline-flex items-center gap-1 px-2 py-0.5 rounded-lg text-xs font-medium', getActionColor(log.action)]">
                    <component :is="getActionIcon(log.action)" class="w-3 h-3" />
                    {{ getActionLabel(log.action) }}
                  </span>
                </td>
                <td class="px-4 py-3 text-sm text-white whitespace-nowrap">{{ log.username || log.user_id || '-' }}</td>
                <td class="px-4 py-3 text-sm text-slate-300 max-w-[300px]">
                  <div class="truncate" :title="log.detail">{{ log.detail || log.target_name || '-' }}</div>
                </td>
                <td class="px-4 py-3 text-sm text-slate-500 font-mono whitespace-nowrap">{{ log.ip || '-' }}</td>
                <td class="px-4 py-3">
                  <span :class="['px-2 py-0.5 text-xs rounded-full font-medium',
                    log.status === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400']">
                    {{ log.status === 'success' ? '成功' : '失败' }}
                  </span>
                </td>
              </tr>
              <tr v-if="adminStore.logs.length === 0">
                <td colspan="6" class="text-center py-16 text-slate-500">
                  <FileText class="w-8 h-8 mx-auto mb-3 text-slate-600" />
                  暂无日志记录
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="flex items-center justify-between px-4 py-3 border-t border-slate-700/30">
          <span class="text-xs text-slate-500">共 {{ totalLogs }} 条记录</span>
          <div class="flex gap-2">
            <button @click="prevPage" :disabled="currentPage === 0"
              :class="['flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium transition-all',
                currentPage === 0 ? 'bg-slate-700/30 text-slate-500 cursor-not-allowed' : 'bg-slate-700/50 text-slate-300 hover:bg-slate-700']">
              <ChevronLeft class="w-3.5 h-3.5" />
              上一页
            </button>
            <button @click="nextPage" :disabled="adminStore.logs.length < pageSize"
              :class="['flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium transition-all',
                adminStore.logs.length < pageSize ? 'bg-slate-700/30 text-slate-500 cursor-not-allowed' : 'bg-slate-700/50 text-slate-300 hover:bg-slate-700']">
              下一页
              <ChevronRight class="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>
