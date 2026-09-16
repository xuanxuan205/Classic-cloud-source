<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useAdminStore } from '@/stores/admin'
import Layout from '@/components/Layout.vue'
import { showToast } from '@/composables/useGlobalFeedback'
import {
  Users, Search, ShieldCheck, Mail, Crown, User, Loader2, Ban, CheckCircle,
  ShieldBan, Trash2, AlertTriangle, BadgeCheck, HardDrive, CloudUpload
} from 'lucide-vue-next'

const adminStore = useAdminStore()
const loading = ref(true)
const searchKeyword = ref('')
const statusFilter = ref<'all' | 'active' | 'banned'>('all')

const showBanModal = ref(false)
const showUnbanModal = ref(false)
const showDeleteModal = ref(false)
const targetUser = ref<any>(null)
const acting = ref(false)
let searchTimer: ReturnType<typeof setTimeout> | null = null

const filteredUsers = computed(() => {
  let result = adminStore.users
  if (statusFilter.value !== 'all') {
    result = result.filter(u => u.user_status === statusFilter.value)
  }
  return result
})

const statusCounts = computed(() => ({
  all: adminStore.users.length,
  active: adminStore.users.filter(u => u.user_status === 'active').length,
  banned: adminStore.users.filter(u => u.user_status === 'banned').length,
  unverified: adminStore.users.filter(u => u.verification_status === 'unverified').length
}))

function storagePercent(u: any): number {
  const used = u.storage_used || 0
  const limit = u.storage_limit || 0
  if (!limit) return 0
  return Math.min(Math.round((used / limit) * 100), 100)
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

function statusLabel(s: string): string {
  return s === 'active' ? '正常' : s === 'banned' ? '封禁' : '禁用'
}

async function loadUsers(keyword: string) {
  loading.value = true
  try { await adminStore.getUsers(0, 50, keyword.trim()) } catch (e: any) { console.error(e) }
  loading.value = false
}

watch(searchKeyword, () => {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(() => loadUsers(searchKeyword.value), 300)
})

onMounted(async () => {
  await loadUsers('')
})

async function handleVerify(userId: number) {
  await adminStore.verifyUser(userId)
  await loadUsers(searchKeyword.value)
}

async function handleUnverify(userId: number) {
  await adminStore.unverifyUser(userId)
  await loadUsers(searchKeyword.value)
}

function askBan(user: any) { targetUser.value = user; showBanModal.value = true }
function askUnban(user: any) { targetUser.value = user; showUnbanModal.value = true }
function askDelete(user: any) { targetUser.value = user; showDeleteModal.value = true }

async function confirmBan() {
  if (!targetUser.value) return
  acting.value = true
  try {
    await adminStore.banUser(targetUser.value.id)
    await loadUsers(searchKeyword.value)
    showBanModal.value = false
    targetUser.value = null
    showToast('用户已封禁', 'success')
  } catch (e: any) { showToast('操作失败，请稍后重试', 'error') }
  acting.value = false
}

async function confirmUnban() {
  if (!targetUser.value) return
  acting.value = true
  try {
    await adminStore.unbanUser(targetUser.value.id)
    await loadUsers(searchKeyword.value)
    showUnbanModal.value = false
    targetUser.value = null
    showToast('已解除封禁', 'success')
  } catch (e: any) { showToast('操作失败，请稍后重试', 'error') }
  acting.value = false
}

async function confirmDelete() {
  if (!targetUser.value) return
  acting.value = true
  try {
    await adminStore.deleteUser(targetUser.value.id)
    await loadUsers(searchKeyword.value)
    showDeleteModal.value = false
    targetUser.value = null
    showToast('用户已删除', 'success')
  } catch (e: any) { showToast('操作失败，请稍后重试', 'error') }
  acting.value = false
}
</script>

<template>
  <Layout>
    <div class="p-6 space-y-6">
      <div class="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 class="text-2xl font-bold text-white flex items-center gap-2">
            <Users class="w-6 h-6 text-blue-400" />用户管理
          </h1>
          <p class="text-slate-400 mt-2 text-sm">管理系统中的所有注册用户，封禁后将邮件通知用户</p>
        </div>
      </div>

      <!-- 统计卡片 -->
      <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-blue-500/40 transition-all">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-blue-500/20 rounded-xl flex items-center justify-center"><Users class="w-5 h-5 text-blue-400" /></div>
            <div>
              <p class="text-2xl font-bold text-white">{{ statusCounts.all }}</p>
              <p class="text-slate-400 text-xs">全部用户</p>
            </div>
          </div>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-green-500/40 transition-all">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-green-500/20 rounded-xl flex items-center justify-center"><CheckCircle class="w-5 h-5 text-green-400" /></div>
            <div>
              <p class="text-2xl font-bold text-white">{{ statusCounts.active }}</p>
              <p class="text-slate-400 text-xs">正常用户</p>
            </div>
          </div>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-red-500/40 transition-all">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-red-500/20 rounded-xl flex items-center justify-center"><Ban class="w-5 h-5 text-red-400" /></div>
            <div>
              <p class="text-2xl font-bold text-white">{{ statusCounts.banned }}</p>
              <p class="text-slate-400 text-xs">封禁用户</p>
            </div>
          </div>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-amber-500/40 transition-all">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-amber-500/20 rounded-xl flex items-center justify-center"><ShieldCheck class="w-5 h-5 text-amber-400" /></div>
            <div>
              <p class="text-2xl font-bold text-white">{{ statusCounts.unverified }}</p>
              <p class="text-slate-400 text-xs">待认证用户</p>
            </div>
          </div>
        </div>
      </div>

      <!-- 筛选工具栏 -->
      <div class="bg-slate-800/50 rounded-xl border border-slate-700/30 p-4">
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div class="relative">
            <Search class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input v-model="searchKeyword" type="text" placeholder="搜索用户名 / 邮箱 / 用户码..."
              class="pl-10 pr-4 py-2 bg-slate-700/50 border border-slate-600/30 rounded-lg text-white text-sm placeholder-slate-400 focus:outline-none focus:border-blue-500 w-72" />
          </div>
          <div class="flex items-center gap-2 flex-wrap">
            <button v-for="s in [{ value: 'all', label: '全部' }, { value: 'active', label: '正常' }, { value: 'banned', label: '封禁' }]" :key="s.value"
              @click="statusFilter = s.value as 'all' | 'active' | 'banned'"
              :class="['px-3 py-2 rounded-lg text-sm font-medium transition-all border',
                statusFilter === s.value ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' : 'bg-slate-700/30 text-slate-300 hover:bg-slate-700/50 border-transparent']">
              {{ s.label }} ({{ statusCounts[s.value as keyof typeof statusCounts] }})
            </button>
          </div>
        </div>
      </div>

      <div v-if="loading" class="text-center py-16 text-slate-400">
        <Loader2 class="w-8 h-8 animate-spin mx-auto mb-3" />
        <p class="text-sm">正在加载用户数据...</p>
      </div>

      <div v-else class="bg-slate-800/50 rounded-xl border border-slate-700/30 overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full min-w-[960px]">
            <thead>
              <tr class="border-b border-slate-700/50 bg-slate-800/80">
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">用户</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">角色</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">状态</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">存储用量</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">上传限额</th>
                <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">注册时间</th>
                <th class="text-right px-4 py-3 text-xs text-slate-500 font-medium">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="user in filteredUsers" :key="user.id" :class="['border-b border-slate-700/20 hover:bg-slate-700/30 transition-colors', user.user_status === 'banned' ? 'bg-red-900/10' : '']">
                <td class="px-4 py-3">
                  <div class="flex items-center gap-3">
                    <div class="w-10 h-10 rounded-full flex items-center justify-center overflow-hidden shrink-0 relative" :class="!user.avatar ? (user.role === 'admin' ? 'bg-amber-600' : 'bg-slate-600') : ''">
                      <img v-if="user.avatar" :src="user.avatar" class="w-full h-full object-cover" @error="($event.target as HTMLImageElement)?.style && (($event.target as HTMLImageElement).style.display='none')" />
                      <Crown v-if="!user.avatar && user.role === 'admin'" class="w-4 h-4 text-white" />
                      <User v-if="!user.avatar && user.role !== 'admin'" class="w-4 h-4 text-white" />
                    </div>
                    <div class="min-w-0">
                      <div class="flex items-center gap-2">
                        <p class="text-white text-sm font-medium truncate">{{ user.username }}</p>
                        <span v-if="user.verification_status === 'verified'" class="px-1.5 py-0.5 bg-green-500/20 text-green-400 rounded text-xs flex items-center gap-0.5">
                          <BadgeCheck class="w-3 h-3" />{{ user.verification_badge || '已认证' }}
                        </span>
                      </div>
                      <div class="flex items-center gap-2 text-xs text-slate-500 mt-0.5">
                        <Mail class="w-3 h-3 flex-shrink-0" />
                        <span class="truncate">{{ user.email }}</span>
                        <span class="text-slate-600 font-mono">ID: {{ user.user_code || user.id }}</span>
                      </div>
                    </div>
                  </div>
                </td>
                <td class="px-4 py-3">
                  <span :class="['px-2 py-0.5 text-xs rounded-full', user.role === 'admin' ? 'bg-amber-500/20 text-amber-400' : 'bg-blue-500/20 text-blue-400']">
                    {{ user.role === 'admin' ? '管理员' : '用户' }}
                  </span>
                </td>
                <td class="px-4 py-3">
                  <span :class="['px-2 py-0.5 text-xs rounded-full flex items-center gap-1 w-fit',
                    user.user_status === 'active' ? 'bg-green-500/20 text-green-400'
                    : user.user_status === 'banned' ? 'bg-red-500/20 text-red-400'
                    : 'bg-slate-500/20 text-slate-400']">
                    <span class="w-1.5 h-1.5 rounded-full" :class="user.user_status === 'active' ? 'bg-green-400' : user.user_status === 'banned' ? 'bg-red-400' : 'bg-slate-400'"></span>
                    {{ statusLabel(user.user_status) }}
                  </span>
                </td>
                <td class="px-4 py-3">
                  <div class="flex items-center gap-2 min-w-[140px]">
                    <HardDrive class="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
                    <div class="flex-1">
                      <div class="flex items-center justify-between text-xs mb-1">
                        <span class="text-slate-400">{{ formatBytes(user.storage_used || 0) }}</span>
                        <span class="text-slate-600">/ {{ formatBytes(user.storage_limit || 0) }}</span>
                      </div>
                      <div class="h-1.5 bg-slate-700/40 rounded-full overflow-hidden">
                        <div :class="storagePercent(user) > 90 ? 'bg-gradient-to-r from-red-500 to-orange-500' : 'bg-gradient-to-r from-blue-500 to-cyan-500'"
                          class="h-full rounded-full transition-all" :style="{ width: storagePercent(user) + '%' }"></div>
                      </div>
                    </div>
                  </div>
                </td>
                <td class="px-4 py-3">
                  <span class="text-slate-400 text-sm flex items-center gap-1.5">
                    <CloudUpload class="w-3.5 h-3.5 text-slate-500" />{{ user.upload_limit ?? '-' }}
                  </span>
                </td>
                <td class="px-4 py-3 text-sm text-slate-500">{{ formatDate(user.created_at) }}</td>
                <td class="px-4 py-3">
                  <div class="flex items-center justify-end gap-1.5 flex-wrap">
                    <button v-if="user.verification_status === 'unverified'" @click="handleVerify(user.id)" title="通过认证"
                      class="px-2.5 py-1.5 bg-green-600/20 text-green-400 rounded-lg hover:bg-green-600/30 text-xs transition-colors flex items-center gap-1">
                      <ShieldCheck class="w-3.5 h-3.5" />认证
                    </button>
                    <button v-if="user.verification_status === 'verified'" @click="handleUnverify(user.id)" title="取消认证"
                      class="px-2.5 py-1.5 bg-yellow-600/20 text-yellow-400 rounded-lg hover:bg-yellow-600/30 text-xs transition-colors flex items-center gap-1">
                      <ShieldBan class="w-3.5 h-3.5" />取消
                    </button>
                    <button v-if="user.user_status !== 'banned'" @click="askBan(user)" title="封禁该用户"
                      class="px-2.5 py-1.5 bg-orange-600/20 text-orange-400 rounded-lg hover:bg-orange-600/30 text-xs transition-colors flex items-center gap-1">
                      <Ban class="w-3.5 h-3.5" />封禁
                    </button>
                    <button v-if="user.user_status === 'banned'" @click="askUnban(user)" title="解封该用户"
                      class="px-2.5 py-1.5 bg-emerald-600/20 text-emerald-400 rounded-lg hover:bg-emerald-600/30 text-xs transition-colors flex items-center gap-1">
                      <CheckCircle class="w-3.5 h-3.5" />解封
                    </button>
                    <button @click="askDelete(user)" title="删除该用户"
                      class="px-2.5 py-1.5 bg-red-600/20 text-red-400 rounded-lg hover:bg-red-600/30 text-xs transition-colors flex items-center gap-1">
                      <Trash2 class="w-3.5 h-3.5" />
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="filteredUsers.length === 0">
                <td colspan="7" class="text-center py-16">
                  <Users class="w-12 h-12 text-slate-600 mx-auto mb-3" />
                  <p class="text-slate-400">暂无符合条件的用户</p>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- 封禁确认 -->
    <Teleport to="body">
      <div v-if="showBanModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" @click.self="showBanModal = false">
        <div class="bg-slate-800 rounded-2xl w-full max-w-md border border-slate-700/50 shadow-2xl p-6">
          <div class="w-12 h-12 mx-auto bg-orange-500/15 rounded-full flex items-center justify-center mb-4">
            <Ban class="w-6 h-6 text-orange-400" />
          </div>
          <h3 class="text-white font-bold text-lg text-center mb-2">封禁用户</h3>
          <p class="text-slate-400 text-sm text-center mb-5">
            确定封禁「{{ targetUser?.username }}」吗？<br />封禁后该用户将无法登录和使用服务，同时系统会向其注册邮箱发送封禁通知邮件。
          </p>
          <div class="flex gap-3">
            <button @click="showBanModal = false" class="flex-1 px-4 py-2.5 bg-slate-700/50 text-slate-300 rounded-lg hover:bg-slate-700 transition-all text-sm">取消</button>
            <button @click="confirmBan" :disabled="acting" class="flex-1 px-4 py-2.5 bg-orange-600 text-white rounded-lg hover:bg-orange-500 disabled:opacity-50 transition-all text-sm font-medium flex items-center justify-center gap-2">
              <Loader2 v-if="acting" class="w-4 h-4 animate-spin" />确认封禁
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- 解封确认 -->
    <Teleport to="body">
      <div v-if="showUnbanModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" @click.self="showUnbanModal = false">
        <div class="bg-slate-800 rounded-2xl w-full max-w-md border border-slate-700/50 shadow-2xl p-6">
          <div class="w-12 h-12 mx-auto bg-emerald-500/15 rounded-full flex items-center justify-center mb-4">
            <CheckCircle class="w-6 h-6 text-emerald-400" />
          </div>
          <h3 class="text-white font-bold text-lg text-center mb-2">解封用户</h3>
          <p class="text-slate-400 text-sm text-center mb-5">
            确定解封「{{ targetUser?.username }}」吗？<br />解封后该用户可正常登录，同时系统会向其注册邮箱发送解封通知邮件。
          </p>
          <div class="flex gap-3">
            <button @click="showUnbanModal = false" class="flex-1 px-4 py-2.5 bg-slate-700/50 text-slate-300 rounded-lg hover:bg-slate-700 transition-all text-sm">取消</button>
            <button @click="confirmUnban" :disabled="acting" class="flex-1 px-4 py-2.5 bg-emerald-600 text-white rounded-lg hover:bg-emerald-500 disabled:opacity-50 transition-all text-sm font-medium flex items-center justify-center gap-2">
              <Loader2 v-if="acting" class="w-4 h-4 animate-spin" />确认解封
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- 删除确认 -->
    <Teleport to="body">
      <div v-if="showDeleteModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" @click.self="showDeleteModal = false">
        <div class="bg-slate-800 rounded-2xl w-full max-w-md border border-slate-700/50 shadow-2xl p-6">
          <div class="w-12 h-12 mx-auto bg-red-500/15 rounded-full flex items-center justify-center mb-4">
            <AlertTriangle class="w-6 h-6 text-red-400" />
          </div>
          <h3 class="text-white font-bold text-lg text-center mb-2">删除用户</h3>
          <p class="text-slate-400 text-sm text-center mb-5">
            确定删除「{{ targetUser?.username }}」吗？<br />此操作不可恢复，该用户的所有数据将被一并清除。
          </p>
          <div class="flex gap-3">
            <button @click="showDeleteModal = false" class="flex-1 px-4 py-2.5 bg-slate-700/50 text-slate-300 rounded-lg hover:bg-slate-700 transition-all text-sm">取消</button>
            <button @click="confirmDelete" :disabled="acting" class="flex-1 px-4 py-2.5 bg-red-600 text-white rounded-lg hover:bg-red-500 disabled:opacity-50 transition-all text-sm font-medium flex items-center justify-center gap-2">
              <Loader2 v-if="acting" class="w-4 h-4 animate-spin" />确认删除
            </button>
          </div>
        </div>
      </div>
    </Teleport>
  </Layout>
</template>
