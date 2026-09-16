<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAdminStore } from '@/stores/admin'
import Layout from '@/components/Layout.vue'
import { showToast, confirmDialog } from '@/composables/useGlobalFeedback'
import {
  Shield, BadgeCheck, Check, X, User, Mail, Loader2, Globe, Search,
  Users, Clock, TrendingUp, CheckCheck
} from 'lucide-vue-next'

const supportedDomains = [
  'qq.com', 'foxmail.com', '163.com', '126.com', 'yeah.net',
  'gmail.com', 'outlook.com', 'hotmail.com', 'live.com',
  'sina.com', 'sina.cn', 'sohu.com', 'aliyun.com',
  'icloud.com', 'me.com', 'proton.me', 'protonmail.com',
  'zoho.com', 'yandex.com', 'mail.ru', 'gmx.com', 'gmx.de',
  'web.de', 'orange.fr', 'laposte.net',
  'yahoo.com', 'yahoo.co.jp', 'naver.com', 'daum.net', 'hanmail.net'
]

const presetBadges = ['官方认证', '企业认证', '创作者认证', 'VIP认证', '明星用户']

const adminStore = useAdminStore()
const loading = ref(true)
const activeTab = ref<'pending' | 'verified'>('pending')
const searchKeyword = ref('')
const customBadge = ref('已认证')
const verifyDialogUserId = ref<number | null>(null)
const showBadgeDialog = ref(false)
const copied = ref(false)
const showDomains = ref(true)

const pendingUsers = computed(() =>
  adminStore.users.filter(u => {
    const status = (u.verification_status || '').toLowerCase()
    if (status === 'verified') return false
    return matchSearch(u)
  })
)

const verifiedUsers = computed(() =>
  adminStore.users.filter(u => {
    if (u.verification_status !== 'verified') return false
    return matchSearch(u)
  })
)

function matchSearch(u: any): boolean {
  if (!searchKeyword.value) return true
  const kw = searchKeyword.value.toLowerCase()
  return (u.username || '').toLowerCase().includes(kw)
    || (u.email || '').toLowerCase().includes(kw)
    || (u.user_code || '').toLowerCase().includes(kw)
}

const verifyRate = computed(() => {
  const total = pendingUsers.value.length + verifiedUsers.value.length
  if (!total) return 0
  return (verifiedUsers.value.length / total) * 100
})

function emailDomain(email: string): string {
  if (!email || !email.includes('@')) return '-'
  return email.split('@')[1] || '-'
}

onMounted(async () => {
  loading.value = true
  try { await adminStore.getUsers(0, 200) } catch (e: any) { console.error(e) }
  loading.value = false
})

function openBadgeDialog(userId: number) {
  verifyDialogUserId.value = userId
  customBadge.value = '官方认证'
  showBadgeDialog.value = true
}

function selectPreset(badge: string) {
  customBadge.value = badge
}

async function handleVerifyWithBadge() {
  if (!verifyDialogUserId.value) return
  try {
    await adminStore.verifyUser(verifyDialogUserId.value, customBadge.value.trim() || '已认证')
    await adminStore.getUsers(0, 200)
    showBadgeDialog.value = false
    verifyDialogUserId.value = null
    showToast('认证已通过', 'success')
  } catch (e: any) { showToast('操作失败，请稍后重试', 'error') }
}

async function handleReject(userId: number) {
  if (!await confirmDialog('确定拒绝该用户的认证申请吗？', { confirmText: '确认拒绝' })) return
  try { await adminStore.unverifyUser(userId); await adminStore.getUsers(0, 200); showToast('已拒绝该申请', 'success') } catch (e: any) { showToast('操作失败，请稍后重试', 'error') }
}

async function handleUnverify(userId: number) {
  if (!await confirmDialog('确定取消该用户的认证吗？取消后认证徽章将不再展示。', { confirmText: '取消认证' })) return
  try { await adminStore.unverifyUser(userId); await adminStore.getUsers(0, 200); showToast('已取消认证', 'success') } catch (e: any) { showToast('操作失败，请稍后重试', 'error') }
}

function copyDomain(d: string) {
  try {
    navigator.clipboard?.writeText(d)
    copied.value = true
    setTimeout(() => { copied.value = false }, 1500)
  } catch (e: any) { /* ignore */ }
}

function formatDate(dateStr: string): string {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleDateString('zh-CN')
}
</script>

<template>
  <Layout>
    <div class="p-6 space-y-6">
      <div class="flex items-start justify-between">
        <div>
          <h1 class="text-2xl font-bold text-white flex items-center gap-2">
            <Shield class="w-6 h-6 text-amber-400" />用户认证
          </h1>
          <p class="text-slate-400 mt-2 text-sm">审核用户认证申请、管理认证徽章，支持市面主流邮箱域名</p>
        </div>
      </div>

      <!-- 统计卡片 -->
      <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-amber-500/40 transition-all">
          <div class="flex items-center justify-between mb-3">
            <div class="w-10 h-10 bg-amber-500/20 rounded-xl flex items-center justify-center">
              <Clock class="w-5 h-5 text-amber-400" />
            </div>
          </div>
          <p class="text-2xl font-bold text-white">{{ pendingUsers.length }}</p>
          <p class="text-slate-400 text-sm mt-1">待认证用户</p>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-green-500/40 transition-all">
          <div class="flex items-center justify-between mb-3">
            <div class="w-10 h-10 bg-green-500/20 rounded-xl flex items-center justify-center">
              <BadgeCheck class="w-5 h-5 text-green-400" />
            </div>
          </div>
          <p class="text-2xl font-bold text-white">{{ verifiedUsers.length }}</p>
          <p class="text-slate-400 text-sm mt-1">已认证用户</p>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-blue-500/40 transition-all">
          <div class="flex items-center justify-between mb-3">
            <div class="w-10 h-10 bg-blue-500/20 rounded-xl flex items-center justify-center">
              <TrendingUp class="w-5 h-5 text-blue-400" />
            </div>
          </div>
          <p class="text-2xl font-bold text-white">{{ verifyRate.toFixed(1) }}%</p>
          <p class="text-slate-400 text-sm mt-1">认证通过率</p>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30 hover:border-indigo-500/40 transition-all">
          <div class="flex items-center justify-between mb-3">
            <div class="w-10 h-10 bg-indigo-500/20 rounded-xl flex items-center justify-center">
              <Users class="w-5 h-5 text-indigo-400" />
            </div>
          </div>
          <p class="text-2xl font-bold text-white">{{ adminStore.users.length }}</p>
          <p class="text-slate-400 text-sm mt-1">已加载用户数</p>
        </div>
      </div>

      <!-- 支持的邮箱域名 -->
      <div class="bg-slate-800/50 rounded-xl border border-slate-700/30 p-4">
        <button class="flex items-center gap-2 w-full text-left" @click="showDomains = !showDomains">
          <Globe class="w-4 h-4 text-slate-400" />
          <h3 class="text-slate-400 text-xs font-medium">支持的邮箱域名（{{ supportedDomains.length }}）</h3>
          <span class="text-slate-600 text-xs ml-auto">{{ showDomains ? '收起' : '展开' }}</span>
        </button>
        <div v-if="showDomains" class="flex flex-wrap gap-1.5 mt-3">
          <span v-for="d in supportedDomains" :key="d" @click="copyDomain(d)" title="点击复制"
            class="px-2.5 py-1 bg-slate-700/50 text-slate-300 rounded-md text-xs font-mono cursor-pointer hover:bg-slate-700 hover:text-white transition-colors">
            {{ d }}<CheckCheck v-if="copied" class="w-3 h-3 inline-block ml-1 text-green-400" />
          </span>
        </div>
      </div>

      <!-- Tabs -->
      <div class="flex items-center gap-2 flex-wrap">
        <button @click="activeTab = 'pending'" :class="['px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2',
          activeTab === 'pending' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-slate-800/50 text-slate-400 hover:text-white']">
          <Clock class="w-4 h-4" />待认证
          <span class="px-1.5 py-0.5 rounded text-xs" :class="activeTab === 'pending' ? 'bg-amber-500/30' : 'bg-slate-700'">{{ pendingUsers.length }}</span>
        </button>
        <button @click="activeTab = 'verified'" :class="['px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2',
          activeTab === 'verified' ? 'bg-green-500/20 text-green-400 border border-green-500/30' : 'bg-slate-800/50 text-slate-400 hover:text-white']">
          <BadgeCheck class="w-4 h-4" />已认证
          <span class="px-1.5 py-0.5 rounded text-xs" :class="activeTab === 'verified' ? 'bg-green-500/30' : 'bg-slate-700'">{{ verifiedUsers.length }}</span>
        </button>
        <div class="flex-1"></div>
        <div class="relative">
          <Search class="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
          <input v-model="searchKeyword" type="text" placeholder="搜索用户名 / 邮箱 / 用户码..."
            class="pl-9 pr-3 py-2 bg-slate-800/50 border border-slate-700/30 rounded-lg text-white text-xs w-56 focus:outline-none focus:border-indigo-500" />
        </div>
      </div>

      <div v-if="loading" class="text-center py-16 text-slate-400">
        <Loader2 class="w-8 h-8 animate-spin mx-auto mb-3" />
        <p class="text-sm">正在加载用户数据...</p>
      </div>

      <!-- 待认证 -->
      <div v-else-if="activeTab === 'pending'">
        <div v-if="pendingUsers.length === 0" class="bg-slate-800/50 rounded-2xl border border-slate-700/30 p-14 text-center">
          <div class="w-16 h-16 mx-auto bg-green-500/10 rounded-full flex items-center justify-center mb-4">
            <CheckCheck class="w-8 h-8 text-green-400" />
          </div>
          <p class="text-white font-medium mb-1">没有待认证的用户</p>
          <p class="text-slate-500 text-sm">所有认证申请均已处理完毕</p>
        </div>
        <div v-else class="space-y-3">
          <div v-for="user in pendingUsers" :key="user.id" class="bg-slate-800/50 rounded-xl border border-slate-700/30 p-5 hover:border-amber-500/30 transition-all">
            <div class="flex items-center justify-between gap-4 flex-wrap">
              <div class="flex items-center gap-4 min-w-0">
                <div class="w-12 h-12 rounded-full bg-slate-600 flex items-center justify-center overflow-hidden shrink-0">
                  <img v-if="user.avatar" :src="user.avatar" class="w-full h-full object-cover" />
                  <User v-else class="w-5 h-5 text-slate-300" />
                </div>
                <div class="min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <h3 class="text-white font-medium">{{ user.username }}</h3>
                    <span class="text-slate-500 text-xs font-mono">#{{ user.user_code || '-' }}</span>
                    <span class="px-2 py-0.5 bg-amber-500/15 text-amber-400 rounded text-xs">待认证</span>
                  </div>
                  <div class="flex items-center gap-3 mt-1 text-xs text-slate-400 flex-wrap">
                    <span class="flex items-center gap-1"><Mail class="w-3 h-3" />{{ user.email }}</span>
                    <span class="text-slate-600">|</span>
                    <span class="font-mono">{{ emailDomain(user.email) }}</span>
                    <span class="text-slate-600">|</span>
                    <span>注册于 {{ formatDate(user.created_at) }}</span>
                  </div>
                </div>
              </div>
              <div class="flex items-center gap-2">
                <button @click="openBadgeDialog(user.id)" class="flex items-center gap-1.5 px-4 py-2 bg-green-600/20 text-green-400 rounded-lg hover:bg-green-600/30 transition-all text-sm font-medium">
                  <Check class="w-4 h-4" />通过认证
                </button>
                <button @click="handleReject(user.id)" class="flex items-center gap-1.5 px-4 py-2 bg-red-600/20 text-red-400 rounded-lg hover:bg-red-600/30 transition-all text-sm font-medium">
                  <X class="w-4 h-4" />拒绝
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 已认证 -->
      <div v-else>
        <div v-if="verifiedUsers.length === 0" class="bg-slate-800/50 rounded-2xl border border-slate-700/30 p-14 text-center">
          <div class="w-16 h-16 mx-auto bg-slate-700/50 rounded-full flex items-center justify-center mb-4">
            <BadgeCheck class="w-8 h-8 text-slate-500" />
          </div>
          <p class="text-white font-medium mb-1">还没有已认证的用户</p>
          <p class="text-slate-500 text-sm">在「待认证」中通过审核后，用户会出现在这里</p>
        </div>
        <div v-else class="space-y-3">
          <div v-for="user in verifiedUsers" :key="user.id" class="bg-slate-800/50 rounded-xl border border-slate-700/30 p-5 hover:border-green-500/30 transition-all">
            <div class="flex items-center justify-between gap-4 flex-wrap">
              <div class="flex items-center gap-4 min-w-0">
                <div class="w-12 h-12 rounded-full bg-slate-600 flex items-center justify-center overflow-hidden shrink-0">
                  <img v-if="user.avatar" :src="user.avatar" class="w-full h-full object-cover" />
                  <User v-else class="w-5 h-5 text-slate-300" />
                </div>
                <div class="min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <h3 class="text-white font-medium">{{ user.username }}</h3>
                    <span class="px-1.5 py-0.5 bg-green-500/20 text-green-400 rounded text-xs flex items-center gap-1">
                      <BadgeCheck class="w-3 h-3" />{{ user.verification_badge || '已认证' }}
                    </span>
                    <span v-if="user.role === 'admin'" class="px-1.5 py-0.5 bg-indigo-500/20 text-indigo-300 rounded text-xs">官方</span>
                    <span class="text-slate-500 text-xs font-mono">#{{ user.user_code || '-' }}</span>
                  </div>
                  <div class="flex items-center gap-3 mt-1 text-xs text-slate-400 flex-wrap">
                    <span class="flex items-center gap-1"><Mail class="w-3 h-3" />{{ user.email }}</span>
                    <span class="text-slate-600">|</span>
                    <span>注册于 {{ formatDate(user.created_at) }}</span>
                  </div>
                </div>
              </div>
              <button v-if="user.role !== 'admin'" @click="handleUnverify(user.id)" class="flex items-center gap-1.5 px-4 py-2 bg-yellow-600/20 text-yellow-400 rounded-lg hover:bg-yellow-600/30 transition-all text-sm font-medium">
                <X class="w-4 h-4" />取消认证
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 认证徽章设置弹窗 -->
    <Teleport to="body">
      <div v-if="showBadgeDialog" class="fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/60" @click="showBadgeDialog = false"></div>
        <div class="relative bg-slate-800 rounded-2xl p-6 w-full max-w-md border border-slate-700 shadow-2xl">
          <div class="flex items-center justify-between mb-2">
            <h3 class="text-white font-bold text-lg">认证徽章设置</h3>
            <button @click="showBadgeDialog = false" class="text-slate-500 hover:text-white transition-colors"><X class="w-5 h-5" /></button>
          </div>
          <p class="text-slate-400 text-sm mb-5">选择或自定义认证徽章，将展示在用户名旁</p>

          <div class="flex flex-wrap gap-2 mb-4">
            <button v-for="b in presetBadges" :key="b" @click="selectPreset(b)"
              :class="['px-3 py-1.5 rounded-lg text-xs font-medium transition-all border',
                customBadge === b ? 'bg-green-600/20 text-green-400 border-green-500/40' : 'bg-slate-700/40 text-slate-300 border-slate-700 hover:border-slate-500']">
              {{ b }}
            </button>
          </div>

          <label class="text-slate-400 text-xs block mb-1.5">自定义徽章（最多 12 字）</label>
          <input v-model="customBadge" type="text" maxlength="12" placeholder="例如：官方认证、企业认证、VIP"
            class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-white text-sm focus:outline-none focus:border-indigo-500" />

          <div class="mt-5 bg-slate-900/60 rounded-xl p-4 border border-slate-700/40">
            <p class="text-slate-500 text-xs mb-2">预览效果</p>
            <div class="flex items-center gap-2">
              <span class="text-white text-sm font-medium">用户名</span>
              <span class="px-1.5 py-0.5 bg-green-500/20 text-green-400 rounded text-xs flex items-center gap-1">
                <BadgeCheck class="w-3 h-3" />{{ customBadge.trim() || '已认证' }}
              </span>
            </div>
          </div>

          <div class="flex gap-3 mt-6">
            <button @click="showBadgeDialog = false" class="flex-1 px-4 py-2.5 bg-slate-700/50 text-slate-300 rounded-lg hover:bg-slate-700 transition-all text-sm">取消</button>
            <button @click="handleVerifyWithBadge" class="flex-1 px-4 py-2.5 bg-green-600 text-white rounded-lg hover:bg-green-500 transition-all text-sm font-medium">确认认证</button>
          </div>
        </div>
      </div>
    </Teleport>
  </Layout>
</template>
