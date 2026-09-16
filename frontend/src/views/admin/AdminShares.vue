<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useAdminStore } from '@/stores/admin'
import Layout from '@/components/Layout.vue'
import { showToast } from '@/composables/useGlobalFeedback'
import {
  Share2, Search, Copy, Trash2, Ban, Unlock, User, Calendar, Eye,
  Check, Loader2, Link2, AlertTriangle, FolderOpen, FileText, ExternalLink
} from 'lucide-vue-next'

const adminStore = useAdminStore()
const loading = ref(true)
const searchKeyword = ref('')
const statusFilter = ref<'all' | 'active' | 'banned' | 'invalid' | 'deleted'>('all')
const copiedId = ref<number | null>(null)
const showBanModal = ref(false)
const showDeleteModal = ref(false)
const targetShare = ref<any>(null)
const acting = ref(false)
let searchTimer: ReturnType<typeof setTimeout> | null = null

const filteredShares = computed(() => {
  let result = adminStore.shares
  if (statusFilter.value === 'active') result = result.filter(s => s.status === 1)
  else if (statusFilter.value === 'banned') result = result.filter(s => s.status === -2)
  else if (statusFilter.value === 'invalid') result = result.filter(s => s.status === 0)
  else if (statusFilter.value === 'deleted') result = result.filter(s => s.status === -1)
  return result
})

const statusCounts = computed(() => ({
  all: adminStore.shares.length,
  active: adminStore.shares.filter(s => s.status === 1).length,
  banned: adminStore.shares.filter(s => s.status === -2).length,
  invalid: adminStore.shares.filter(s => s.status === 0).length,
  deleted: adminStore.shares.filter(s => s.status === -1).length
}))

function statusLabel(s: number): string {
  if (s === 1) return '正常'
  if (s === -2) return '已封禁'
  if (s === -1) return '已删除'
  return '已失效'
}

function statusClass(s: number): string {
  if (s === 1) return 'bg-green-500/20 text-green-400'
  if (s === -2) return 'bg-red-500/20 text-red-400'
  if (s === -1) return 'bg-slate-500/20 text-slate-400'
  return 'bg-yellow-500/20 text-yellow-400'
}

function fullUrl(code: string): string {
  return `${location.origin}/share/${code}`
}

async function loadShares(keyword: string) {
  loading.value = true
  try { await adminStore.getShares(0, 50, keyword.trim()) } catch (e: any) { console.error(e) }
  loading.value = false
}

watch(searchKeyword, () => {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(() => loadShares(searchKeyword.value), 300)
})

onMounted(async () => {
  await loadShares('')
})

async function copyText(id: number, text: string) {
  try {
    await navigator.clipboard.writeText(text)
    copiedId.value = id
    setTimeout(() => copiedId.value = null, 2000)
  } catch { /* ignore */ }
}

function askBan(share: any) { targetShare.value = share; showBanModal.value = true }
function askDelete(share: any) { targetShare.value = share; showDeleteModal.value = true }

async function confirmBan() {
  if (!targetShare.value) return
  acting.value = true
  try {
    await adminStore.updateShareStatus(targetShare.value.id, -2)
    await loadShares(searchKeyword.value)
    showBanModal.value = false
    targetShare.value = null
    showToast('分享已封禁', 'success')
  } catch (e: any) { showToast('操作失败，请稍后重试', 'error') }
  acting.value = false
}

async function confirmDelete() {
  if (!targetShare.value) return
  acting.value = true
  try {
    await adminStore.updateShareStatus(targetShare.value.id, -1)
    await loadShares(searchKeyword.value)
    showDeleteModal.value = false
    targetShare.value = null
    showToast('分享已删除', 'success')
  } catch (e: any) { showToast('操作失败，请稍后重试', 'error') }
  acting.value = false
}

async function handleUnban(shareId: number) {
  try {
    await adminStore.updateShareStatus(shareId, 1)
    await loadShares(searchKeyword.value)
    showToast('已解除封禁', 'success')
  } catch (e: any) { showToast('操作失败，请稍后重试', 'error') }
}

function formatDate(dateStr: string): string {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleString('zh-CN', { hour12: false })
}
</script>

<template>
  <Layout>
    <div class="p-6 space-y-6">
      <div>
        <h1 class="text-2xl font-bold text-white flex items-center gap-2">
          <Share2 class="w-6 h-6 text-pink-400" />分享管理
        </h1>
        <p class="text-slate-400 mt-2 text-sm">管理所有文件分享链接和权限，封禁后访问者将看到违规封禁提示页</p>
      </div>

      <!-- 统计卡片 -->
      <div class="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-4">
        <div class="bg-slate-800/60 rounded-2xl p-4 border border-slate-700/30">
          <p class="text-2xl font-bold text-white">{{ statusCounts.all }}</p>
          <p class="text-slate-400 text-xs mt-1">全部分享</p>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-4 border border-slate-700/30">
          <p class="text-2xl font-bold text-green-400">{{ statusCounts.active }}</p>
          <p class="text-slate-400 text-xs mt-1">正常</p>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-4 border border-slate-700/30">
          <p class="text-2xl font-bold text-red-400">{{ statusCounts.banned }}</p>
          <p class="text-slate-400 text-xs mt-1">已封禁</p>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-4 border border-slate-700/30">
          <p class="text-2xl font-bold text-yellow-400">{{ statusCounts.invalid }}</p>
          <p class="text-slate-400 text-xs mt-1">已失效</p>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-4 border border-slate-700/30">
          <p class="text-2xl font-bold text-slate-400">{{ statusCounts.deleted }}</p>
          <p class="text-slate-400 text-xs mt-1">已删除</p>
        </div>
      </div>

      <!-- 筛选工具栏 -->
      <div class="bg-slate-800/50 rounded-xl border border-slate-700/30 p-4">
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div class="relative">
            <Search class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input v-model="searchKeyword" type="text" placeholder="搜索分享码 / 用户名 / 用户ID..."
              class="pl-10 pr-4 py-2 bg-slate-700/50 border border-slate-600/30 rounded-lg text-white text-sm placeholder-slate-400 focus:outline-none focus:border-blue-500 w-72" />
          </div>
          <div class="flex items-center gap-2 flex-wrap">
            <button v-for="s in [{ value: 'all', label: '全部' }, { value: 'active', label: '正常' }, { value: 'banned', label: '已封禁' }, { value: 'invalid', label: '已失效' }, { value: 'deleted', label: '已删除' }]" :key="s.value"
              @click="statusFilter = s.value as any"
              :class="['px-3 py-2 rounded-lg text-sm font-medium transition-all border',
                statusFilter === s.value ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' : 'bg-slate-700/30 text-slate-300 hover:bg-slate-700/50 border-transparent']">
              {{ s.label }} ({{ statusCounts[s.value as keyof typeof statusCounts] }})
            </button>
          </div>
        </div>
      </div>

      <div v-if="loading" class="text-center py-16 text-slate-400">
        <Loader2 class="w-8 h-8 animate-spin mx-auto mb-3" />
        <p class="text-sm">正在加载分享数据...</p>
      </div>

      <div v-else class="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div v-for="share in filteredShares" :key="share.id" :class="['rounded-2xl border transition-all overflow-hidden',
          share.status === -2 ? 'bg-red-900/10 border-red-500/30' : share.status === 1 ? 'bg-slate-800/60 border-slate-700/30 hover:border-slate-500/50' : 'bg-slate-800/40 border-slate-700/30']">
          <div class="p-5">
            <div class="flex items-start justify-between gap-3 mb-4">
              <div class="flex items-center gap-3 min-w-0">
                <div class="w-11 h-11 bg-gradient-to-br from-pink-500 to-purple-500 rounded-xl flex items-center justify-center flex-shrink-0">
                  <FolderOpen v-if="share.share_type === 2" class="w-5 h-5 text-white" />
                  <FileText v-else class="w-5 h-5 text-white" />
                </div>
                <div class="min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <code class="text-sm text-blue-400 font-mono bg-slate-700/50 px-2 py-1 rounded">{{ share.share_code }}</code>
                    <span :class="['px-2 py-0.5 text-xs rounded-full flex items-center gap-1 w-fit', statusClass(share.status)]">
                      <span class="w-1.5 h-1.5 rounded-full" :class="share.status === 1 ? 'bg-green-400' : share.status === -2 ? 'bg-red-400' : share.status === -1 ? 'bg-slate-400' : 'bg-yellow-400'"></span>
                      {{ statusLabel(share.status) }}
                    </span>
                  </div>
                  <p class="text-slate-500 text-xs mt-1">分享ID: {{ share.id }} · {{ share.share_type === 2 ? '文件夹分享' : '文件分享' }}</p>
                </div>
              </div>
              <a :href="fullUrl(share.share_code)" target="_blank" rel="noopener noreferrer" title="打开分享页"
                class="p-2 text-slate-400 hover:text-blue-400 hover:bg-slate-700/50 rounded-lg transition-colors flex-shrink-0">
                <ExternalLink class="w-4 h-4" />
              </a>
            </div>

            <div class="grid grid-cols-2 gap-3 mb-4">
              <div class="bg-slate-700/30 rounded-lg p-3">
                <div class="flex items-center gap-2 text-slate-400 text-xs"><User class="w-3.5 h-3.5 flex-shrink-0" /><span>用户: <span class="text-white font-mono">{{ share.username || "未知用户" }}</span> <span class="text-slate-500">(ID: {{ share.user_code || share.user_id || "-" }})</span></span></div>
              </div>
              <div class="bg-slate-700/30 rounded-lg p-3">
                <div class="flex items-center gap-2 text-slate-400 text-xs"><Eye class="w-3.5 h-3.5 flex-shrink-0" /><span>下载 {{ share.download_count || 0 }}/{{ share.download_limit == null || share.download_limit < 0 ? '∞' : share.download_limit }} 次</span></div>
              </div>
              <div class="bg-slate-700/30 rounded-lg p-3 col-span-2">
                <div class="flex items-center gap-2 text-slate-400 text-xs"><Calendar class="w-3.5 h-3.5 flex-shrink-0" /><span>创建于 {{ formatDate(share.created_at) }}</span></div>
              </div>
            </div>

            <div class="flex items-center gap-2">
              <button @click="copyText(share.id, fullUrl(share.share_code))" class="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 bg-blue-500/20 text-blue-400 rounded-lg hover:bg-blue-500/30 transition-all text-xs">
                <Check v-if="copiedId === share.id" class="w-3.5 h-3.5" /><Copy v-else class="w-3.5 h-3.5" />{{ copiedId === share.id ? '已复制' : '复制链接' }}
              </button>
              <button v-if="share.status === 1" @click="askBan(share)" class="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30 transition-all text-xs">
                <Ban class="w-3.5 h-3.5" />封禁
              </button>
              <button v-if="share.status !== 1" @click="handleUnban(share.id)" class="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 bg-green-500/20 text-green-400 rounded-lg hover:bg-green-500/30 transition-all text-xs">
                <Unlock class="w-3.5 h-3.5" />恢复
              </button>
              <button @click="askDelete(share)" class="flex items-center justify-center gap-1.5 px-3 py-2 bg-slate-700/30 text-slate-400 rounded-lg hover:bg-slate-700/50 transition-all text-xs">
                <Trash2 class="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        <div v-if="filteredShares.length === 0" class="col-span-full text-center py-16">
          <Share2 class="w-12 h-12 text-slate-600 mx-auto mb-3" />
          <p class="text-slate-400">暂无分享链接</p>
        </div>
      </div>
    </div>

    <!-- 封禁确认 -->
    <Teleport to="body">
      <div v-if="showBanModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" @click.self="showBanModal = false">
        <div class="bg-slate-800 rounded-2xl w-full max-w-md border border-slate-700/50 shadow-2xl p-6">
          <div class="w-12 h-12 mx-auto bg-red-500/15 rounded-full flex items-center justify-center mb-4">
            <Ban class="w-6 h-6 text-red-400" />
          </div>
          <h3 class="text-white font-bold text-lg text-center mb-2">封禁分享链接</h3>
          <p class="text-slate-400 text-sm text-center mb-5">
            确定封禁分享码「{{ targetShare?.share_code }}」吗？<br />
            封禁后，访问者打开链接将看到「该分享因违规行为已被封禁」的专属提示页，无法再下载内容。
          </p>
          <div class="flex gap-3">
            <button @click="showBanModal = false" class="flex-1 px-4 py-2.5 bg-slate-700/50 text-slate-300 rounded-lg hover:bg-slate-700 transition-all text-sm">取消</button>
            <button @click="confirmBan" :disabled="acting" class="flex-1 px-4 py-2.5 bg-red-600 text-white rounded-lg hover:bg-red-500 disabled:opacity-50 transition-all text-sm font-medium flex items-center justify-center gap-2">
              <Loader2 v-if="acting" class="w-4 h-4 animate-spin" />确认封禁
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- 删除确认 -->
    <Teleport to="body">
      <div v-if="showDeleteModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" @click.self="showDeleteModal = false">
        <div class="bg-slate-800 rounded-2xl w-full max-w-md border border-slate-700/50 shadow-2xl p-6">
          <div class="w-12 h-12 mx-auto bg-slate-500/15 rounded-full flex items-center justify-center mb-4">
            <AlertTriangle class="w-6 h-6 text-slate-400" />
          </div>
          <h3 class="text-white font-bold text-lg text-center mb-2">删除分享链接</h3>
          <p class="text-slate-400 text-sm text-center mb-5">
            确定删除分享码「{{ targetShare?.share_code }}」吗？<br />删除后访问者打开链接将提示分享已失效，操作可随时通过「恢复」找回。
          </p>
          <div class="flex gap-3">
            <button @click="showDeleteModal = false" class="flex-1 px-4 py-2.5 bg-slate-700/50 text-slate-300 rounded-lg hover:bg-slate-700 transition-all text-sm">取消</button>
            <button @click="confirmDelete" :disabled="acting" class="flex-1 px-4 py-2.5 bg-slate-600 text-white rounded-lg hover:bg-slate-500 disabled:opacity-50 transition-all text-sm font-medium flex items-center justify-center gap-2">
              <Loader2 v-if="acting" class="w-4 h-4 animate-spin" />确认删除
            </button>
          </div>
        </div>
      </div>
    </Teleport>
  </Layout>
</template>
