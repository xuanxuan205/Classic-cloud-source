<script setup lang="ts">
import { R_ADMIN_APPEALS, R_ADMIN_APPEALS_ID_RESOLVE } from '@/utils/routeCodes'

import { ref, computed, onMounted } from 'vue'
import Layout from '@/components/Layout.vue'
import { request } from '@/utils/axios'
import { showToast } from '@/composables/useGlobalFeedback'
import { Inbox, Check, X, RefreshCw, Loader2, ShieldAlert } from 'lucide-vue-next'

interface Appeal {
  id: string
  ip: string
  contact: string
  reason: string
  status: string
  created_at: string
  resolved_at?: string
  resolution_note?: string
  notified?: boolean
  notification_note?: string
}

type Filter = 'ALL' | 'PENDING' | 'PROCESSED' | 'REJECTED'

const appeals = ref<Appeal[]>([])
const loading = ref(false)
const filter = ref<Filter>('PENDING')
const resolvingId = ref<string | null>(null)
const showModal = ref(false)
const actionId = ref('')
const actionType = ref<'processed' | 'rejected'>('processed')
const actionContact = ref('')
const note = ref('')
const resultMessage = ref('')

const filteredAppeals = computed(() => {
  if (filter.value === 'ALL') return appeals.value
  return appeals.value.filter((item) => item.status === filter.value)
})

const counts = computed(() => ({
  all: appeals.value.length,
  pending: appeals.value.filter((item) => item.status === 'PENDING').length,
  processed: appeals.value.filter((item) => item.status === 'PROCESSED').length,
  rejected: appeals.value.filter((item) => item.status === 'REJECTED').length,
}))

async function loadAppeals() {
  loading.value = true
  try {
    const res = await request<Appeal[]>({ url: R_ADMIN_APPEALS, method: 'GET' })
    if (res.success && res.data) {
      appeals.value = res.data
    } else {
      appeals.value = []
    }
  } catch (e: any) {
    console.error('loadAppeals error:', e)
    appeals.value = []
  } finally {
    loading.value = false
  }
}

function openResolve(item: Appeal, type: 'processed' | 'rejected') {
  actionId.value = item.id
  actionType.value = type
  actionContact.value = item.contact || ''
  note.value = ''
  showModal.value = true
}

function isValidEmail(value: string) {
  return /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}$/.test(value.trim())
}

async function confirmResolve() {
  if (!actionId.value) return
  resolvingId.value = actionId.value
  try {
    const res = await request({
      url: `${R_ADMIN_APPEALS_ID_RESOLVE}/${actionId.value}`,
      method: 'POST',
      data: { decision: actionType.value, note: note.value }
    })
    if (res.success) {
      showModal.value = false
      resultMessage.value = res.message || '处理完成'
      setTimeout(() => { resultMessage.value = '' }, 8000)
      await loadAppeals()
    } else {
      showToast(res.message || '处理失败', 'error')
    }
  } catch (e: any) {
    showToast('处理失败: ' + (e?.message || '网络错误'), 'error')
  } finally {
    resolvingId.value = null
  }
}

function statusText(status: string) {
  if (status === 'PENDING') return '待处理'
  if (status === 'PROCESSED') return '已处理'
  if (status === 'REJECTED') return '已驳回'
  return status
}

function statusClass(status: string) {
  if (status === 'PENDING') return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
  if (status === 'PROCESSED') return 'bg-green-500/10 text-green-400 border-green-500/30'
  if (status === 'REJECTED') return 'bg-red-500/10 text-red-400 border-red-500/30'
  return 'bg-slate-500/10 text-slate-400 border-slate-500/30'
}

onMounted(loadAppeals)
</script>

<template>
  <Layout>
    <div class="p-6 space-y-6">
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold text-white">申诉管理</h1>
          <p class="text-slate-400 mt-2 text-sm">查看被拦截用户提交的申诉。处理后系统会尝试邮件通知申诉人；未填写有效邮箱的申诉无法通知。</p>
        </div>
        <button @click="loadAppeals" :disabled="loading" class="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white rounded-lg text-sm transition-colors">
          <RefreshCw :class="['w-4 h-4', loading ? 'animate-spin' : '']" />刷新
        </button>
      </div>

      <div v-if="resultMessage" class="px-4 py-3 rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 text-sm">
        {{ resultMessage }}
      </div>

      <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
        <button @click="filter = 'ALL'" :class="['rounded-xl border p-4 text-left transition-all', filter === 'ALL' ? 'bg-indigo-600/20 border-indigo-500/40' : 'bg-slate-800/50 border-slate-700/30 hover:border-slate-600']">
          <p class="text-slate-400 text-xs">全部</p>
          <p class="text-white text-2xl font-bold mt-1">{{ counts.all }}</p>
        </button>
        <button @click="filter = 'PENDING'" :class="['rounded-xl border p-4 text-left transition-all', filter === 'PENDING' ? 'bg-indigo-600/20 border-indigo-500/40' : 'bg-slate-800/50 border-slate-700/30 hover:border-slate-600']">
          <p class="text-yellow-400 text-xs">待处理</p>
          <p class="text-white text-2xl font-bold mt-1">{{ counts.pending }}</p>
        </button>
        <button @click="filter = 'PROCESSED'" :class="['rounded-xl border p-4 text-left transition-all', filter === 'PROCESSED' ? 'bg-indigo-600/20 border-indigo-500/40' : 'bg-slate-800/50 border-slate-700/30 hover:border-slate-600']">
          <p class="text-green-400 text-xs">已处理</p>
          <p class="text-white text-2xl font-bold mt-1">{{ counts.processed }}</p>
        </button>
        <button @click="filter = 'REJECTED'" :class="['rounded-xl border p-4 text-left transition-all', filter === 'REJECTED' ? 'bg-indigo-600/20 border-indigo-500/40' : 'bg-slate-800/50 border-slate-700/30 hover:border-slate-600']">
          <p class="text-red-400 text-xs">已驳回</p>
          <p class="text-white text-2xl font-bold mt-1">{{ counts.rejected }}</p>
        </button>
      </div>

      <div v-if="loading" class="text-center py-16 text-slate-400">
        <Loader2 class="w-6 h-6 animate-spin mx-auto mb-2" />加载中...
      </div>

      <div v-else-if="filteredAppeals.length === 0" class="text-center py-16 bg-slate-800/40 rounded-2xl border border-slate-700/30">
        <Inbox class="w-14 h-14 text-slate-600 mx-auto mb-3" />
        <p class="text-slate-400">暂无申诉记录</p>
      </div>

      <div v-else class="space-y-3">
        <div v-for="item in filteredAppeals" :key="item.id" class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30">
          <div class="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
            <div class="min-w-0 flex-1 space-y-2">
              <div class="flex flex-wrap items-center gap-2">
                <span class="text-white font-mono text-xs">{{ item.id }}</span>
                <span :class="['px-2 py-0.5 rounded-full text-xs border', statusClass(item.status)]">{{ statusText(item.status) }}</span>
              </div>
              <div class="grid md:grid-cols-2 gap-2 text-sm">
                <p class="text-slate-400">来源 IP：<span class="text-slate-200">{{ item.ip }}</span></p>
                <p class="text-slate-400">联系方式：<span class="text-slate-200">{{ item.contact || '未填写' }}</span></p>
                <p class="text-slate-400">提交时间：<span class="text-slate-200">{{ item.created_at }}</span></p>
                <p v-if="item.resolved_at" class="text-slate-400">处理时间：<span class="text-slate-200">{{ item.resolved_at }}</span></p>
              </div>
              <div class="bg-slate-900/60 rounded-lg p-3">
                <p class="text-slate-400 text-xs mb-1">申诉说明</p>
                <p class="text-slate-200 text-sm whitespace-pre-wrap">{{ item.reason || '未填写' }}</p>
              </div>
              <div v-if="item.resolution_note" class="bg-slate-900/60 rounded-lg p-3">
                <p class="text-slate-400 text-xs mb-1">处理备注</p>
                <p class="text-slate-200 text-sm whitespace-pre-wrap">{{ item.resolution_note }}</p>
              </div>
              <div v-if="item.notification_note" class="bg-slate-900/60 rounded-lg p-3">
                <p class="text-slate-400 text-xs mb-1">通知状态</p>
                <p class="text-slate-200 text-sm whitespace-pre-wrap">{{ item.notification_note }}</p>
              </div>
            </div>
            <div v-if="item.status === 'PENDING'" class="flex md:flex-col gap-2 shrink-0">
              <button @click="openResolve(item, 'processed')" :disabled="resolvingId === item.id" class="flex items-center justify-center gap-1.5 px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm rounded-lg transition-colors">
                <Check class="w-4 h-4" />已处理
              </button>
              <button @click="openResolve(item, 'rejected')" :disabled="resolvingId === item.id" class="flex items-center justify-center gap-1.5 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white text-sm rounded-lg transition-colors">
                <X class="w-4 h-4" />已驳回
              </button>
            </div>
          </div>
        </div>
      </div>

      <Teleport to="body">
        <div v-if="showModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" @click.self="showModal = false">
          <div class="bg-slate-800 rounded-2xl p-6 w-full max-w-md border border-slate-700/50 shadow-2xl">
            <div class="flex items-center gap-2 mb-4">
              <ShieldAlert class="w-5 h-5" :class="actionType === 'processed' ? 'text-green-400' : 'text-red-400'" />
              <h3 class="text-xl font-bold text-white">{{ actionType === 'processed' ? '标记为已处理' : '标记为已驳回' }}</h3>
            </div>
            <p class="text-slate-400 text-sm mb-2">申诉人联系方式：<span class="text-slate-200">{{ actionContact || '未填写' }}</span></p>
            <p v-if="!isValidEmail(actionContact)" class="text-amber-400 text-sm mb-3">该申诉未填写有效邮箱，处理后将无法邮件通知申诉人。</p>
            <label class="text-slate-400 text-sm block mb-2">处理备注（选填，如有有效邮箱将随结果发送给申诉人）</label>
            <textarea v-model="note" rows="4" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-indigo-500 resize-none" placeholder="例如：已人工复核并放行"></textarea>
            <div class="flex justify-end gap-2 mt-5">
              <button @click="showModal = false" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-sm transition-colors">取消</button>
              <button @click="confirmResolve" :disabled="resolvingId !== null" class="flex items-center gap-1.5 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg text-sm transition-colors">
                <Loader2 v-if="resolvingId !== null" class="w-4 h-4 animate-spin" />{{ isValidEmail(actionContact) ? '确认并通知' : '确认处理（无法邮件通知）' }}
              </button>
            </div>
          </div>
        </div>
      </Teleport>
    </div>
  </Layout>
</template>
