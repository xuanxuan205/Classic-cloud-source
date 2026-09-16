<script setup lang="ts">
import { R_AUTH_ANNOUNCEMENTS } from '@/utils/routeCodes'

import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useFilesStore } from '@/stores/files'
import { useSharesStore } from '@/stores/shares'
import { useAuthStore } from '@/stores/auth'
import { request } from '@/utils/axios'
import { announcementToHtml, stripMarkdown } from '@/utils/text'
import { showBrowserNotify } from '@/utils/browserNotify'
import Layout from '@/components/Layout.vue'
import { Cloud, FileText, Share2, Zap, Clock, Bell, X, Megaphone, ChevronDown, ChevronUp, ChevronLeft, ChevronRight, Pin } from 'lucide-vue-next'

const filesStore = useFilesStore()
const sharesStore = useSharesStore()
const authStore = useAuthStore()

const recentFiles = ref<any[]>([])
const recentShares = ref<any[]>([])
const storageUsed = ref(0)
const storageLimit = ref(0)
const fileCount = ref(0)
const shareCount = ref(0)
const isLoading = ref(true)
const announcements = ref<any[]>([])
const showAllAnnouncements = ref(false)
const popupList = ref<any[]>([])
const popupIndex = ref(0)
const readIds = ref<Set<number>>(new Set())
let announceTimer: ReturnType<typeof setInterval> | null = null

const unreadCount = computed(() => announcements.value.filter(a => !readIds.value.has(Number(a.id))).length)

onMounted(async () => {
  try {
    const [storageRes, filesRes, sharesRes] = await Promise.all([
      filesStore.getStorageStats(),
      filesStore.getFiles(0, 0, 4),
      sharesStore.getShares(0, 4)
    ])
    
    recentFiles.value = filesStore.files.slice(0, 4)
    recentShares.value = sharesStore.shares.slice(0, 4)
    
    if (storageRes.success && storageRes.data) {
      storageUsed.value = (storageRes.data as any).used || 0
      storageLimit.value = (storageRes.data as any).limit || 0
    }
    if (filesRes.success && (filesRes as any).data) {
      fileCount.value = (filesRes as any).data.totalElements || 0
    }
    if (sharesRes.success && (sharesRes as any).data) {
      shareCount.value = (sharesRes as any).data.totalElements || 0
    }
  } catch (e) {
    console.error('Dashboard load error:', e)
  }
  isLoading.value = false
  
  // Fetch announcements (fixed panel + auto popup)
  loadReadIds()
  await loadAnnouncements()
  announceTimer = setInterval(() => {
    if (document.visibilityState === 'visible') loadAnnouncements()
  }, 60000)
})

onUnmounted(() => {
  if (announceTimer) clearInterval(announceTimer)
})

const LAST_SEEN_ANNOUNCEMENT_KEY = 'jdy_last_seen_announcement_id'
const READ_IDS_KEY = 'jdy_read_announcement_ids'

function loadReadIds() {
  try {
    const raw = localStorage.getItem(READ_IDS_KEY)
    if (!raw) return
    const arr = JSON.parse(raw)
    if (Array.isArray(arr)) readIds.value = new Set(arr.map((n: any) => Number(n)).filter((n: number) => !Number.isNaN(n)))
  } catch (e) { /* ignore */ }
}

function persistReadIds() {
  try { localStorage.setItem(READ_IDS_KEY, JSON.stringify([...readIds.value])) } catch (e) { /* ignore */ }
}

function markRead(ids: number[]) {
  if (!ids.length) return
  ids.forEach(id => readIds.value.add(id))
  persistReadIds()
}

async function loadAnnouncements() {
  try {
    const res = await request<any[]>({ url: R_AUTH_ANNOUNCEMENTS, method: 'GET' })
    if (!res.success || !res.data) return
    announcements.value = res.data
    checkNewAnnouncementPopup(res.data)
  } catch (e) { /* silent */ }
}

function checkNewAnnouncementPopup(list: any[]) {
  if (!list || list.length === 0) return
  const maxId = list.reduce((max, a) => Math.max(max, Number(a.id) || 0), 0)
  const lastSeen = Number(localStorage.getItem(LAST_SEEN_ANNOUNCEMENT_KEY) || 0)
  if (!lastSeen) {
    // 首次访问：静默记录并视为已读，不弹历史公告
    localStorage.setItem(LAST_SEEN_ANNOUNCEMENT_KEY, String(maxId))
    markRead(list.map((a: any) => Number(a.id)))
    return
  }
  const fresh = list.filter((a: any) => Number(a.id) > lastSeen)
  if (fresh.length > 0) {
    popupList.value = fresh
    popupIndex.value = 0
    localStorage.setItem(LAST_SEEN_ANNOUNCEMENT_KEY, String(maxId))
    // IronWall v1.47.10: 新公告到达时按“浏览器通知”开关真正推送一条系统通知
    showBrowserNotify('平台公告', fresh[0]?.title || '有新的平台公告，请查看')
  }
}

function toggleAnnouncementList() {
  showAllAnnouncements.value = !showAllAnnouncements.value
  if (showAllAnnouncements.value) {
    // 展开查看即视为已读，红点消失
    markRead(announcements.value.map((a: any) => Number(a.id)))
  }
}

function closeAnnouncementPopup() {
  markRead(popupList.value.map((a: any) => Number(a.id)))
  popupList.value = []
  popupIndex.value = 0
}

function prevPopup() {
  popupIndex.value = Math.max(0, popupIndex.value - 1)
}

function nextPopup() {
  popupIndex.value = Math.min(popupList.value.length - 1, popupIndex.value + 1)
}

function formatStorage(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

function formatDate(dateStr: string): string {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleDateString('zh-CN', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function plainExcerpt(text: string, len = 42): string {
  const plain = stripMarkdown(text)
  return plain.length > len ? plain.slice(0, len) + '…' : plain
}

const storagePercentage = () => {
  if (storageLimit.value === 0) return 0
  return Math.min((storageUsed.value / storageLimit.value) * 100, 100)
}
</script>

<template>
  <Layout>
    <div class="space-y-8">
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-3xl font-bold text-white">仪表盘</h1>
          <p class="text-slate-400 mt-2">欢迎回来，{{ authStore.user?.username }}</p>
        </div>
        <div class="flex items-center gap-2 px-5 py-2.5 bg-slate-800/50 rounded-xl border border-slate-700/30">
          <div class="w-2 h-2 bg-green-400 rounded-full"></div>
          <span class="text-slate-300 text-sm">系统运行正常</span>
        </div>
      </div>

      <!-- 固定平台公告（最多 10 条，点击「查看以下公告」展开；未读显示红点） -->
      <div v-if="announcements.length > 0"
        class="bg-gradient-to-r from-red-500/10 via-red-500/5 to-transparent border border-red-500/20 rounded-2xl overflow-hidden">
        <div class="flex items-center gap-3 p-4">
          <div class="relative w-10 h-10 bg-red-500/15 rounded-xl flex items-center justify-center shrink-0">
            <Megaphone class="w-5 h-5 text-red-400" />
            <span v-if="unreadCount > 0" class="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full border-2 border-slate-900"></span>
          </div>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2">
              <p class="text-red-400 font-semibold text-sm">平台公告</p>
              <span class="text-xs px-2 py-0.5 rounded-full bg-red-500/15 text-red-400">{{ announcements.length }}</span>
              <span v-if="unreadCount > 0" class="text-xs px-2 py-0.5 rounded-full bg-red-500/20 text-red-300">{{ unreadCount }} 条未读</span>
            </div>
            <p class="text-red-300/80 text-sm mt-0.5 truncate">{{ announcements[0].title }}：{{ plainExcerpt(announcements[0].content) }}</p>
          </div>
          <button @click="toggleAnnouncementList"
            class="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-red-500/25 text-red-300 hover:bg-red-500/10 hover:text-red-200 text-sm transition-colors shrink-0">
            {{ showAllAnnouncements ? '收起公告' : '查看以下公告' }}
            <ChevronDown v-if="!showAllAnnouncements" class="w-4 h-4" />
            <ChevronUp v-else class="w-4 h-4" />
          </button>
        </div>
        <Transition name="announce-list">
          <div v-if="showAllAnnouncements" class="border-t border-red-500/15 divide-y divide-red-500/10 max-h-96 overflow-y-auto">
            <div v-for="ann in announcements" :key="ann.id" class="px-5 py-3.5">
              <div class="flex items-center justify-between gap-3">
                <div class="flex items-center gap-2 min-w-0">
                  <span v-if="ann.status === 'pinned'" class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-400 text-xs shrink-0">
                    <Pin class="w-3 h-3" />置顶
                  </span>
                  <p class="text-red-300 font-medium text-sm truncate">{{ ann.title }}</p>
                </div>
                <span class="text-red-400/60 text-xs shrink-0">{{ formatDate(ann.created_at) }}</span>
              </div>
              <p class="text-red-200/70 text-sm mt-1 leading-relaxed" v-html="announcementToHtml(ann.content)"></p>
            </div>
          </div>
        </Transition>
      </div>

      <!-- 新公告自动弹出弹窗（多条轮播） -->
      <Teleport to="body">
        <Transition name="announce-pop">
          <div v-if="popupList.length > 0"
            class="fixed inset-0 z-[80] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
            @click.self="closeAnnouncementPopup">
            <div class="bg-slate-800 rounded-2xl w-full max-w-lg border border-slate-700/50 shadow-2xl overflow-hidden">
              <div class="bg-gradient-to-r from-red-600 to-rose-600 px-6 py-4 flex items-center gap-3">
                <Megaphone class="w-6 h-6 text-white shrink-0" />
                <div class="flex-1 min-w-0">
                  <p class="text-white font-bold">平台公告</p>
                  <p class="text-white/70 text-xs mt-0.5">
                    {{ popupList.length > 1 ? '新公告 ' + (popupIndex + 1) + ' / ' + popupList.length : '新公告' }}
                  </p>
                </div>
                <button @click="closeAnnouncementPopup" class="text-white/70 hover:text-white transition-colors shrink-0">
                  <X class="w-5 h-5" />
                </button>
              </div>
              <div class="p-6">
                <div class="flex items-start justify-between gap-3 mb-3">
                  <h3 class="text-white text-lg font-bold break-words">{{ popupList[popupIndex]?.title }}</h3>
                  <span class="text-slate-500 text-xs shrink-0">{{ formatDate(popupList[popupIndex]?.created_at) }}</span>
                </div>
                <div class="text-slate-300 text-sm leading-relaxed max-h-[50vh] overflow-y-auto" v-html="announcementToHtml(popupList[popupIndex]?.content)"></div>
                <div v-if="popupList.length > 1" class="flex items-center justify-center gap-2 mt-4">
                  <button @click="prevPopup" :disabled="popupIndex === 0"
                    class="p-1.5 rounded-lg bg-slate-700/60 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 transition-colors">
                    <ChevronLeft class="w-4 h-4" />
                  </button>
                  <span v-for="(p, i) in popupList" :key="p.id"
                    :class="i === popupIndex ? 'bg-red-500 w-6' : 'bg-slate-600 w-2'"
                    class="h-2 rounded-full transition-all"></span>
                  <button @click="nextPopup" :disabled="popupIndex === popupList.length - 1"
                    class="p-1.5 rounded-lg bg-slate-700/60 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 transition-colors">
                    <ChevronRight class="w-4 h-4" />
                  </button>
                </div>
                <button @click="closeAnnouncementPopup" class="w-full mt-6 py-2.5 bg-red-600 hover:bg-red-500 text-white rounded-lg text-sm font-medium transition-all">我知道了</button>
              </div>
            </div>
          </div>
        </Transition>
      </Teleport>

      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div class="bg-slate-800/40 rounded-2xl p-6 border border-slate-700/30">
          <div class="flex items-start justify-between mb-4">
            <div class="p-3 rounded-xl bg-amber-500/10">
              <Zap class="w-6 h-6 text-amber-400" />
            </div>
          </div>
          <p class="text-3xl font-bold text-white">{{ formatStorage(storageUsed) }}</p>
          <p class="text-sm text-slate-400 mt-1">已用存储</p>
        </div>
        <div class="bg-slate-800/40 rounded-2xl p-6 border border-slate-700/30">
          <div class="flex items-start justify-between mb-4">
            <div class="p-3 rounded-xl bg-green-500/10">
              <Share2 class="w-6 h-6 text-green-400" />
            </div>
          </div>
          <p class="text-3xl font-bold text-white">{{ shareCount }}</p>
          <p class="text-sm text-slate-400 mt-1">活跃分享</p>
        </div>
        <div class="bg-slate-800/40 rounded-2xl p-6 border border-slate-700/30">
          <div class="flex items-start justify-between mb-4">
            <div class="p-3 rounded-xl bg-blue-500/10">
              <Cloud class="w-6 h-6 text-blue-400" />
            </div>
          </div>
          <p class="text-3xl font-bold text-white">{{ formatStorage(storageLimit) }}</p>
          <p class="text-sm text-slate-400 mt-1">总存储空间</p>
        </div>
        <div class="bg-slate-800/40 rounded-2xl p-6 border border-slate-700/30">
          <div class="flex items-start justify-between mb-4">
            <div class="p-3 rounded-xl bg-purple-500/10">
              <FileText class="w-6 h-6 text-purple-400" />
            </div>
          </div>
          <p class="text-3xl font-bold text-white">{{ fileCount }}</p>
          <p class="text-sm text-slate-400 mt-1">文件总数</p>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="bg-slate-800/40 rounded-2xl p-6 border border-slate-700/30">
          <div class="flex items-center justify-between mb-6">
            <h3 class="text-lg font-semibold text-white flex items-center gap-3">
              <div class="w-8 h-8 bg-blue-500/10 rounded-lg flex items-center justify-center">
                <FileText class="w-4 h-4 text-blue-400" />
              </div>
              最近文件
            </h3>
          </div>
          <div class="space-y-3">
            <div v-for="file in recentFiles" :key="file.id" class="flex items-center gap-4 p-4 bg-slate-700/20 rounded-xl">
              <div class="w-12 h-12 bg-slate-600 rounded-xl flex items-center justify-center">
                <FileText class="w-6 h-6 text-slate-400" />
              </div>
              <div class="flex-1 min-w-0">
                <p class="text-white truncate">{{ file.original_name }}</p>
                <p class="text-sm text-slate-400 flex items-center gap-2">
                  <Clock class="w-3 h-3" />
                  {{ formatDate(file.created_at) }}
                  <span class="text-slate-500">·</span>
                  {{ formatStorage(file.file_size) }}
                </p>
              </div>
            </div>
            <div v-if="recentFiles.length === 0" class="text-center py-8">
              <p class="text-slate-400">暂无文件</p>
              <p class="text-slate-500 text-sm mt-1">上传您的第一个文件开始使用</p>
            </div>
          </div>
        </div>

        <div class="bg-slate-800/40 rounded-2xl p-6 border border-slate-700/30">
          <div class="flex items-center justify-between mb-6">
            <h3 class="text-lg font-semibold text-white flex items-center gap-3">
              <div class="w-8 h-8 bg-green-500/10 rounded-lg flex items-center justify-center">
                <Share2 class="w-4 h-4 text-green-400" />
              </div>
              最近分享
            </h3>
          </div>
          <div class="space-y-3">
            <div v-for="share in recentShares" :key="share.id" class="flex items-center gap-4 p-4 bg-slate-700/20 rounded-xl">
              <div class="w-12 h-12 bg-green-600/20 rounded-xl flex items-center justify-center">
                <Share2 class="w-6 h-6 text-green-400" />
              </div>
              <div class="flex-1 min-w-0">
                <p class="text-white truncate">{{ (share as any).file_name || share.share_code }}</p>
                <p class="text-sm text-slate-400">
                  下载 {{ share.download_count }} 次
                  <span v-if="share.expire_time" class="text-slate-500"> · {{ formatDate(share.expire_time) }}</span>
                </p>
              </div>
              <span :class="['px-3 py-1.5 text-xs rounded-full', share.status === 1 ? 'bg-green-500/20 text-green-400' : 'bg-slate-600/50 text-slate-400']">
                {{ share.status === 1 ? '启用' : '禁用' }}
              </span>
            </div>
            <div v-if="recentShares.length === 0" class="text-center py-8">
              <p class="text-slate-400">暂无分享</p>
              <p class="text-slate-500 text-sm mt-1">分享您的文件给朋友</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </Layout>
</template>
