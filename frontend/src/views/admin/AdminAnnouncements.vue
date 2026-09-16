<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAdminStore } from '@/stores/admin'
import Layout from '@/components/Layout.vue'
import { showToast } from '@/composables/useGlobalFeedback'
import { announcementToHtml, stripMarkdown } from '@/utils/text'
import {
  Megaphone, Plus, Edit, Trash2, X, Loader2, Eye, Calendar,
  FileText, FileCheck, AlertTriangle, PenLine, Pin, Clock
} from 'lucide-vue-next'

const adminStore = useAdminStore()
const loading = ref(true)
const showModal = ref(false)
const showPreview = ref(false)
const showDelete = ref(false)
const deleteTarget = ref<{ id: number; title: string } | null>(null)
const editingId = ref<number | null>(null)
const formTitle = ref('')
const formContent = ref('')
const formStatus = ref('published')
const formPublishAt = ref('')
const saving = ref(false)

const publishedCount = computed(() => adminStore.announcements.filter(a => a.status === 'published' || a.status === 'pinned').length)
const scheduledCount = computed(() => adminStore.announcements.filter(a => a.status === 'scheduled').length)
const draftCount = computed(() => adminStore.announcements.filter(a => a.status === 'draft').length)

const sortedAnnouncements = computed(() => {
  const rank: Record<string, number> = { pinned: 0, scheduled: 1, published: 2, draft: 3 }
  return [...adminStore.announcements].sort((a: any, b: any) => {
    const r = (rank[a.status] ?? 9) - (rank[b.status] ?? 9)
    if (r !== 0) return r
    return new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime()
  })
})

const titleLength = computed(() => formTitle.value.length)
const contentLength = computed(() => formContent.value.length)
const nowLocalInput = computed(() => {
  const d = new Date()
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset())
  return d.toISOString().slice(0, 16)
})

function statusLabel(s: string): string {
  if (s === 'pinned') return '置顶'
  if (s === 'scheduled') return '定时发布'
  if (s === 'draft') return '草稿'
  return '已发布'
}

function statusTheme(s: string) {
  if (s === 'pinned') return { bar: 'bg-gradient-to-r from-rose-500 to-red-500', iconBg: 'bg-rose-500/15', iconColor: 'text-rose-400', badge: 'bg-rose-500/15 text-rose-400' }
  if (s === 'scheduled') return { bar: 'bg-gradient-to-r from-sky-500 to-blue-500', iconBg: 'bg-sky-500/15', iconColor: 'text-sky-400', badge: 'bg-sky-500/15 text-sky-400' }
  if (s === 'draft') return { bar: 'bg-gradient-to-r from-amber-500 to-orange-500', iconBg: 'bg-amber-500/15', iconColor: 'text-amber-400', badge: 'bg-amber-500/15 text-amber-400' }
  return { bar: 'bg-gradient-to-r from-green-500 to-emerald-500', iconBg: 'bg-green-500/15', iconColor: 'text-green-400', badge: 'bg-green-500/15 text-green-400' }
}

function statusIcon(s: string) {
  if (s === 'pinned') return Pin
  if (s === 'scheduled') return Clock
  if (s === 'draft') return PenLine
  return FileCheck
}

onMounted(async () => {
  loading.value = true
  try { await adminStore.getAnnouncements(0, 50) } catch (e: any) { console.error(e) }
  loading.value = false
})

function openCreate() {
  editingId.value = null
  formTitle.value = ''
  formContent.value = ''
  formStatus.value = 'published'
  formPublishAt.value = ''
  showModal.value = true
}

function openEdit(ann: any) {
  editingId.value = ann.id
  formTitle.value = ann.title
  formContent.value = ann.content
  formStatus.value = ann.status || 'published'
  formPublishAt.value = ann.publish_at ? String(ann.publish_at).slice(0, 16) : ''
  showModal.value = true
}

function openPreview(ann: any) {
  formTitle.value = ann.title
  formContent.value = ann.content
  formStatus.value = ann.status || 'published'
  formPublishAt.value = ann.publish_at ? String(ann.publish_at).slice(0, 16) : ''
  showPreview.value = true
}

async function handleSave() {
  if (!formTitle.value.trim()) { showToast('请填写公告标题', 'error'); return }
  if (!formContent.value.trim()) { showToast('请填写公告内容', 'error'); return }
  if (formStatus.value === 'scheduled') {
    if (!formPublishAt.value) { showToast('请选择定时发布时间', 'error'); return }
    if (new Date(formPublishAt.value).getTime() <= Date.now()) { showToast('定时发布时间必须晚于当前时间', 'error'); return }
  }
  saving.value = true
  try {
    const publishAt = formStatus.value === 'scheduled' ? formPublishAt.value : undefined
    if (editingId.value) {
      await adminStore.updateAnnouncement(editingId.value, formTitle.value.trim(), formContent.value.trim(), formStatus.value, publishAt)
    } else {
      await adminStore.createAnnouncement(formTitle.value.trim(), formContent.value.trim(), formStatus.value, publishAt)
    }
    showModal.value = false
    await adminStore.getAnnouncements(0, 50)
    showToast(editingId.value ? '公告已更新' : '公告已发布', 'success')
  } catch (e: any) {
    showToast('保存失败，请稍后重试', 'error')
  }
  saving.value = false
}

function askDelete(ann: any) {
  deleteTarget.value = { id: ann.id, title: ann.title }
  showDelete.value = true
}

async function handleDelete() {
  if (!deleteTarget.value) return
  try {
    await adminStore.deleteAnnouncement(deleteTarget.value.id)
    showDelete.value = false
    deleteTarget.value = null
    await adminStore.getAnnouncements(0, 50)
    showToast('公告已删除', 'success')
  } catch (e: any) { showToast('删除失败，请稍后重试', 'error') }
}

function formatDate(dateStr: string): string {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleString('zh-CN', { hour12: false })
}

function excerpt(text: string, len = 90): string {
  if (!text) return ''
  return text.length > len ? text.slice(0, len) + '…' : text
}
</script>

<template>
  <Layout>
    <div class="space-y-6">
      <div class="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 class="text-3xl font-bold text-white flex items-center gap-3">
            <Megaphone class="w-7 h-7 text-indigo-400" />系统公告
          </h1>
          <p class="text-slate-400 mt-2">创建和管理面向用户的公告与通知（置顶 / 定时 / 草稿）</p>
        </div>
        <button @click="openCreate" class="flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl transition-all text-sm font-medium shadow-lg shadow-indigo-900/30">
          <Plus class="w-4 h-4" />新建公告
        </button>
      </div>

      <!-- 概览 -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-indigo-500/20 rounded-xl flex items-center justify-center">
              <FileText class="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <p class="text-2xl font-bold text-white">{{ adminStore.announcements.length }}</p>
              <p class="text-slate-400 text-xs">全部公告</p>
            </div>
          </div>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-green-500/20 rounded-xl flex items-center justify-center">
              <FileCheck class="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p class="text-2xl font-bold text-white">{{ publishedCount }}</p>
              <p class="text-slate-400 text-xs">已发布（含置顶）</p>
            </div>
          </div>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-sky-500/20 rounded-xl flex items-center justify-center">
              <Clock class="w-5 h-5 text-sky-400" />
            </div>
            <div>
              <p class="text-2xl font-bold text-white">{{ scheduledCount }}</p>
              <p class="text-slate-400 text-xs">定时待发布</p>
            </div>
          </div>
        </div>
        <div class="bg-slate-800/60 rounded-2xl p-5 border border-slate-700/30">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-amber-500/20 rounded-xl flex items-center justify-center">
              <PenLine class="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <p class="text-2xl font-bold text-white">{{ draftCount }}</p>
              <p class="text-slate-400 text-xs">草稿</p>
            </div>
          </div>
        </div>
      </div>

      <div v-if="loading" class="text-center py-16 text-slate-400">
        <Loader2 class="w-8 h-8 animate-spin mx-auto mb-3" />
        <p class="text-sm">正在加载公告...</p>
      </div>

      <div v-else class="space-y-4">
        <div v-for="ann in sortedAnnouncements" :key="ann.id" class="bg-slate-800/60 rounded-2xl border border-slate-700/30 hover:border-indigo-500/40 transition-all overflow-hidden">
          <div :class="statusTheme(ann.status).bar" class="h-1"></div>
          <div class="p-5">
            <div class="flex items-start justify-between gap-4">
              <div class="flex items-start gap-3 min-w-0">
                <div :class="statusTheme(ann.status).iconBg" class="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0">
                  <component :is="statusIcon(ann.status)" :class="statusTheme(ann.status).iconColor" class="w-5 h-5" />
                </div>
                <div class="min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <h3 class="text-white font-semibold text-lg">{{ ann.title }}</h3>
                    <span :class="statusTheme(ann.status).badge" class="px-2 py-0.5 rounded text-xs flex items-center gap-1">
                      <component :is="statusIcon(ann.status)" class="w-3 h-3" />
                      {{ statusLabel(ann.status) }}
                    </span>
                  </div>
                  <p class="text-slate-500 text-xs mt-1 flex items-center gap-1.5">
                    <Calendar class="w-3 h-3" />{{ formatDate(ann.created_at) }}
                    <template v-if="ann.status === 'scheduled' && ann.publish_at">
                      <span class="text-slate-600">·</span>
                      <Clock class="w-3 h-3 text-sky-400" />将于 {{ formatDate(ann.publish_at) }} 自动发布
                    </template>
                  </p>
                </div>
              </div>
              <div class="flex items-center gap-1.5 flex-shrink-0">
                <button @click="openPreview(ann)" title="预览" class="p-2 text-slate-400 hover:text-indigo-400 hover:bg-slate-700/50 rounded-lg transition-colors"><Eye class="w-4 h-4" /></button>
                <button @click="openEdit(ann)" title="编辑" class="p-2 text-slate-400 hover:text-blue-400 hover:bg-slate-700/50 rounded-lg transition-colors"><Edit class="w-4 h-4" /></button>
                <button @click="askDelete(ann)" title="删除" class="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-700/50 rounded-lg transition-colors"><Trash2 class="w-4 h-4" /></button>
              </div>
            </div>
            <p class="text-slate-400 text-sm leading-relaxed mt-3 bg-slate-900/40 rounded-xl p-4 border border-slate-700/20">{{ excerpt(stripMarkdown(ann.content)) }}</p>
          </div>
        </div>

        <div v-if="adminStore.announcements.length === 0" class="text-center py-16">
          <div class="w-20 h-20 mx-auto bg-indigo-500/10 rounded-full flex items-center justify-center mb-4">
            <Megaphone class="w-10 h-10 text-indigo-400" />
          </div>
          <p class="text-white font-medium mb-1">还没有公告</p>
          <p class="text-slate-500 text-sm mb-6">点击右上角「新建公告」发布第一条公告</p>
          <button @click="openCreate" class="inline-flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl transition-all text-sm font-medium">
            <Plus class="w-4 h-4" />新建公告
          </button>
        </div>
      </div>
    </div>

    <!-- 新建/编辑弹窗 -->
    <Teleport to="body">
      <div v-if="showModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" @click.self="showModal = false">
        <div class="bg-slate-800 rounded-2xl w-full max-w-2xl border border-slate-700/50 shadow-2xl max-h-[90vh] overflow-y-auto">
          <div class="flex items-center justify-between p-6 pb-4">
            <div>
              <h3 class="text-xl font-bold text-white">{{ editingId ? '编辑公告' : '新建公告' }}</h3>
              <p class="text-slate-500 text-xs mt-1">支持 **加粗**、# 标题、- 列表、1. 列表等简单排版</p>
            </div>
            <button @click="showModal = false" class="text-slate-500 hover:text-white transition-colors"><X class="w-5 h-5" /></button>
          </div>
          <div class="px-6 pb-6 space-y-4">
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="text-slate-400 text-sm">标题</label>
                <span :class="titleLength > 100 ? 'text-red-400' : 'text-slate-600'" class="text-xs">{{ titleLength }}/100</span>
              </div>
              <input v-model="formTitle" maxlength="100" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500" placeholder="公告标题" />
            </div>
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <label class="text-slate-400 text-sm">内容</label>
                <span :class="contentLength > 2000 ? 'text-red-400' : 'text-slate-600'" class="text-xs">{{ contentLength }}/2000</span>
              </div>
              <textarea v-model="formContent" rows="7" maxlength="2000" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:border-indigo-500 resize-none leading-relaxed" placeholder="公告内容...&#10;支持：**加粗**、# 标题、- 列表、1. 列表"></textarea>
            </div>
            <div>
              <label class="text-slate-400 text-sm block mb-2">状态</label>
              <div class="grid grid-cols-2 gap-3">
                <button @click="formStatus = 'published'"
                  :class="['flex items-center justify-center gap-2 px-4 py-3 rounded-xl border text-sm font-medium transition-all',
                    formStatus === 'published' ? 'bg-green-600/20 text-green-400 border-green-500/40' : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-500']">
                  <FileCheck class="w-4 h-4" />立即发布
                </button>
                <button @click="formStatus = 'pinned'"
                  :class="['flex items-center justify-center gap-2 px-4 py-3 rounded-xl border text-sm font-medium transition-all',
                    formStatus === 'pinned' ? 'bg-rose-600/20 text-rose-400 border-rose-500/40' : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-500']">
                  <Pin class="w-4 h-4" />置顶发布
                </button>
                <button @click="formStatus = 'scheduled'"
                  :class="['flex items-center justify-center gap-2 px-4 py-3 rounded-xl border text-sm font-medium transition-all',
                    formStatus === 'scheduled' ? 'bg-sky-600/20 text-sky-400 border-sky-500/40' : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-500']">
                  <Clock class="w-4 h-4" />定时发布
                </button>
                <button @click="formStatus = 'draft'"
                  :class="['flex items-center justify-center gap-2 px-4 py-3 rounded-xl border text-sm font-medium transition-all',
                    formStatus === 'draft' ? 'bg-amber-600/20 text-amber-400 border-amber-500/40' : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-500']">
                  <PenLine class="w-4 h-4" />存为草稿
                </button>
              </div>
              <div v-if="formStatus === 'scheduled'" class="mt-3">
                <label class="text-slate-400 text-sm block mb-1.5">定时发布时间（到点自动发布，每 30 秒检查一次）</label>
                <input v-model="formPublishAt" type="datetime-local" :min="nowLocalInput"
                  class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:border-sky-500" />
              </div>
            </div>
            <div class="bg-slate-900/60 rounded-xl p-4 border border-slate-700/40">
              <p class="text-slate-500 text-xs mb-2 flex items-center gap-1.5"><Eye class="w-3.5 h-3.5" />用户端预览</p>
              <p class="text-white text-sm font-medium mb-1">{{ formTitle || '公告标题' }}</p>
              <div class="text-slate-400 text-xs leading-relaxed line-clamp-3" v-html="announcementToHtml(formContent || '公告内容将在这里预览…')"></div>
            </div>
            <button @click="handleSave" :disabled="saving" class="w-full py-3 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-600/30 text-white rounded-lg font-medium transition-all flex items-center justify-center gap-2">
              <Loader2 v-if="saving" class="w-4 h-4 animate-spin" />{{ saving ? '保存中...' : (editingId ? '保存修改' : '发布公告') }}
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- 预览弹窗 -->
    <Teleport to="body">
      <div v-if="showPreview" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" @click.self="showPreview = false">
        <div class="bg-slate-800 rounded-2xl w-full max-w-xl border border-slate-700/50 shadow-2xl max-h-[85vh] overflow-y-auto">
          <div class="flex items-center justify-between p-6 pb-4">
            <h3 class="text-xl font-bold text-white flex items-center gap-2"><Eye class="w-5 h-5 text-indigo-400" />公告预览</h3>
            <button @click="showPreview = false" class="text-slate-500 hover:text-white transition-colors"><X class="w-5 h-5" /></button>
          </div>
          <div class="px-6 pb-6">
            <div class="bg-slate-900/70 rounded-2xl p-6 border border-slate-700/40">
              <div class="flex items-center gap-2 mb-3">
                <span :class="statusTheme(formStatus).badge" class="px-2 py-0.5 rounded text-xs flex items-center gap-1">
                  <component :is="statusIcon(formStatus)" class="w-3 h-3" />
                  {{ statusLabel(formStatus) }}
                </span>
                <span v-if="formStatus === 'scheduled' && formPublishAt" class="text-slate-500 text-xs">将于 {{ formatDate(formPublishAt) }} 自动发布</span>
              </div>
              <h4 class="text-white text-lg font-bold mb-3">{{ formTitle }}</h4>
              <div class="text-slate-300 text-sm leading-relaxed" v-html="announcementToHtml(formContent)"></div>
            </div>
            <button @click="showPreview = false" class="w-full mt-5 py-2.5 bg-slate-700/60 hover:bg-slate-700 text-white rounded-lg text-sm font-medium transition-all">关闭预览</button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- 删除确认弹窗 -->
    <Teleport to="body">
      <div v-if="showDelete" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" @click.self="showDelete = false">
        <div class="bg-slate-800 rounded-2xl w-full max-w-md border border-slate-700/50 shadow-2xl p-6">
          <div class="w-12 h-12 mx-auto bg-red-500/15 rounded-full flex items-center justify-center mb-4">
            <AlertTriangle class="w-6 h-6 text-red-400" />
          </div>
          <h3 class="text-white font-bold text-lg text-center mb-2">删除公告</h3>
          <p class="text-slate-400 text-sm text-center mb-6">
            确定删除「{{ deleteTarget?.title }}」吗？<br />删除后将无法恢复，用户也不再可见。
          </p>
          <div class="flex gap-3">
            <button @click="showDelete = false" class="flex-1 px-4 py-2.5 bg-slate-700/50 text-slate-300 rounded-lg hover:bg-slate-700 transition-all text-sm">取消</button>
            <button @click="handleDelete" class="flex-1 px-4 py-2.5 bg-red-600 text-white rounded-lg hover:bg-red-500 transition-all text-sm font-medium flex items-center justify-center gap-2">
              <Trash2 class="w-4 h-4" />确认删除
            </button>
          </div>
        </div>
      </div>
    </Teleport>
  </Layout>
</template>
