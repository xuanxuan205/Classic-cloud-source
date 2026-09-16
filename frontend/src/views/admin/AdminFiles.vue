<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useAdminStore } from '@/stores/admin'
import Layout from '@/components/Layout.vue'
import { showToast, confirmDialog } from '@/composables/useGlobalFeedback'
import { Search, Download, Trash2, Ban, Unlock, User, Calendar, FileText, FileImage, FileVideo, FileArchive, FileAudio, Cloud, Loader2, Files } from 'lucide-vue-next'

const adminStore = useAdminStore()
const loading = ref(true)
const searchKeyword = ref('')
const typeFilter = ref('all')
const statusFilter = ref('all')
let searchTimer: ReturnType<typeof setTimeout> | null = null

const filteredFiles = computed(() => {
  let result = adminStore.files
  if (typeFilter.value !== 'all') {
    result = result.filter(f => f.file_type === typeFilter.value)
  }
  if (statusFilter.value !== 'all') {
    if (statusFilter.value === 'active') result = result.filter(f => f.status === 1)
    else result = result.filter(f => f.status !== 1)
  }
  return result
})

async function loadFiles(keyword: string) {
  loading.value = true
  try { await adminStore.getFiles(0, 50, keyword.trim()) } catch (e: any) { console.error(e) }
  loading.value = false
}

watch(searchKeyword, () => {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(() => loadFiles(searchKeyword.value), 300)
})

onMounted(async () => {
  await loadFiles('')
})

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

function getFileIcon(type: string) {
  switch (type) { case 'image': return FileImage; case 'video': return FileVideo; case 'audio': return FileAudio; case 'archive': return FileArchive; default: return FileText }
}

function getFileColor(type: string) {
  switch (type) { case 'image': return 'from-pink-500 to-rose-500'; case 'video': return 'from-purple-500 to-violet-500'; case 'audio': return 'from-amber-500 to-orange-500'; case 'archive': return 'from-cyan-500 to-blue-500'; default: return 'from-blue-500 to-indigo-500' }
}

async function handleBan(fileId: number) {
  if (!await confirmDialog('确定封禁此文件？')) return
  try { await adminStore.updateFileStatus(fileId, 0); await loadFiles(searchKeyword.value); showToast('文件已封禁', 'success') } catch (e: any) { showToast('操作失败', 'error') }
}

async function handleUnban(fileId: number) {
  try { await adminStore.updateFileStatus(fileId, 1); await loadFiles(searchKeyword.value); showToast('已解除封禁', 'success') } catch (e: any) { showToast('操作失败', 'error') }
}

async function handleDelete(fileId: number) {
  if (!await confirmDialog('确定永久删除此文件？文件记录、物理文件及其公开分享将一并删除，此操作不可恢复！', { confirmText: '永久删除' })) return
  try {
    // Use updateFileStatus for file deletion via admin
    await adminStore.updateFileStatus(fileId, -1)
    await loadFiles(searchKeyword.value)
    showToast('文件已删除', 'success')
  } catch (e: any) { showToast('删除失败', 'error') }
}
</script>

<template>
  <Layout>
    <div class="p-6 space-y-6">
      <div>
        <h1 class="text-2xl font-bold text-white">文件管理</h1>
        <p class="text-slate-400 mt-2 text-sm">查看和管理所有用户上传的文件</p>
      </div>

      <div class="bg-slate-800/50 rounded-xl border border-slate-700/30 p-4">
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div class="relative">
            <Search class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input v-model="searchKeyword" type="text" placeholder="搜索文件名 / 用户名 / 用户ID..." class="pl-10 pr-4 py-2 bg-slate-700/50 border border-slate-600/30 rounded-lg text-white text-sm placeholder-slate-400 focus:outline-none focus:border-blue-500 w-64" />
          </div>
          <div class="flex items-center gap-2">
            <select v-model="typeFilter" class="px-3 py-2 bg-slate-700/50 border border-slate-600/30 rounded-lg text-white text-sm focus:outline-none">
              <option value="all">全部类型</option>
              <option value="image">图片</option>
              <option value="video">视频</option>
              <option value="audio">音频</option>
              <option value="document">文档</option>
              <option value="archive">压缩包</option>
            </select>
            <button v-for="s in [{ value: 'all', label: '全部' }, { value: 'active', label: '正常' }, { value: 'banned', label: '已封禁' }]" :key="s.value"
              @click="statusFilter = s.value" :class="['px-3 py-2 rounded-lg text-sm font-medium transition-all', statusFilter === s.value ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' : 'bg-slate-700/30 text-slate-300 hover:bg-slate-700/50 border border-transparent']">{{ s.label }}</button>
          </div>
        </div>
      </div>

      <div v-if="loading" class="text-center py-12 text-slate-400"><Loader2 class="w-6 h-6 animate-spin mx-auto mb-2" />加载中...</div>

      <div v-else class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-5">
        <div v-for="file in filteredFiles" :key="file.id" class="bg-slate-800/50 rounded-xl p-5 border border-slate-700/30 hover:border-slate-500/50 transition-all">
          <div class="flex items-start justify-between mb-4">
            <div class="w-12 h-12 rounded-lg flex items-center justify-center bg-gradient-to-br" :class="getFileColor(file.file_type)">
              <component :is="getFileIcon(file.file_type)" class="w-6 h-6 text-white/90" />
            </div>
            <span :class="['px-2 py-0.5 rounded-full text-xs', file.status === 1 ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400']">{{ file.status === 1 ? '正常' : '已封禁' }}</span>
          </div>
          <h4 class="text-white font-medium truncate mb-2 text-sm">{{ file.original_name }}</h4>
          <div class="space-y-1.5 text-xs text-slate-400">
            <div class="flex items-center gap-2"><User class="w-3 h-3 shrink-0" />用户: <span class="truncate">{{ file.username || '未知用户' }}</span><span class="shrink-0 text-slate-500">(ID: {{ file.user_code || file.user_id || '-' }})</span></div>
            <div class="flex items-center gap-2"><Cloud class="w-3 h-3" />{{ formatBytes(file.file_size) }}</div>
            <div class="flex items-center gap-2"><Calendar class="w-3 h-3" />{{ formatDate(file.created_at) }}</div>
            <div class="flex items-center gap-2"><Download class="w-3 h-3" />{{ file.download_count || 0 }} 次下载</div>
          </div>
          <div class="flex items-center gap-2 mt-4">
            <button v-if="file.status === 1" @click="handleBan(file.id)" class="flex-1 flex items-center justify-center gap-1 px-2 py-1.5 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30 transition-all text-xs"><Ban class="w-3 h-3" />封禁</button>
            <button v-if="file.status !== 1" @click="handleUnban(file.id)" class="flex-1 flex items-center justify-center gap-1 px-2 py-1.5 bg-green-500/20 text-green-400 rounded-lg hover:bg-green-500/30 transition-all text-xs"><Unlock class="w-3 h-3" />解封</button>
            <button @click="handleDelete(file.id)" class="flex items-center justify-center gap-1 px-2 py-1.5 bg-slate-700/30 text-slate-400 rounded-lg hover:bg-slate-700/50 transition-all text-xs"><Trash2 class="w-3 h-3" /></button>
          </div>
        </div>
        <div v-if="filteredFiles.length === 0" class="col-span-full text-center py-12">
          <Files class="w-12 h-12 text-slate-600 mx-auto mb-3" /><p class="text-slate-400">暂无文件</p>
        </div>
      </div>
    </div>
  </Layout>
</template>
