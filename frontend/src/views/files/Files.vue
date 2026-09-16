<script setup lang="ts">
import { ref, onMounted, computed } from "vue"
import { useRouter } from "vue-router"
import { useFilesStore } from "@/stores/files"
import { useAuthStore } from "@/stores/auth"
import { useI18n } from "@/i18n"
import Layout from "@/components/Layout.vue"
import { Upload, Search, FolderOpen, Download, Trash2, RefreshCw, X, ArrowLeft, FolderPlus, Grid3X3, List, CloudUpload, FileText, FileImage, FileVideo, FileAudio, FileArchive, FileCode, HardDrive, Languages, ChevronRight, Image, BarChart3, Zap, Settings, Share2, AlertCircle } from "lucide-vue-next"

const { locale, t, toggleLocale } = useI18n()
const filesStore = useFilesStore()
const authStore = useAuthStore()
const router = useRouter()
const searchKeyword = ref("")
const showCreateFolder = ref(false)
const newFolderName = ref("")
const showDeleteModal = ref(false)
const currentFile = ref<any>(null)
const viewMode = ref<"grid" | "list">("grid")

const uploadProgress = ref(0)
const isUploading = ref(false)
const dragOver = ref(false)
const activeFilter = ref('all')
const currentFolderName = ref('')
const refreshLoading = ref(false)
const toastMessage = ref("")


onMounted(async () => {
  await filesStore.getFiles(filesStore.currentFolderId)
  await filesStore.getFolders(filesStore.currentFolderId)
  await filesStore.getStorageStats()
})

async function goBack() { filesStore.currentFolderId = 0; currentFolderName.value = ''; await filesStore.getFiles(0); await filesStore.getFolders(0) }
async function navigateToFolder(folderId: number, folderName?: string) { filesStore.currentFolderId = folderId; currentFolderName.value = folderName || ''; await filesStore.getFiles(folderId); await filesStore.getFolders(folderId) }


const filters = computed(() => [
  { id: 'all', label: t.value.files.all, icon: FolderOpen, color: 'text-slate-400' },
  { id: 'image', label: t.value.files.images, icon: FileImage, color: 'text-pink-400' },
  { id: 'video', label: t.value.files.videos, icon: FileVideo, color: 'text-purple-400' },
  { id: 'audio', label: t.value.files.audio, icon: FileAudio, color: 'text-yellow-400' },
  { id: 'archive', label: t.value.files.archives, icon: FileArchive, color: 'text-orange-400' },
  { id: 'document', label: t.value.files.documents, icon: FileText, color: 'text-blue-400' },
  { id: 'code', label: 'Code', icon: FileCode, color: 'text-green-400' },
])

const filteredFiles = computed(() => {
  let files = filesStore.files
  if (searchKeyword.value) { const q = searchKeyword.value.toLowerCase(); files = files.filter(f => (f.original_name || "").toLowerCase().includes(q)) }
  if (activeFilter.value === "all") return files
  const typeMap: Record<string, string[]> = {
    image: ["jpg","jpeg","png","gif","webp","bmp","svg","ico"],
    video: ["mp4","webm","avi","mov","mkv","flv"],
    audio: ["mp3","wav","ogg","flac","aac","m4a"],
    archive: ["zip","rar","7z","tar","gz","bz2","xz"],
    document: ["doc","docx","pdf","txt","xls","xlsx","ppt","pptx","csv"],
    code: ["js","ts","jsx","tsx","py","java","go","rs","html","css","json","xml","yaml","yml","sh","bat","ps1"]
  }
  return files.filter(file => typeMap[activeFilter.value]?.includes((file.file_type || "").toLowerCase()) || false)
})

const stats = computed(() => ({
  fileCount: filesStore.files.length,
  folderCount: filesStore.folders.length,
  totalItems: filesStore.files.length + filesStore.folders.length,
  totalSize: filesStore.stats?.used ?? filesStore.files.reduce((sum: number, f: any) => sum + (f.file_size || 0), 0),
  totalDownloads: filesStore.stats?.total_downloads ?? filesStore.files.reduce((sum: number, f: any) => sum + (f.download_count || 0), 0),
}))

function formatFileSize(bytes: number): string {
  if (!bytes) return "0 B"
  if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + " GB"
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + " MB"
  if (bytes >= 1024) return (bytes / 1024).toFixed(2) + " KB"
  return bytes + " B"
}

function getFileIcon(fileType: string) {
  const t = (fileType || "").toLowerCase()
  if (["jpg","jpeg","png","gif","webp","bmp","svg","ico"].includes(t)) return Image
  if (["mp4","webm","avi","mov","mkv"].includes(t)) return FileVideo
  if (["mp3","wav","ogg","flac","aac"].includes(t)) return FileAudio
  if (["zip","rar","7z","tar","gz","bz2"].includes(t)) return FileArchive
  if (["js","ts","py","java","go","rs","html","css","json"].includes(t)) return FileCode
  return FileText
}

function getFileIconColor(fileType: string) {
  const t = (fileType || "").toLowerCase()
  if (["jpg","jpeg","png","gif","webp","bmp","svg"].includes(t)) return "text-pink-400"
  if (["mp4","webm","avi","mov","mkv"].includes(t)) return "text-purple-400"
  if (["mp3","wav","ogg","flac","aac"].includes(t)) return "text-yellow-400"
  if (["zip","rar","7z","tar","gz","bz2"].includes(t)) return "text-orange-400"
  if (["js","ts","py","java","go","rs","html","css","json"].includes(t)) return "text-green-400"
  return "text-blue-400"
}

async function handleUpload(event: Event) {
  const target = event.target as HTMLInputElement
  const files = target.files
  if (!files || files.length === 0) return
  isUploading.value = true; uploadProgress.value = 0
  let failedCount = 0
  for (let i = 0; i < files.length; i++) {
    const result = await filesStore.uploadFile(files[i] as unknown as File, filesStore.currentFolderId, (pct: number) => {
      uploadProgress.value = Math.round((i / files.length) * 100 + pct / files.length)
    })
    if (!result.success) failedCount++
  }
  await filesStore.getFiles(filesStore.currentFolderId)
  await filesStore.getFolders(filesStore.currentFolderId)
  await filesStore.getStorageStats()
  target.value = ""; isUploading.value = false; uploadProgress.value = 0
  if (failedCount > 0) { toastMessage.value = failedCount + t.value.files.uploadFailed; setTimeout(() => toastMessage.value = "", 4000) }
}

function handleDragOver(event: DragEvent) { event.preventDefault(); dragOver.value = true }
function handleDragLeave() { dragOver.value = false }
async function handleDrop(event: DragEvent) {
  event.preventDefault(); dragOver.value = false
  const files = event.dataTransfer?.files
  if (!files || files.length === 0) return
  isUploading.value = true; uploadProgress.value = 0
  let failedCount = 0
  for (let i = 0; i < files.length; i++) {
    const result = await filesStore.uploadFile(files[i] as unknown as File, filesStore.currentFolderId, (pct: number) => {
      uploadProgress.value = Math.round((i / files.length) * 100 + pct / files.length)
    })
    if (!result.success) failedCount++
  }
  await filesStore.getFiles(filesStore.currentFolderId)
  await filesStore.getFolders(filesStore.currentFolderId)
  await filesStore.getStorageStats()
  isUploading.value = false; uploadProgress.value = 0
  if (failedCount > 0) { toastMessage.value = failedCount + t.value.files.uploadFailed; setTimeout(() => toastMessage.value = "", 4000) }
}

async function handleDelete(file: any) {
  await filesStore.deleteFile(file.id)
  await filesStore.getFiles(filesStore.currentFolderId)
  await filesStore.getStorageStats()
  showDeleteModal.value = false
}

async function createFolder() {
  if (!newFolderName.value.trim()) return
  await filesStore.createFolder(newFolderName.value.trim(), filesStore.currentFolderId)
  await filesStore.getFolders(filesStore.currentFolderId)
  newFolderName.value = ""; showCreateFolder.value = false
}

async function handleDeleteFolder(folder: any) {
  const result = await filesStore.deleteFolder(folder.id)
  if (result.success) {
    await filesStore.getFolders(filesStore.currentFolderId)
    await filesStore.getFiles(filesStore.currentFolderId)
    await filesStore.getStorageStats()
    toastMessage.value = '文件夹已删除'
  } else {
    toastMessage.value = result.message || '删除失败'
  }
  setTimeout(() => toastMessage.value = '', 2000)
}

async function refreshAll() {
  refreshLoading.value = true
  await filesStore.getFiles(filesStore.currentFolderId)
  await filesStore.getFolders(filesStore.currentFolderId)
  await filesStore.getStorageStats()
  refreshLoading.value = false
}


const folderDistribution = computed(() => {
  return filesStore.folders.map((f: any) => ({
    key: 'folder_' + f.id,
    name: f.name,
    count: 0,
    size: 0,
    isFolder: true,
    icon: FolderOpen,
    color: 'text-yellow-400 bg-yellow-500/10'
  }))
})

const fileTypeStats = computed(() => {
  const types: Record<string, { count: number; size: number; label: string; icon: any; color: string }> = {
    image: { count: 0, size: 0, label: '图片', icon: FileImage, color: 'text-pink-400 bg-pink-500/10' },
    video: { count: 0, size: 0, label: '视频', icon: FileVideo, color: 'text-purple-400 bg-purple-500/10' },
    audio: { count: 0, size: 0, label: '音频', icon: FileAudio, color: 'text-yellow-400 bg-yellow-500/10' },
    archive: { count: 0, size: 0, label: '压缩包', icon: FileArchive, color: 'text-orange-400 bg-orange-500/10' },
    document: { count: 0, size: 0, label: '文档', icon: FileText, color: 'text-blue-400 bg-blue-500/10' },
    code: { count: 0, size: 0, label: '代码', icon: FileCode, color: 'text-green-400 bg-green-500/10' },
    other: { count: 0, size: 0, label: '其他', icon: FileText, color: 'text-slate-400 bg-slate-500/10' },
  }
  const extMap: Record<string, string> = {
    jpg: 'image', jpeg: 'image', png: 'image', gif: 'image', webp: 'image', bmp: 'image', svg: 'image', ico: 'image',
    mp4: 'video', webm: 'video', avi: 'video', mov: 'video', mkv: 'video', flv: 'video',
    mp3: 'audio', wav: 'audio', ogg: 'audio', flac: 'audio', aac: 'audio', m4a: 'audio',
    zip: 'archive', rar: 'archive', '7z': 'archive', tar: 'archive', gz: 'archive', bz2: 'archive', xz: 'archive',
    doc: 'document', docx: 'document', pdf: 'document', txt: 'document', xls: 'document', xlsx: 'document', ppt: 'document', pptx: 'document', csv: 'document',
    js: 'code', ts: 'code', jsx: 'code', tsx: 'code', py: 'code', java: 'code', go: 'code', rs: 'code', html: 'code', css: 'code', json: 'code', xml: 'code', yaml: 'code', yml: 'code', sh: 'code', bat: 'code', ps1: 'code',
  }
  filesStore.files.forEach((f: any) => {
    const ext = ((f.original_name || f.file_type || '').split('.').pop() || '').toLowerCase()
    const cat = extMap[ext] || 'other'
    types[cat].count++
    types[cat].size += f.file_size || 0
  })
  return Object.entries(types).filter(([_, v]) => v.count > 0).map(([k, v]) => ({ key: k, ...v }))
})

function formatDownloadCount(n: number): string {
  if (!n) return '0'
  if (n >= 10000) return (n / 10000).toFixed(1) + 'w'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'k'
  return String(n)
}

function getFileBgColor(fileType: string) {
  const t = (fileType || '').toLowerCase()
  if (['jpg','jpeg','png','gif','webp','bmp','svg'].includes(t)) return 'bg-pink-500/10'
  if (['mp4','webm','avi','mov','mkv'].includes(t)) return 'bg-purple-500/10'
  if (['mp3','wav','ogg','flac','aac'].includes(t)) return 'bg-yellow-500/10'
  if (['zip','rar','7z','tar','gz','bz2'].includes(t)) return 'bg-orange-500/10'
  if (['js','ts','py','java','go','rs','html','css','json'].includes(t)) return 'bg-green-500/10'
  return 'bg-blue-500/10'
}

function triggerFileInput() {
  const inp = document.createElement('input')
  inp.type = 'file'; inp.multiple = true
  inp.onchange = (e: any) => handleUpload(e)
  inp.click()
}

function formatDate(s: string) { if (!s) return ""; return new Date(s).toLocaleDateString("zh-CN", { month: "short", day: "numeric" }) }
</script>
<template>
  <Layout>
    <div class="p-4 sm:p-6 xl:p-8 w-full space-y-5">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div class="flex items-center gap-3 mb-1">
            <div class="w-9 h-9 rounded-xl bg-indigo-500/15 flex items-center justify-center">
              <FolderOpen class="w-5 h-5 text-indigo-400" />
            </div>
            <h1 class="text-xl sm:text-2xl font-bold text-white">{{ t.files.title }}</h1>
            <button @click="toggleLocale" class="flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs text-slate-400 hover:text-white transition-colors border border-slate-700/50">
              <Languages class="w-3.5 h-3.5" />
              {{ locale === "zh" ? "EN" : "中" }}
            </button>
          </div>
          <p class="text-slate-400 text-xs sm:text-sm ml-12">{{ t.files.subtitle }}</p>
        </div>
        <div class="flex items-center gap-2">
          <button @click="showCreateFolder = true" class="flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium rounded-xl border border-slate-700/50 transition-all">
            <FolderPlus class="w-4 h-4 text-yellow-400" />{{ t.files.newFolder }}
          </button>
          <label class="flex items-center gap-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium rounded-xl cursor-pointer transition-all shadow-lg shadow-indigo-600/20">
            <Upload class="w-4 h-4" />{{ t.files.upload }}
            <input type="file" multiple class="hidden" @change="handleUpload" />
          </label>
        </div>
      </div>

      <!-- Breadcrumb -->
      <div class="flex items-center gap-2 text-sm">
        <button @click="goBack" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all"
          :class="filesStore.currentFolderId > 0 ? 'bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 hover:bg-indigo-500/20' : 'bg-slate-800/40 border border-slate-700/30 text-white cursor-default'">
          <FolderOpen class="w-3.5 h-3.5 text-yellow-400" />
          {{ filesStore.currentFolderId > 0 ? '← 返回上级' : '根目录' }}
        </button>
        <template v-if="filesStore.currentFolderId > 0">
          <span class="text-slate-600">/</span>
          <span class="px-2 py-0.5 bg-slate-800/60 rounded text-slate-300 font-medium">{{ currentFolderName }}</span>
        </template>
      </div>

      <!-- Storage Stats -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div class="bg-slate-800/40 border border-slate-700/30 rounded-2xl p-4 flex items-center gap-3 hover:border-slate-600/50 transition-all">
          <div class="w-10 h-10 rounded-xl bg-indigo-500/10 flex items-center justify-center shrink-0">
            <FolderOpen class="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <p class="text-xl font-bold text-white">{{ stats.totalItems }}</p>
            <p class="text-xs text-slate-400">总文件数</p>
          </div>
        </div>
        <div class="bg-slate-800/40 border border-slate-700/30 rounded-2xl p-4 flex items-center gap-3 hover:border-slate-600/50 transition-all">
          <div class="w-10 h-10 rounded-xl bg-emerald-500/10 flex items-center justify-center shrink-0">
            <HardDrive class="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <p class="text-xl font-bold text-white">{{ formatFileSize(stats.totalSize) }}</p>
            <p class="text-xs text-slate-400">已使用空间</p>
          </div>
        </div>
        <div class="bg-slate-800/40 border border-slate-700/30 rounded-2xl p-4 flex items-center gap-3 hover:border-slate-600/50 transition-all">
          <div class="w-10 h-10 rounded-xl bg-amber-500/10 flex items-center justify-center shrink-0">
            <Download class="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <p class="text-xl font-bold text-white">{{ formatDownloadCount(stats.totalDownloads) }}</p>
            <p class="text-xs text-slate-400">总下载次数</p>
          </div>
        </div>
        <div class="bg-slate-800/40 border border-slate-700/30 rounded-2xl p-4 flex items-center gap-3 hover:border-slate-600/50 transition-all">
          <div class="w-10 h-10 rounded-xl bg-rose-500/10 flex items-center justify-center shrink-0">
            <Zap class="w-5 h-5 text-rose-400" />
          </div>
          <div>
            <p class="text-xl font-bold text-white">{{ authStore.user?.role==='admin' ? '无限' : (filesStore.stats?.upload_limit ? filesStore.stats.upload_limit + ' MB' : '850 MB') }}</p>
            <p class="text-xs text-slate-400">上传限制</p>
          </div>
        </div>
      </div>

      <!-- File Type Distribution + Quick Actions -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div class="lg:col-span-2 bg-slate-800/40 border border-slate-700/30 rounded-2xl p-5">
          <h3 class="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <FolderOpen v-if="folderDistribution.length > 0" class="w-4 h-4 text-yellow-400" />
            <BarChart3 v-else class="w-4 h-4 text-indigo-400" />
            {{ folderDistribution.length > 0 ? '文件夹' : '文件类型分布' }}
          </h3>
          <div v-if="folderDistribution.length > 0" class="space-y-2">
            <div v-for="folder in folderDistribution" :key="folder.key"
                 @click="navigateToFolder(Number(folder.key.replace('folder_','')), folder.name)"
                 class="flex items-center gap-3 p-3 rounded-xl bg-slate-700/30 hover:bg-slate-700/50 cursor-pointer transition-all group">
              <div class="w-8 h-8 rounded-lg bg-yellow-500/10 flex items-center justify-center shrink-0">
                <FolderOpen class="w-4 h-4 text-yellow-400" />
              </div>
              <span class="text-sm text-slate-300 group-hover:text-white transition-colors truncate">{{ folder.name }}</span>
              <ChevronRight class="w-4 h-4 ml-auto text-slate-600 group-hover:text-slate-400 transition-colors" />
            </div>
          </div>
          <div v-else-if="fileTypeStats.length > 0" class="space-y-3">
            <div v-for="item in fileTypeStats" :key="item.key" class="flex items-center gap-3">
              <div :class="['w-8 h-8 rounded-lg flex items-center justify-center shrink-0', item.color.split(' ')[1] || 'bg-slate-500/10']">
                <component :is="item.icon" :class="['w-4 h-4', item.color.split(' ')[0]]" />
              </div>
              <div class="flex-1 min-w-0">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs text-slate-400">{{ item.label }}</span>
                  <span class="text-xs text-slate-500">{{ item.count }} 个 · {{ formatFileSize(item.size) }}</span>
                </div>
                <div class="h-1.5 bg-slate-700/50 rounded-full overflow-hidden">
                  <div class="h-full rounded-full transition-all duration-500" :style="{ width: stats.fileCount > 0 ? (item.count / stats.fileCount * 100) + '%' : '0%', background: item.key === 'image' ? 'linear-gradient(90deg,#ec4899,#f472b6)' : item.key === 'video' ? 'linear-gradient(90deg,#a855f7,#c084fc)' : item.key === 'audio' ? 'linear-gradient(90deg,#eab308,#facc15)' : item.key === 'archive' ? 'linear-gradient(90deg,#f97316,#fb923c)' : item.key === 'document' ? 'linear-gradient(90deg,#3b82f6,#60a5fa)' : item.key === 'code' ? 'linear-gradient(90deg,#22c55e,#4ade80)' : 'linear-gradient(90deg,#64748b,#94a3b8)' }"></div>
                </div>
              </div>
            </div>
          </div>
          <div v-else class="text-center py-8">
            <FolderOpen class="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <p class="text-xs text-slate-500">暂无文件或文件夹</p>
          </div>
        </div>
        <div class="bg-slate-800/40 border border-slate-700/30 rounded-2xl p-5">
          <h3 class="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
            <Zap class="w-4 h-4 text-amber-400" />快速操作
          </h3>
          <div class="space-y-2">
            <button @click="router.push('/recycle')" class="w-full flex items-center gap-3 p-3 rounded-xl bg-slate-700/30 hover:bg-slate-700/50 text-slate-300 hover:text-white transition-all text-sm">
              <div class="w-8 h-8 rounded-lg bg-rose-500/10 flex items-center justify-center"><Trash2 class="w-4 h-4 text-rose-400" /></div>
              回收站
              <ChevronRight class="w-4 h-4 ml-auto text-slate-600" />
            </button>
            <button @click="router.push('/shares')" class="w-full flex items-center gap-3 p-3 rounded-xl bg-slate-700/30 hover:bg-slate-700/50 text-slate-300 hover:text-white transition-all text-sm">
              <div class="w-8 h-8 rounded-lg bg-indigo-500/10 flex items-center justify-center"><Share2 class="w-4 h-4 text-indigo-400" /></div>
              我的分享
              <ChevronRight class="w-4 h-4 ml-auto text-slate-600" />
            </button>
            <button @click="router.push('/profile')" class="w-full flex items-center gap-3 p-3 rounded-xl bg-slate-700/30 hover:bg-slate-700/50 text-slate-300 hover:text-white transition-all text-sm">
              <div class="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center"><Settings class="w-4 h-4 text-emerald-400" /></div>
              个人中心
              <ChevronRight class="w-4 h-4 ml-auto text-slate-600" />
            </button>
            <button @click="router.push('/dashboard')" class="w-full flex items-center gap-3 p-3 rounded-xl bg-slate-700/30 hover:bg-slate-700/50 text-slate-300 hover:text-white transition-all text-sm">
              <div class="w-8 h-8 rounded-lg bg-amber-500/10 flex items-center justify-center"><BarChart3 class="w-4 h-4 text-amber-400" /></div>
              仪表板
              <ChevronRight class="w-4 h-4 ml-auto text-slate-600" />
            </button>
            <button @click="refreshAll" :disabled="refreshLoading" class="w-full flex items-center gap-3 p-3 rounded-xl bg-slate-700/30 hover:bg-slate-700/50 text-slate-300 hover:text-white transition-all text-sm disabled:opacity-50">
              <div class="w-8 h-8 rounded-lg bg-sky-500/10 flex items-center justify-center">
                <RefreshCw :class="['w-4 h-4 text-sky-400', refreshLoading && 'animate-spin']" />
              </div>
              {{ refreshLoading ? '刷新中...' : '刷新数据' }}
            </button>
          </div>
        </div>
      </div>
<!-- Search + View -->
      <div class="flex flex-col sm:flex-row gap-3">
        <div class="relative flex-1">
          <Search class="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input v-model="searchKeyword" placeholder="搜索文件..." class="w-full pl-10 pr-4 py-2.5 bg-slate-800/40 border border-slate-700/30 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500/50 transition-all" />
        </div>
        <div class="flex bg-slate-800/40 border border-slate-700/30 rounded-xl p-1 gap-0.5">
          <button @click="viewMode = 'grid'" :class="['p-2 rounded-lg transition-all', viewMode === 'grid' ? 'bg-slate-700 text-white shadow-sm' : 'text-slate-500 hover:text-slate-300']"><Grid3X3 class="w-4 h-4" /></button>
          <button @click="viewMode = 'list'" :class="['p-2 rounded-lg transition-all', viewMode === 'list' ? 'bg-slate-700 text-white shadow-sm' : 'text-slate-500 hover:text-slate-300']"><List class="w-4 h-4" /></button>
        </div>
      </div>

      <!-- Drop Zone -->
      <div @drop="handleDrop" @dragover="handleDragOver" @dragleave="handleDragLeave" @click="triggerFileInput"
        :class="['border-2 border-dashed rounded-2xl p-6 sm:p-8 text-center transition-all cursor-pointer',
          dragOver ? 'border-indigo-400 bg-indigo-500/10 scale-[1.01]' : 'border-slate-700/50 bg-slate-800/10 hover:border-slate-600/50 hover:bg-slate-800/20']"
      >
        <CloudUpload :class="['w-10 h-10 sm:w-12 sm:h-12 mx-auto mb-3 transition-colors', dragOver ? 'text-indigo-400' : 'text-slate-600']" />
        <p class="text-slate-400 text-sm font-medium">{{ dragOver ? '释放以上传文件' : '拖拽文件到这里或点击选择' }}</p>
        <p class="text-slate-500 text-xs mt-1">支持文档(pdf/doc/docx/xls/xlsx/ppt/pptx/txt/md/csv)、图片(jpg/jpeg/png/gif/bmp/webp/svg)、音视频(mp3/wav/flac/mp4/mov/mkv/avi)、压缩包(zip/7z/rar)</p>
      </div>

      <!-- Upload Progress -->
      <div v-if="isUploading" class="bg-indigo-500/5 border border-indigo-500/20 rounded-xl p-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-white text-sm font-medium">正在上传...</span>
          <span class="text-indigo-400 text-sm font-bold">{{ uploadProgress }}%</span>
        </div>
        <div class="h-2 bg-slate-700 rounded-full overflow-hidden">
          <div class="h-full bg-gradient-to-r from-indigo-500 to-purple-500 rounded-full transition-all duration-300" :style="{ width: uploadProgress + '%' }"></div>
        </div>
      </div>

      <!-- Folders -->
      <div v-if="filesStore.folders.length > 0">
        <h3 class="text-sm font-semibold text-slate-400 mb-3 flex items-center gap-2">
          <FolderOpen class="w-4 h-4 text-yellow-400" />文件夹
        </h3>
        <div :class="viewMode === 'grid' ? 'grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-2 sm:gap-3' : 'space-y-1'">
          <div v-for="folder in filesStore.folders" :key="folder.id" @click="navigateToFolder(folder.id, folder.name)"
            class="group flex items-center gap-3 p-3 bg-slate-800/30 rounded-xl border border-slate-700/20 cursor-pointer hover:bg-slate-700/40 hover:border-yellow-500/30 transition-all"
          >
            <FolderOpen class="w-8 h-8 text-yellow-400 shrink-0 group-hover:scale-110 transition-transform" />
            <div class="min-w-0 flex-1">
              <p class="text-sm text-white truncate font-medium">{{ folder.name }}</p>
              <p class="text-xs text-slate-500">{{ formatDate(folder.created_at) }}</p>
            </div>
            <button @click.stop="handleDeleteFolder(folder)" class="p-1.5 text-slate-600 hover:text-red-400 hover:bg-red-500/10 rounded-lg opacity-0 group-hover:opacity-100 transition-all shrink-0" :title="'删除文件夹'">
              <Trash2 class="w-4 h-4" />
            </button>
            <ChevronRight class="w-4 h-4 text-slate-600 group-hover:text-slate-400 transition-colors shrink-0" />
          </div>
        </div>
      </div>

      <!-- Files -->
      <div v-if="filteredFiles.length > 0">
        <h3 class="text-sm font-semibold text-slate-400 mb-3 flex items-center gap-2">
          <FileText class="w-4 h-4 text-indigo-400" />文件列表
          <span class="text-slate-600 font-normal text-xs">共 {{ filteredFiles.length }} 个文件</span>
        </h3>
        <!-- Grid View -->
        <div v-if="viewMode === 'grid'" class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 2xl:grid-cols-8 gap-2 sm:gap-3">
          <div v-for="file in filteredFiles" :key="file.id"
            class="group relative bg-slate-800/30 rounded-xl border border-slate-700/20 hover:bg-slate-700/40 hover:border-slate-600/30 transition-all p-4"
          >
            <div class="flex flex-col items-center text-center">
              <div :class="['w-12 h-12 rounded-xl flex items-center justify-center mb-3', getFileBgColor(file.file_type)]">
                <component :is="getFileIcon(file.file_type)" :class="['w-6 h-6', getFileIconColor(file.file_type)]" />
              </div>
              <p class="text-xs text-white truncate w-full mb-1 font-medium">{{ file.original_name }}</p>
              <p class="text-xs text-slate-500">{{ formatFileSize(file.file_size) }}</p>
            </div>
            <div class="absolute top-2 right-2 flex gap-1 opacity-0 group-hover:opacity-100 transition-all">
              <button @click.stop="filesStore.downloadFile(file.id)" class="p-1.5 bg-slate-700/80 text-slate-400 hover:text-indigo-400 hover:bg-indigo-500/20 rounded-lg transition-all"><Download class="w-3.5 h-3.5" /></button>
              <button @click.stop="currentFile = file; showDeleteModal = true" class="p-1.5 bg-slate-700/80 text-slate-400 hover:text-red-400 hover:bg-red-500/20 rounded-lg transition-all"><Trash2 class="w-3.5 h-3.5" /></button>
            </div>
          </div>
        </div>
        <!-- List View -->
        <div v-else class="space-y-1">
          <div v-for="file in filteredFiles" :key="file.id"
            class="group flex items-center gap-3 p-3 bg-slate-800/30 rounded-xl border border-slate-700/20 hover:bg-slate-700/40 transition-all"
          >
            <div :class="['w-9 h-9 rounded-lg flex items-center justify-center shrink-0', getFileBgColor(file.file_type)]">
              <component :is="getFileIcon(file.file_type)" :class="['w-4 h-4', getFileIconColor(file.file_type)]" />
            </div>
            <div class="min-w-0 flex-1">
              <p class="text-sm text-white truncate">{{ file.original_name }}</p>
              <p class="text-xs text-slate-500">{{ formatFileSize(file.file_size) }} · {{ formatDate(file.created_at) }}</p>
            </div>
            <div class="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-all">
              <button @click="filesStore.downloadFile(file.id)" class="p-2 text-slate-400 hover:text-indigo-400 hover:bg-indigo-500/10 rounded-lg transition-all"><Download class="w-4 h-4" /></button>
              <button @click="currentFile = file; showDeleteModal = true" class="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all"><Trash2 class="w-4 h-4" /></button>
            </div>
          </div>
        </div>
      </div>

      <!-- Empty State -->
      <div v-if="filteredFiles.length === 0 && filesStore.folders.length === 0 && !isUploading" class="text-center py-16">
        <div class="w-24 h-24 bg-slate-800/50 rounded-full flex items-center justify-center mx-auto mb-4">
          <CloudUpload class="w-12 h-12 text-slate-600" />
        </div>
        <h3 class="text-lg font-semibold text-white mb-2">暂无文件</h3>
        <p class="text-slate-400 text-sm mb-6">点击上方按钮上传您的第一个文件</p>
        <button @click="triggerFileInput" class="inline-flex items-center gap-2 px-6 py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl cursor-pointer transition-all font-medium shadow-lg shadow-indigo-600/20">
          <Upload class="w-5 h-5" />{{ t.files.upload }}
        </button>
      </div>

      <!-- Toast -->
      <Transition name="toast">
        <div v-if="toastMessage" class="fixed top-4 right-4 z-50 px-4 py-3 bg-red-500/90 backdrop-blur text-white rounded-xl shadow-lg text-sm flex items-center gap-2">
          <AlertCircle class="w-4 h-4" />{{ toastMessage }}
        </div>
      </Transition>

      <!-- New Folder Modal -->
      <Teleport to="body">
        <Transition name="modal">
          <div v-if="showCreateFolder" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" @click.self="showCreateFolder = false">
            <div class="bg-slate-800 rounded-2xl p-6 w-full max-w-sm border border-slate-700/50 shadow-2xl">
              <div class="flex items-center justify-between mb-5">
                <h3 class="text-lg font-bold text-white flex items-center gap-2"><FolderPlus class="w-5 h-5 text-yellow-400" />{{ t.files.newFolder }}</h3>
                <button @click="showCreateFolder = false" class="text-slate-500 hover:text-white transition-colors"><X class="w-5 h-5" /></button>
              </div>
              <input v-model="newFolderName" :placeholder="t.files.folderName" @keyup.enter="createFolder"
                class="w-full bg-slate-700/50 border border-slate-600 rounded-xl px-4 py-3 text-white text-sm focus:outline-none focus:border-indigo-500 mb-4 transition-all placeholder-slate-500"
              />
              <div class="flex gap-3">
                <button @click="showCreateFolder = false" class="flex-1 py-2.5 bg-slate-700/50 text-slate-300 rounded-xl hover:bg-slate-700 transition-all text-sm font-medium">取消</button>
                <button @click="createFolder" :disabled="!newFolderName.trim()" class="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl transition-all text-sm font-medium">创建</button>
              </div>
            </div>
          </div>
        </Transition>
      </Teleport>

      <!-- Delete File Modal -->
      <Teleport to="body">
        <Transition name="modal">
          <div v-if="showDeleteModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" @click.self="showDeleteModal = false">
            <div class="bg-slate-800 rounded-2xl p-6 w-full max-w-sm border border-slate-700/50 shadow-2xl text-center">
              <div class="w-12 h-12 rounded-full bg-red-500/10 flex items-center justify-center mx-auto mb-4">
                <AlertCircle class="w-6 h-6 text-red-400" />
              </div>
              <h3 class="text-lg font-bold text-white mb-2">确定要删除吗？</h3>
              <p class="text-slate-400 text-sm mb-6">“{{ currentFile?.original_name || '' }}” 将被永久删除，无法恢复</p>
              <div class="flex gap-3">
                <button @click="showDeleteModal = false" class="flex-1 py-2.5 bg-slate-700/50 text-slate-300 rounded-xl hover:bg-slate-700 transition-all text-sm font-medium">取消</button>
                <button @click="handleDelete(currentFile)" class="flex-1 py-2.5 bg-red-500 hover:bg-red-600 text-white rounded-xl transition-all text-sm font-medium">确定删除</button>
              </div>
            </div>
          </div>
        </Transition>
      </Teleport>
    </div>
  </Layout>
</template>

<style scoped>
.toast-enter-active, .toast-leave-active { transition: all 0.3s ease; }
.toast-enter-from, .toast-leave-to { opacity: 0; transform: translateY(-20px); }
.modal-enter-active, .modal-leave-active { transition: all 0.2s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
.modal-enter-from > div, .modal-leave-to > div { transform: scale(0.95); }
.scrollbar-none::-webkit-scrollbar { display: none; }
.scrollbar-none { -ms-overflow-style: none; scrollbar-width: none; }
@keyframes spin{to{transform:rotate(360deg)}}
.animate-spin{animation:spin .8s linear infinite}
</style>
