<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useFilesStore } from '@/stores/files'
import Layout from '@/components/Layout.vue'
import { showToast } from '@/composables/useGlobalFeedback'
import { Trash2, RotateCcw, Trash, FileText, Loader2, AlertTriangle, X } from 'lucide-vue-next'

const filesStore = useFilesStore()
const deletedFiles = ref<any[]>([])
const loading = ref(false)

// Custom modal
const showModal = ref(false)
const modalType = ref<'restore' | 'delete'>('restore')
const modalTarget = ref<any>(null)
const modalLoading = ref(false)



async function loadDeleted() {
  loading.value = true
  try {
    const res = await filesStore.getDeletedFiles()
    if (res.success) {
      deletedFiles.value = res.data?.content || []
    }
  } catch (e: any) {
    console.error('RecycleBin load error:', e)
  }
  loading.value = false
}

function openModal(type: 'restore' | 'delete', file: any) {
  modalType.value = type
  modalTarget.value = file
  showModal.value = true
}

function closeModal() {
  if (!modalLoading.value) {
    showModal.value = false
    modalTarget.value = null
  }
}

async function confirmAction() {
  if (!modalTarget.value) return
  modalLoading.value = true
  const fileId = modalTarget.value.id
  let res: any
  if (modalType.value === 'restore') {
    res = await filesStore.restoreFile(fileId)
    if (res.success) {
      deletedFiles.value = deletedFiles.value.filter(f => f.id !== fileId)
      await filesStore.getStorageStats()
      showToast('恢复成功，文件已回到我的文件')
    } else {
      showToast(res.message || '恢复失败', 'error')
    }
  } else {
    res = await filesStore.permanentDeleteFile(fileId)
    if (res.success) {
      deletedFiles.value = deletedFiles.value.filter(f => f.id !== fileId)
      await filesStore.getStorageStats()
      showToast('已永久删除')
    } else {
      showToast(res.message || '删除失败', 'error')
    }
  }
  modalLoading.value = false
  showModal.value = false
  modalTarget.value = null
}

function formatSize(bytes: number): string {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

function formatDate(dateStr: string): string {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleDateString('zh-CN')
}

onMounted(loadDeleted)
</script>

<template>
  <Layout>
    <div class="p-3 sm:p-4 md:p-6">
      <h1 class="text-xl sm:text-2xl font-bold text-white mb-4 sm:mb-6 flex items-center gap-2">
        <Trash2 class="w-5 h-5 sm:w-6 sm:h-6 text-red-400" />回收站
      </h1>

      <div v-if="loading" class="text-center py-12 text-slate-400">
        <Loader2 class="w-6 h-6 animate-spin mx-auto mb-2" />加载中...
      </div>

      <div v-else-if="deletedFiles.length === 0" class="text-center py-12">
        <Trash2 class="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <p class="text-slate-400">回收站为空</p>
        <p class="text-slate-500 text-sm mt-1">删除的文件会出现在这里</p>
      </div>

      <div v-else class="bg-slate-800/50 rounded-xl border border-slate-700/30 overflow-hidden">
        <div class="hidden sm:grid grid-cols-12 gap-4 px-4 py-3 text-xs text-slate-500 border-b border-slate-700/30 bg-slate-800/80">
          <span class="col-span-5">文件名</span>
          <span class="col-span-2">大小</span>
          <span class="col-span-2">删除时间</span>
          <span class="col-span-3 text-right">操作</span>
        </div>
        <div v-for="file in deletedFiles" :key="file.id" class="grid grid-cols-1 sm:grid-cols-12 gap-2 sm:gap-4 px-4 py-3 border-b border-slate-700/20 hover:bg-slate-700/30 transition-colors items-center">
          <span class="col-span-5 text-white text-sm truncate flex items-center gap-2">
            <FileText class="w-4 h-4 text-slate-400 shrink-0" />{{ file.original_name || file.filename }}
          </span>
          <span class="col-span-2 text-slate-400 text-xs sm:text-sm">{{ formatSize(file.file_size) }}</span>
          <span class="col-span-2 text-slate-500 text-xs">{{ formatDate(file.created_at) }}</span>
          <span class="col-span-3 flex justify-end gap-2">
            <button @click="openModal('restore', file)" class="px-3 py-1.5 bg-green-600/20 text-green-400 rounded-lg hover:bg-green-600/30 text-xs flex items-center gap-1 transition-colors">
              <RotateCcw class="w-3 h-3" />恢复
            </button>
            <button @click="openModal('delete', file)" class="px-3 py-1.5 bg-red-600/20 text-red-400 rounded-lg hover:bg-red-600/30 text-xs flex items-center gap-1 transition-colors">
              <Trash class="w-3 h-3" />删除
            </button>
          </span>
        </div>
      </div>
    </div>

    <!-- Custom Confirmation Modal -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showModal" class="fixed inset-0 z-50 flex items-center justify-center p-4" @click.self="closeModal">
          <div class="absolute inset-0 bg-black/60 backdrop-blur-sm"></div>
          <div class="relative bg-slate-800/95 border border-slate-700/50 rounded-2xl shadow-2xl w-full max-w-md p-6">
            <button @click="closeModal" :disabled="modalLoading" class="absolute top-4 right-4 text-slate-500 hover:text-slate-300 transition-colors">
              <X class="w-5 h-5" />
            </button>

            <div class="text-center">
              <div v-if="modalType === 'restore'" class="w-14 h-14 mx-auto mb-4 rounded-2xl bg-green-500/10 flex items-center justify-center">
                <RotateCcw class="w-7 h-7 text-green-400" />
              </div>
              <div v-else class="w-14 h-14 mx-auto mb-4 rounded-2xl bg-red-500/10 flex items-center justify-center">
                <AlertTriangle class="w-7 h-7 text-red-400" />
              </div>
              <h3 class="text-lg font-bold text-white mb-1">{{ modalType === 'restore' ? '恢复文件' : '永久删除' }}</h3>
              <p class="text-sm text-slate-400 mb-2">
                {{ modalType === 'restore' ? '确定要将此文件恢复到我的文件吗？' : '永久删除后不可恢复，确定要继续吗？' }}
              </p>
              <p class="text-sm text-slate-500 mb-6 truncate px-2">{{ modalTarget?.original_name || modalTarget?.filename }}</p>
            </div>

            <div class="flex gap-3">
              <button @click="closeModal" :disabled="modalLoading" class="flex-1 py-2.5 rounded-xl border border-slate-600/50 text-slate-300 hover:bg-slate-700/50 transition-colors text-sm font-medium">
                取消
              </button>
              <button @click="confirmAction" :disabled="modalLoading"
                :class="modalType === 'restore'
                  ? 'flex-1 py-2.5 rounded-xl bg-green-600 hover:bg-green-500 text-white transition-colors text-sm font-medium flex items-center justify-center gap-2 disabled:opacity-50'
                  : 'flex-1 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-white transition-colors text-sm font-medium flex items-center justify-center gap-2 disabled:opacity-50'">
                <Loader2 v-if="modalLoading" class="w-4 h-4 animate-spin" />
                <span>{{ modalLoading ? '处理中...' : (modalType === 'restore' ? '确认恢复' : '确认删除') }}</span>
              </button>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

  </Layout>
</template>

<style scoped>
.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.25s ease;
}
.modal-enter-active > div:last-child,
.modal-leave-active > div:last-child {
  transition: transform 0.25s ease;
}
.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}
.modal-enter-from > div:last-child {
  transform: scale(0.95) translateY(10px);
}
.modal-leave-to > div:last-child {
  transform: scale(0.95) translateY(10px);
}

</style>