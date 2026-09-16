<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useAdminStore } from '@/stores/admin'
import Layout from '@/components/Layout.vue'
import { showToast } from '@/composables/useGlobalFeedback'
import { Upload, Loader2, X, Save, HardDrive, ArrowUpDown } from 'lucide-vue-next'

const adminStore = useAdminStore()
const loading = ref(true)
const showModal = ref(false)
const editingUser = ref<any>(null)
const editStorage = ref(300)
const editUpload = ref(100)
const saving = ref(false)

onMounted(async () => {
  loading.value = true
  try { await adminStore.getUsers(0, 100) } catch (e: any) { console.error(e) }
  loading.value = false
})

function openEdit(user: any) {
  editingUser.value = user
  editStorage.value = Math.round((user.storage_limit || 314572800) / 1024 / 1024)
  editUpload.value = user.upload_limit || 100
  showModal.value = true
}

async function handleSave() {
  if (!editingUser.value) return
  saving.value = true
  try {
    await adminStore.updateUser(editingUser.value.id, {
      storage_limit: editStorage.value * 1024 * 1024,
      upload_limit: editUpload.value
    })
    await adminStore.getUsers(0, 100)
    showModal.value = false
    showToast('已保存', 'success')
  } catch (e: any) { showToast('保存失败', 'error') }
  saving.value = false
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B'
  const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}
</script>

<template>
  <Layout>
    <div class="p-6 space-y-6">
      <div>
        <h1 class="text-2xl font-bold text-white flex items-center gap-2"><Upload class="w-6 h-6 text-indigo-400" />上传限制</h1>
        <p class="text-slate-400 mt-2 text-sm">管理每个用户的存储空间和每日上传数量限制</p>
      </div>

      <div v-if="loading" class="text-center py-12 text-slate-400"><Loader2 class="w-6 h-6 animate-spin mx-auto mb-2" />加载中...</div>

      <div v-else class="bg-slate-800/50 rounded-xl border border-slate-700/30 overflow-hidden">
        <table class="w-full">
          <thead>
            <tr class="border-b border-slate-700/50 bg-slate-800/80">
              <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">用户</th>
              <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">存储空间</th>
              <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">已使用</th>
              <th class="text-left px-4 py-3 text-xs text-slate-500 font-medium">每日上传</th>
              <th class="text-right px-4 py-3 text-xs text-slate-500 font-medium">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="user in adminStore.users" :key="user.id" class="border-b border-slate-700/20 hover:bg-slate-700/30 transition-colors">
              <td class="px-4 py-3">
                <div class="flex items-center gap-3">
                  <div class="w-8 h-8 rounded-full bg-slate-600 flex items-center justify-center overflow-hidden shrink-0">
                    <img v-if="user.avatar" :src="user.avatar" class="w-full h-full object-cover" />
                    <span v-else class="text-xs text-slate-300 font-medium">{{ (user.username || '?')[0] }}</span>
                  </div>
                  <div>
                    <p class="text-white text-sm">{{ user.username }}</p>
                    <p class="text-slate-500 text-xs">{{ user.email }}</p>
                  </div>
                </div>
              </td>
              <td class="px-4 py-3 text-sm text-white">{{ formatBytes(user.storage_limit || 0) }}</td>
              <td class="px-4 py-3">
                <div class="flex items-center gap-2">
                  <div class="w-20 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                    <div class="h-full bg-indigo-500 rounded-full" :style="{ width: Math.min(((user.storage_used || 0) / (user.storage_limit || 1)) * 100, 100) + '%' }"></div>
                  </div>
                  <span class="text-xs text-slate-400">{{ formatBytes(user.storage_used || 0) }}</span>
                </div>
              </td>
              <td class="px-4 py-3 text-sm text-white">{{ user.upload_limit === -1 ? '无限制' : (user.upload_limit || 100) + ' 个/天' }}</td>
              <td class="px-4 py-3 text-right">
                <button @click="openEdit(user)" class="px-4 py-2 bg-indigo-600/20 text-indigo-400 rounded-lg hover:bg-indigo-600/30 text-xs font-medium transition-all">调整</button>
              </td>
            </tr>
            <tr v-if="adminStore.users.length === 0">
              <td colspan="5" class="text-center py-12 text-slate-500">暂无用户数据</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Edit Modal -->
      <Teleport to="body">
        <div v-if="showModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" @click.self="showModal = false">
          <div class="bg-slate-800 rounded-2xl p-6 w-full max-w-md border border-slate-700/50 shadow-2xl">
            <div class="flex items-center justify-between mb-6">
              <h3 class="text-lg font-bold text-white flex items-center gap-2"><ArrowUpDown class="w-5 h-5 text-indigo-400" />调整限制</h3>
              <button @click="showModal = false" class="text-slate-500 hover:text-white"><X class="w-5 h-5" /></button>
            </div>

            <div v-if="editingUser" class="space-y-4">
              <div class="bg-slate-700/30 rounded-xl p-4 flex items-center gap-3">
                <div class="w-10 h-10 rounded-full bg-indigo-600 flex items-center justify-center text-white font-bold text-sm">{{ (editingUser.username || '?')[0] }}</div>
                <div>
                  <p class="text-white font-medium">{{ editingUser.username }}</p>
                  <p class="text-slate-500 text-xs">{{ editingUser.email }}</p>
                </div>
              </div>

              <div>
                <label class="text-slate-400 text-sm block mb-2 flex items-center gap-1.5"><HardDrive class="w-3.5 h-3.5" />存储空间 (MB)</label>
                <div class="flex items-center gap-2">
                  <input v-model.number="editStorage" type="range" min="50" max="10240" step="50" class="flex-1 accent-indigo-500" />
                  <span class="text-white font-mono text-sm w-16 text-right">{{ editStorage }} MB</span>
                </div>
                <div class="flex justify-between text-xs text-slate-500 mt-1">
                  <span>50 MB</span><span>{{ editStorage >= 1024 ? (editStorage / 1024).toFixed(1) + ' GB' : '' }}</span><span>10 GB</span>
                </div>
              </div>

              <div>
                <label class="text-slate-400 text-sm block mb-2 flex items-center gap-1.5"><Upload class="w-3.5 h-3.5" />每日上传数量</label>
                <div class="flex items-center gap-2">
                  <input v-model.number="editUpload" type="range" min="5" max="1000" step="5" class="flex-1 accent-indigo-500" />
                  <span class="text-white font-mono text-sm w-16 text-right">{{ editUpload }} 个</span>
                </div>
                <div class="flex justify-between text-xs text-slate-500 mt-1">
                  <span>5 个</span><span>1000 个</span>
                </div>
              </div>

              <button @click="handleSave" :disabled="saving" class="w-full py-3 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg font-medium transition-all flex items-center justify-center gap-2">
                <Loader2 v-if="saving" class="w-4 h-4 animate-spin" />
                <Save v-else class="w-4 h-4" />
                {{ saving ? '保存中...' : '保存设置' }}
              </button>
            </div>
          </div>
        </div>
      </Teleport>
    </div>
  </Layout>
</template>
