<script setup lang="ts">
import { ref, onMounted, computed } from "vue"
import { useSharesStore } from "@/stores/shares"
import { useFilesStore } from "@/stores/files"
import Layout from "@/components/Layout.vue"
import { Plus, Copy, Trash2, Check, Clock, Search, Globe, Lock, Languages, FileText, FolderOpen, ChevronDown, ChevronUp, Shield, Link, Calendar, Hash, Eye } from "lucide-vue-next"

const sharesStore = useSharesStore()
const filesStore = useFilesStore()
const locale = ref<"zh" | "en">("zh")

const showCreate = ref(false)
const selectedTarget = ref<string | null>(null)  // format: 'file:123' or 'folder:456'
const selectedFileId = ref<number | null>(null)
const expireDays = ref(7)
const sharePassword = ref("")
const shareDescription = ref("")
const shareContact = ref("")
const shareSharerName = ref("")
const shareDownloadLimit = ref(0)
const copiedCode = ref<string | null>(null)
const searchQuery = ref("")
const showDeleteModal = ref(false)
const deleteTargetId = ref<number | null>(null)
const activeTab = ref("all")

const t = computed(() => locale.value === "zh" ? zhTexts : enTexts)

const zhTexts = {
  title: "我的分享", subtitle: "管理和分享您的文件",
  createShare: "创建新分享", creating: "创建中...",
  shareType: "分享类型", fileShare: "文件分享", folderShare: "文件夹分享",
  selectFile: "选择文件", selectFileHint: "请选择要分享的文件",
  description: "文件描述（可选）", descHint: "描述这个分享的内容、用途或注意事项",
  password: "分享密码（可选）", pwHint: "留空表示无密码，4-10个字符",
  sharerName: "分享者名称（可选）", sharerNameHint: "显示在分享页面的分享者名称，留空使用用户名",
  contact: "联系分享者（可选）", contactHint: "提供联系方式，方便他人获取密码",
  expireDays: "有效期（天）", day1: "1天", day7: "7天", day15: "15天", day30: "30天", permanent: "永久有效",
  downloadLimit: "下载次数限制（0 为不限）",
  createBtn: "创建分享",
  myShares: "我的分享列表", total: "共", sharesUnit: "个分享",
  shareCode: "分享码", type: "类型", fileType: "文件分享", folderType: "文件夹分享",
  created: "创建时间", hasPassword: "有密码保护", noExpire: "永久有效",
  copyLink: "复制链接", delete: "删除", deleteConfirm: "确定要删除这个分享吗？",
  all: "全部", active: "有效", expired: "已过期",
  searchHint: "搜索分享码...",
  noShares: "暂无分享记录", noSharesDesc: "创建您的第一个分享吧",
  copySuccess: "已复制",
  chooseDays: "选择天数",
}

const enTexts = {
  title: "My Shares", subtitle: "Manage and share your files",
  createShare: "Create Share", creating: "Creating...",
  shareType: "Share Type", fileShare: "File Share", folderShare: "Folder Share",
  selectFile: "Select File", selectFileHint: "Choose a file to share",
  description: "Description (optional)", descHint: "Describe the content, usage, or notes for downloaders",
  password: "Password (optional)", pwHint: "Leave empty for no password, 4-10 chars",
  sharerName: "Sharer Name (optional)", sharerNameHint: "Name shown on share page, empty = username",
  contact: "Contact (optional)", contactHint: "Provide contact info for password inquiries",
  expireDays: "Expiry (days)", day1: "1 Day", day7: "7 Days", day15: "15 Days", day30: "30 Days", permanent: "Permanent",
  downloadLimit: "Download Limit (0 = unlimited)",
  createBtn: "Create",
  myShares: "My Shares", total: "Total", sharesUnit: "shares",
  shareCode: "Code", type: "Type", fileType: "File Share", folderType: "Folder Share",
  created: "Created", hasPassword: "Password Protected", noExpire: "Permanent",
  copyLink: "Copy Link", delete: "Delete", deleteConfirm: "Delete this share?",
  all: "All", active: "Active", expired: "Expired",
  searchHint: "Search by code...",
  noShares: "No shares yet", noSharesDesc: "Create your first share",
  copySuccess: "Copied",
  chooseDays: "Choose days",
}

const tabs = computed(() => [
  { id: "all", label: t.value.all },
  { id: "active", label: t.value.active },
  { id: "expired", label: t.value.expired },
])

const expireOptions = [
  { value: 1, label: () => locale.value === "zh" ? "1天" : "1 Day" },
  { value: 7, label: () => locale.value === "zh" ? "7天" : "7 Days" },
  { value: 15, label: () => locale.value === "zh" ? "15天" : "15 Days" },
  { value: 30, label: () => locale.value === "zh" ? "30天" : "30 Days" },
  { value: 0, label: () => locale.value === "zh" ? "永久有效" : "Permanent" },
]

onMounted(async () => {
  await Promise.all([
    filesStore.getFiles(0, 0, 200),
    filesStore.getFolders(0),
    sharesStore.getShares()
  ])
})

const filteredShares = computed(() => {
  let items = sharesStore.shares
  if (activeTab.value === "active") items = items.filter(s => isActive(s))
  if (activeTab.value === "expired") items = items.filter(s => !isActive(s))
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    items = items.filter(s => (s.share_code || "").toLowerCase().includes(q))
  }
  return items
})

function isActive(s: any): boolean {
  if (s.status !== 1) return false
  if (s.expire_time && new Date(s.expire_time) < new Date()) return false
  return true
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "-"
  return new Date(dateStr).toLocaleDateString("zh-CN", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
}

function getExpireLabel(s: any): string {
  if (!s.expire_time) return locale.value === "zh" ? "永久有效" : "Permanent"
  const d = new Date(s.expire_time)
  if (d.getTime() > new Date("2099-01-01").getTime()) return locale.value === "zh" ? "永久有效" : "Permanent"
  return formatDate(s.expire_time)
}

function copyCode(share: any) {
  const url = window.location.origin + "/share/" + share.share_code
  navigator.clipboard.writeText(url)
  copiedCode.value = share.share_code
  setTimeout(() => copiedCode.value = null, 2000)
}

async function handleCreateShare() {
  if (!selectedTarget.value) return
  const parts = selectedTarget.value.split(':')
  const type = parts[0] as 'file' | 'folder'
  const id = Number(parts[1])
  if (!id) return
  
  const shareType = type === 'folder' ? 2 : 1
  await sharesStore.createShare(id, {
    days: expireDays.value,
    password: sharePassword.value,
    description: shareDescription.value,
    contact: shareContact.value,
    sharerName: shareSharerName.value,
    downloadLimit: shareDownloadLimit.value,
    shareType: shareType,
  })
  await sharesStore.getShares()
  showCreate.value = false
  selectedTarget.value = null
  sharePassword.value = ""
  shareDescription.value = ""
  shareContact.value = ""
  expireDays.value = 7
  shareDownloadLimit.value = 0
}

async function handleDelete(shareId: number) {
  deleteTargetId.value = shareId
  showDeleteModal.value = true
}
async function confirmDelete() {
  if (deleteTargetId.value !== null) {
    await sharesStore.deleteShare(deleteTargetId.value)
    showDeleteModal.value = false
    deleteTargetId.value = null
    await sharesStore.getShares()
  }
}
function cancelDelete() {
  showDeleteModal.value = false
  deleteTargetId.value = null
}

function toggleLocale() { locale.value = locale.value === "zh" ? "en" : "zh" }
</script>


<template>
  <Layout>
    <div class="p-4 sm:p-6 xl:p-8 w-full space-y-5">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div class="flex items-center gap-3 mb-1">
            <h1 class="text-xl sm:text-2xl font-bold text-white">{{ t.title }}</h1>
            <button @click="toggleLocale" class="flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs text-slate-400 hover:text-white transition-colors">
              <Languages class="w-3.5 h-3.5" />{{ locale === "zh" ? "EN" : "中" }}
            </button>
          </div>
          <p class="text-slate-400 text-xs sm:text-sm">{{ t.subtitle }}</p>
        </div>
        <button @click="showCreate = !showCreate"
          :class="['flex items-center gap-2 px-5 py-2.5 rounded-xl transition-all text-sm font-medium',
            showCreate ? 'bg-slate-700 text-white' : 'bg-violet-600 hover:bg-violet-500 text-white shadow-lg shadow-violet-500/20']">
          <component :is="showCreate ? ChevronUp : Plus" class="w-4 h-4" />
          {{ t.createShare }}
        </button>
      </div>

      <!-- Inline Create Form -->
      <Transition name="slide">
        <div v-if="showCreate" class="bg-slate-800/60 rounded-2xl border border-slate-700/30 p-5 space-y-5">
          <!-- Select File or Folder -->
          <div>
            <label class="block text-sm text-slate-400 mb-2">{{ locale === 'zh' ? '选择文件或文件夹' : 'Select File or Folder' }}</label>
            <select v-model="selectedTarget"
              class="w-full px-4 py-3 bg-slate-800/50 border border-slate-700/30 rounded-xl text-white text-sm focus:outline-none focus:border-violet-500/50 transition-colors">
              <option :value="null">{{ locale === 'zh' ? '请选择要分享的文件或文件夹' : 'Select a file or folder' }}</option>
              <optgroup v-if="filesStore.files.length > 0" label="文件">
                <option v-for="file in filesStore.files" :key="'f'+file.id" :value="'file:'+file.id">
                  {{ file.original_name }} ({{ ((file.file_size || 0) / 1024).toFixed(1) }} KB)
                </option>
              </optgroup>
              <optgroup v-if="filesStore.folders.length > 0" label="文件夹">
                <option v-for="folder in filesStore.folders" :key="'d'+folder.id" :value="'folder:'+folder.id">
                  {{ folder.name }}
                </option>
              </optgroup>
            </select>
          </div>

          <!-- Description -->
          <div>
            <label class="block text-sm text-slate-400 mb-2">{{ t.description }}</label>
            <textarea v-model="shareDescription" :placeholder="t.descHint" rows="2"
              class="w-full px-4 py-3 bg-slate-800/50 border border-slate-700/30 rounded-xl text-white text-sm placeholder-slate-500 focus:outline-none focus:border-violet-500/50 resize-none transition-colors"></textarea>
          </div>

          <!-- Sharer Name -->
          <div>
            <label class="block text-sm text-slate-400 mb-2">{{ t.sharerName }}</label>
            <input v-model="shareSharerName" type="text" :placeholder="t.sharerNameHint" maxlength="100"
              class="w-full px-4 py-3 bg-slate-800/50 border border-slate-700/30 rounded-xl text-white text-sm placeholder-slate-500 focus:outline-none focus:border-violet-500/50 transition-colors" />
          </div>

          <!-- Contact -->
          <div>
            <label class="block text-sm text-slate-400 mb-2">{{ t.contact }}</label>
            <input v-model="shareContact" type="text" :placeholder="t.contactHint"
              class="w-full px-4 py-3 bg-slate-800/50 border border-slate-700/30 rounded-xl text-white text-sm placeholder-slate-500 focus:outline-none focus:border-violet-500/50 transition-colors" />
          </div>

          <!-- Download Limit -->
          <div>
            <label class="block text-sm text-slate-400 mb-2">{{ t.downloadLimit }}</label>
            <input v-model.number="shareDownloadLimit" type="number" min="0" max="9999" placeholder="0 = 不限"
              class="w-full px-4 py-3 bg-slate-800/50 border border-slate-700/30 rounded-xl text-white text-sm placeholder-slate-500 focus:outline-none focus:border-violet-500/50 transition-colors" />
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <!-- Password -->
            <div>
              <label class="block text-sm text-slate-400 mb-2">{{ t.password }}</label>
              <input v-model="sharePassword" type="text" :placeholder="t.pwHint" minlength="4" maxlength="10"
                class="w-full px-4 py-3 bg-slate-800/50 border border-slate-700/30 rounded-xl text-white text-sm placeholder-slate-500 focus:outline-none focus:border-violet-500/50 transition-colors" />
            </div>
            <!-- Expiry -->
            <div>
              <label class="block text-sm text-slate-400 mb-2">{{ t.expireDays }}</label>
              <div class="flex gap-2 flex-wrap">
                <button v-for="opt in expireOptions" :key="opt.value"
                  @click="expireDays = opt.value"
                  :class="['px-3 py-2 rounded-lg text-xs font-medium transition-all border',
                    expireDays === opt.value ? 'bg-violet-500/20 text-violet-400 border-violet-500/30' : 'bg-slate-700/30 text-slate-400 border-slate-700/30 hover:bg-slate-700/50']">
                  {{ opt.label() }}
                </button>
              </div>
            </div>
          </div>

          <!-- Create Button -->
          <button @click="handleCreateShare" :disabled="!selectedTarget"
            :class="['w-full py-3 rounded-xl text-sm font-medium transition-all',
              selectedTarget ? 'bg-violet-600 hover:bg-violet-500 text-white shadow-lg shadow-violet-500/20' : 'bg-slate-700/50 text-slate-500 cursor-not-allowed']">
            {{ t.createBtn }}
          </button>
        </div>
      </Transition>

      <!-- Share List -->
      <div class="bg-slate-800/60 rounded-2xl border border-slate-700/30 overflow-hidden">
        <!-- List Header -->
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-5 py-4 border-b border-slate-700/30">
          <div class="flex items-center gap-2">
            <Link class="w-4 h-4 text-violet-400" />
            <span class="text-white font-medium text-sm">{{ t.myShares }}</span>
            <span class="text-xs text-slate-500 bg-slate-700/50 px-2 py-0.5 rounded-full">{{ t.total }} {{ filteredShares.length }} {{ t.sharesUnit }}</span>
          </div>
          <div class="flex items-center gap-2">
            <div class="flex bg-slate-700/30 rounded-lg p-0.5">
              <button v-for="tab in tabs" :key="tab.id" @click="activeTab = tab.id"
                :class="['px-3 py-1.5 rounded-md text-xs font-medium transition-all',
                  activeTab === tab.id ? 'bg-violet-500/20 text-violet-400' : 'text-slate-400 hover:text-slate-300']">
                {{ tab.label }}
              </button>
            </div>
            <div class="relative">
              <Search class="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
              <input v-model="searchQuery" :placeholder="t.searchHint"
                class="w-40 pl-9 pr-3 py-2 bg-slate-700/30 border border-slate-700/30 rounded-lg text-white text-xs placeholder-slate-500 focus:outline-none focus:border-violet-500/30" />
            </div>
          </div>
        </div>

        <!-- Share Items -->
        <div class="divide-y divide-slate-700/20">
          <div v-if="filteredShares.length === 0" class="text-center py-16">
            <Link class="w-10 h-10 mx-auto mb-3 text-slate-600" />
            <p class="text-slate-400 text-sm">{{ t.noShares }}</p>
            <p class="text-slate-500 text-xs mt-1">{{ t.noSharesDesc }}</p>
          </div>

          <div v-for="share in filteredShares" :key="share.id"
            class="px-5 py-4 hover:bg-slate-700/20 transition-colors group">
            <div class="flex items-start gap-4">
              <!-- Icon -->
              <div :class="['flex-shrink-0 w-10 h-10 rounded-xl flex items-center justify-center',
                share.share_type === 2 ? 'bg-amber-500/10 text-amber-400' : 'bg-violet-500/10 text-violet-400']">
                <component :is="share.share_type === 2 ? FolderOpen : FileText" class="w-5 h-5" />
              </div>

              <!-- Content -->
              <div class="flex-1 min-w-0">
                <div class="flex items-start justify-between gap-2">
                  <div class="min-w-0">
                    <h3 class="text-white text-sm font-medium leading-tight truncate">
                      {{ share.file_name || share.share_code || "未命名" }}
                    </h3>
                    <p v-if="share.description" class="text-slate-500 text-xs mt-0.5 line-clamp-2">{{ share.description }}</p>
                  </div>
                  <div class="flex items-center gap-1.5 flex-shrink-0">
                    <button @click="copyCode(share)"
                      :class="['flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium transition-all',
                        copiedCode === share.share_code ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-700/50 text-slate-400 hover:bg-slate-600/50 hover:text-white']">
                      <component :is="copiedCode === share.share_code ? Check : Copy" class="w-3 h-3" />
                      {{ copiedCode === share.share_code ? t.copySuccess : t.copyLink }}
                    </button>
                    <button @click="handleDelete(share.id)"
                      class="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-all opacity-0 group-hover:opacity-100">
                      <Trash2 class="w-4 h-4" />
                    </button>
                  </div>
                </div>

                <!-- Meta -->
                <div class="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2">
                  <span class="flex items-center gap-1 text-xs text-slate-500">
                    <Hash class="w-3 h-3" />
                    {{ t.shareCode }}: <code class="text-slate-300 font-mono">{{ share.share_code }}</code>
                  </span>
                  <span class="flex items-center gap-1 text-xs text-slate-500">
                    <Eye class="w-3 h-3" />
                    {{ share.share_type === 2 ? t.folderType : t.fileType }}
                  </span>
                  <span class="flex items-center gap-1 text-xs text-slate-500">
                    <Calendar class="w-3 h-3" />
                    {{ formatDate(share.created_at) }}
                  </span>
                  <span class="flex items-center gap-1 text-xs text-slate-500">
                    <Clock class="w-3 h-3" />
                    {{ getExpireLabel(share) }}
                  </span>
                  <span v-if="share.has_password" class="flex items-center gap-1 text-xs text-amber-400">
                    <Lock class="w-3 h-3" />
                    {{ t.hasPassword }}
                  </span>
                  <span v-if="!isActive(share)" class="px-1.5 py-0.5 text-xs rounded bg-red-500/10 text-red-400">
                    {{ t.expired }}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </Layout>

  <!-- Delete Confirm Modal -->
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="showDeleteModal" class="modal-overlay" @click.self="cancelDelete">
        <div class="modal-dialog">
          <div class="modal-icon-box">
            <svg class="modal-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <h3 class="modal-title">{{ locale === 'zh' ? '确定要删除这个分享吗？' : 'Delete this share?' }}</h3>
          <p class="modal-desc">{{ locale === 'zh' ? '删除后将无法恢复，分享链接将立即失效' : 'This action cannot be undone. The share link will be invalidated.' }}</p>
          <div class="modal-actions">
            <button @click="cancelDelete" class="modal-btn modal-btn-cancel">{{ locale === 'zh' ? '取消' : 'Cancel' }}</button>
            <button @click="confirmDelete" class="modal-btn modal-btn-delete">{{ locale === 'zh' ? '确定删除' : 'Delete' }}</button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>


<style scoped>
.slide-enter-active, .slide-leave-active { transition: all 0.25s ease; }
.slide-enter-from, .slide-leave-to { opacity: 0; transform: translateY(-8px); }
.line-clamp-2 { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }

/* Modal */
.modal-overlay{position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:20px}
.modal-dialog{background:#1e293b;border:1px solid rgba(99,102,241,0.2);border-radius:20px;padding:32px;max-width:400px;width:100%;text-align:center;box-shadow:0 25px 60px rgba(0,0,0,0.5)}
.modal-icon-box{width:56px;height:56px;border-radius:50%;background:rgba(239,68,68,0.1);display:flex;align-items:center;justify-content:center;margin:0 auto 16px}
.modal-icon{width:28px;height:28px;color:#ef4444}
.modal-title{font-size:18px;font-weight:700;color:#f1f5f9;margin-bottom:8px}
.modal-desc{font-size:13px;color:#94a3b8;line-height:1.5;margin-bottom:24px}
.modal-actions{display:flex;gap:12px}
.modal-btn{flex:1;padding:12px 20px;border-radius:12px;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.2s;border:none}
.modal-btn-cancel{background:rgba(71,85,105,0.3);color:#cbd5e1}
.modal-btn-cancel:hover{background:rgba(71,85,105,0.5)}
.modal-btn-delete{background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff}
.modal-btn-delete:hover{transform:translateY(-1px);box-shadow:0 4px 16px rgba(239,68,68,0.3)}

.modal-enter-active,.modal-leave-active{transition:all 0.2s ease}
.modal-enter-from,.modal-leave-to{opacity:0}
.modal-enter-from .modal-dialog,.modal-leave-to .modal-dialog{transform:scale(0.9)}
</style>
