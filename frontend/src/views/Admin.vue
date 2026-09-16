<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useAdminStore } from '@/stores/admin'
import Layout from '@/components/Layout.vue'
import { showToast } from '@/composables/useGlobalFeedback'
import { 
  Users, 
  Search, 
  ChevronDown, 
  ChevronUp,
  Shield,
  Lock,
  Unlock,
  Cloud,
  FileText,
  Share2,
  Edit,
  AlertCircle,
  X,
  Crown,
  Mail,
  Calendar,
  User
} from 'lucide-vue-next'

const users = ref<any[]>([])
const searchKeyword = ref('')
const expandedUserId = ref<number | null>(null)
const showEditModal = ref(false)
const showBanModal = ref(false)
const currentUser = ref<any>(null)
const newStorageLimit = ref(0)
const newUploadLimit = ref(850)
const banReason = ref('')
const adminStore = useAdminStore()

const storageOptions = [
  { label: '100 MB', value: 100 * 1024 * 1024 },
  { label: '300 MB', value: 300 * 1024 * 1024 },
  { label: '500 MB', value: 500 * 1024 * 1024 },
  { label: '1 GB', value: 1 * 1024 * 1024 * 1024 },
  { label: '5 GB', value: 5 * 1024 * 1024 * 1024 },
  { label: '10 GB', value: 10 * 1024 * 1024 * 1024 },
  { label: '无限', value: 0 }
]

const uploadOptions = [
  { label: '10 MB', value: 10 },
  { label: '20 MB', value: 20 },
  { label: '50 MB', value: 50 },
  { label: '100 MB', value: 100 },
  { label: '500 MB', value: 500 },
  { label: '850 MB', value: 850 },
  { label: '无限', value: 0 }
]

onMounted(async () => {
  await loadUsers()
})

async function loadUsers() {
  try {
    const res = await adminStore.getUsers(0, 50); users.value = (res as any).data?.content || []  } catch (error) {
    console.error('Failed to load users:', error)
  }
}

const filteredUsers = computed(() => {
  if (!searchKeyword.value.trim()) return users.value
  const keyword = searchKeyword.value.toLowerCase()
  return users.value.filter(user => 
    user.username.toLowerCase().includes(keyword) ||
    user.email.toLowerCase().includes(keyword)
  )
})

function formatStorage(bytes: number): string {
  if (bytes === 0) return '无限'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

function formatUploadLimit(limit: number): string {
  if (limit === 0) return '无限'
  return limit + ' MB'
}

function getStatusInfo(status: string) {
  const statusMap: Record<string, { label: string; class: string; icon: any }> = {
    active: { label: '正常', class: 'bg-green-500/20 text-green-400', icon: Unlock },
    banned: { label: '已封禁', class: 'bg-red-500/20 text-red-400', icon: Lock },
    disabled: { label: '已禁用', class: 'bg-slate-500/20 text-slate-400', icon: AlertCircle }
  }
  return statusMap[status] || statusMap.active
}

function getStoragePercentage(user: any): number {
  if (!user.storage_limit || user.storage_limit === 0) return 0
  return Math.min((user.storage_used / user.storage_limit) * 100, 100)
}

function toggleExpand(userId: number) {
  expandedUserId.value = expandedUserId.value === userId ? null : userId
}

function openEditModal(user: any) {
  currentUser.value = user
  newStorageLimit.value = user.storage_limit || 314572800
  newUploadLimit.value = user.upload_limit || 50
  showEditModal.value = true
}

function openBanModal(user: any) {
  currentUser.value = user
  banReason.value = ''
  showBanModal.value = true
}

async function handleSaveUser() {
  const index = users.value.findIndex(u => u.id === currentUser.value.id)
  if (index !== -1) {
    users.value[index].storage_limit = newStorageLimit.value
    users.value[index].upload_limit = newUploadLimit.value
  }
  showEditModal.value = false
  currentUser.value = null
}

async function handleBanUser() {
  if (!banReason.value.trim()) {
    showToast('请输入封禁原因', 'error')
    return
  }
  const index = users.value.findIndex(u => u.id === currentUser.value.id)
  if (index !== -1) {
    users.value[index].user_status = 'banned'
    users.value[index].ban_reason = banReason.value
  }
  showBanModal.value = false
  currentUser.value = null
}

async function handleUnbanUser(userId: number) {
  const index = users.value.findIndex(u => u.id === userId)
  if (index !== -1) {
    users.value[index].user_status = 'active'
    users.value[index].ban_reason = ''
  }
}

async function handleDisableUser(userId: number) {
  const index = users.value.findIndex(u => u.id === userId)
  if (index !== -1) {
    users.value[index].user_status = 'disabled'
  }
}

async function handleEnableUser(userId: number) {
  const index = users.value.findIndex(u => u.id === userId)
  if (index !== -1) {
    users.value[index].user_status = 'active'
  }
}
</script>

<template>
  <Layout>
    <div class="space-y-6">
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-3xl font-bold text-white">
            <span class="bg-gradient-to-r from-red-400 via-orange-400 to-amber-400 bg-clip-text text-transparent">用户管理</span>
          </h1>
          <p class="text-slate-400 mt-2">管理所有用户账号和权限</p>
        </div>
        <div class="flex items-center gap-2">
          <div class="flex items-center gap-2 px-5 py-2.5 bg-red-500/10 rounded-xl border border-red-500/20">
            <Shield class="w-5 h-5 text-red-400" />
            <span class="text-red-300 font-medium">管理员权限</span>
          </div>
        </div>
      </div>

      <div class="bg-slate-800/40 backdrop-blur-xl rounded-2xl p-6 border border-slate-700/30">
        <div class="flex items-center justify-between mb-6">
          <div class="relative flex-1 max-w-md">
            <Search class="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400" />
            <input
              v-model="searchKeyword"
              type="text"
              placeholder="搜索用户名或邮箱..."
              class="w-full pl-12 pr-4 py-3 bg-slate-700/30 border border-slate-600/30 rounded-xl text-white placeholder-slate-400 focus:ring-2 focus:ring-red-500/50 focus:border-red-500/50 outline-none transition-all"
            />
          </div>
          <div class="flex items-center gap-4">
            <div class="flex items-center gap-2 px-4 py-2 bg-green-500/10 rounded-lg">
              <div class="w-2 h-2 bg-green-500 rounded-full"></div>
              <span class="text-green-400 text-sm font-medium">{{ users.filter(u => u.user_status === 'active').length }} 正常</span>
            </div>
            <div class="flex items-center gap-2 px-4 py-2 bg-red-500/10 rounded-lg">
              <div class="w-2 h-2 bg-red-500 rounded-full"></div>
              <span class="text-red-400 text-sm font-medium">{{ users.filter(u => u.user_status === 'banned').length }} 封禁</span>
            </div>
            <div class="flex items-center gap-2 px-4 py-2 bg-slate-500/10 rounded-lg">
              <div class="w-2 h-2 bg-slate-500 rounded-full"></div>
              <span class="text-slate-400 text-sm font-medium">{{ users.filter(u => u.user_status === 'disabled').length }} 禁用</span>
            </div>
          </div>
        </div>

        <div class="space-y-4">
          <div 
            v-for="user in filteredUsers" 
            :key="user.id"
            class="bg-slate-700/20 rounded-2xl border border-slate-600/30 overflow-hidden transition-all hover:border-slate-500/50"
          >
            <div 
              @click="toggleExpand(user.id)"
              class="flex items-center gap-4 p-5 cursor-pointer"
            >
              <div class="relative">
                <div 
                  :class="[
                    'w-12 h-12 rounded-xl flex items-center justify-center',
                    user.is_official 
                      ? 'bg-gradient-to-br from-red-500 via-orange-500 to-amber-500' 
                      : user.role === 'admin'
                        ? 'bg-gradient-to-br from-amber-500 to-orange-500'
                        : 'bg-gradient-to-br from-blue-500 via-purple-500 to-pink-500'
                  ]"
                >
                  <Crown v-if="user.is_official" class="w-6 h-6 text-white" />
                  <User v-else class="w-6 h-6 text-white" />
                </div>
              </div>
              
              <div class="flex-1">
                <div class="flex items-center gap-3">
                  <span 
                    :class="[
                      'font-semibold text-lg',
                      user.is_official ? 'text-red-400' : 'text-white'
                    ]"
                  >
                    {{ user.username }}
                  </span>
                  <span 
                    v-if="user.is_official"
                    class="px-2 py-0.5 bg-gradient-to-r from-red-500 to-orange-500 text-white text-xs font-bold rounded-full"
                  >
                    官方
                  </span>
                  <span 
                    v-else-if="user.role === 'admin'"
                    class="px-2 py-0.5 bg-amber-500/20 text-amber-400 text-xs font-medium rounded-full"
                  >
                    管理员
                  </span>
                  <span 
                    :class="['px-2 py-0.5 text-xs font-medium rounded-full flex items-center gap-1', getStatusInfo(user.user_status).class]"
                  >
                    <component :is="getStatusInfo(user.user_status).icon" class="w-3 h-3" />
                    {{ getStatusInfo(user.user_status).label }}
                  </span>
                </div>
                <div class="flex items-center gap-4 mt-1 text-sm text-slate-400">
                  <span class="flex items-center gap-1">
                    <Mail class="w-4 h-4" />
                    {{ user.email }}
                  </span>
                  <span class="flex items-center gap-1">
                    <Calendar class="w-4 h-4" />
                    {{ user.created_at }}
                  </span>
                </div>
              </div>

              <div class="flex items-center gap-6">
                <div class="text-right">
                  <div class="flex items-center gap-2 mb-1">
                    <Cloud class="w-4 h-4 text-cyan-400" />
                    <span class="text-slate-300 text-sm">{{ formatStorage(user.storage_used) }} / {{ formatStorage(user.storage_limit) }}</span>
                  </div>
                  <div class="w-32 bg-slate-600/50 rounded-full h-1.5">
                    <div 
                      class="bg-gradient-to-r from-cyan-500 to-blue-500 h-1.5 rounded-full transition-all"
                      :style="{ width: `${getStoragePercentage(user)}%` }"
                    ></div>
                  </div>
                </div>
                
                <div class="flex items-center gap-2">
                  <button 
                    @click.stop="openEditModal(user)"
                    class="p-2.5 text-slate-400 hover:text-blue-400 hover:bg-blue-500/10 rounded-xl transition-all"
                  >
                    <Edit class="w-5 h-5" />
                  </button>
                  <component 
                    :is="expandedUserId === user.id ? ChevronUp : ChevronDown" 
                    class="w-5 h-5 text-slate-400" 
                  />
                </div>
              </div>
            </div>

            <div 
              v-if="expandedUserId === user.id"
              class="border-t border-slate-600/30 bg-slate-800/30 p-5"
            >
              <div class="grid grid-cols-1 md:grid-cols-3 gap-5 mb-5">
                <div class="bg-slate-700/30 rounded-xl p-4">
                  <div class="flex items-center gap-3 mb-3">
                    <div class="w-10 h-10 bg-blue-500/10 rounded-lg flex items-center justify-center">
                      <FileText class="w-5 h-5 text-blue-400" />
                    </div>
                    <span class="text-slate-400">文件数量</span>
                  </div>
                  <p class="text-2xl font-bold text-white">{{ user.file_count }}</p>
                </div>
                <div class="bg-slate-700/30 rounded-xl p-4">
                  <div class="flex items-center gap-3 mb-3">
                    <div class="w-10 h-10 bg-green-500/10 rounded-lg flex items-center justify-center">
                      <Share2 class="w-5 h-5 text-green-400" />
                    </div>
                    <span class="text-slate-400">分享链接</span>
                  </div>
                  <p class="text-2xl font-bold text-white">{{ user.share_count }}</p>
                </div>
                <div class="bg-slate-700/30 rounded-xl p-4">
                  <div class="flex items-center gap-3 mb-3">
                    <div class="w-10 h-10 bg-purple-500/10 rounded-lg flex items-center justify-center">
                      <Cloud class="w-5 h-5 text-purple-400" />
                    </div>
                    <span class="text-slate-400">上传限制</span>
                  </div>
                  <p class="text-2xl font-bold text-white">{{ formatUploadLimit(user.upload_limit) }}</p>
                </div>
              </div>

              <div v-if="user.ban_reason" class="mb-5 p-4 bg-red-500/10 rounded-xl border border-red-500/20">
                <div class="flex items-center gap-2 mb-2">
                  <AlertCircle class="w-5 h-5 text-red-400" />
                  <span class="text-red-300 font-medium">封禁原因</span>
                </div>
                <p class="text-slate-300">{{ user.ban_reason }}</p>
              </div>

              <div class="flex items-center gap-3">
                <template v-if="user.user_status === 'active'">
                  <button 
                    @click="openBanModal(user)"
                    class="flex items-center gap-2 px-4 py-2.5 bg-red-500/10 text-red-400 rounded-xl hover:bg-red-500/20 transition-all border border-red-500/20"
                  >
                    <Lock class="w-4 h-4" />
                    封禁账号
                  </button>
                  <button 
                    @click="handleDisableUser(user.id)"
                    class="flex items-center gap-2 px-4 py-2.5 bg-slate-500/10 text-slate-400 rounded-xl hover:bg-slate-500/20 transition-all border border-slate-500/20"
                  >
                    <AlertCircle class="w-4 h-4" />
                    禁用账号
                  </button>
                </template>
                <template v-else-if="user.user_status === 'banned'">
                  <button 
                    @click="handleUnbanUser(user.id)"
                    class="flex items-center gap-2 px-4 py-2.5 bg-green-500/10 text-green-400 rounded-xl hover:bg-green-500/20 transition-all border border-green-500/20"
                  >
                    <Unlock class="w-4 h-4" />
                    解封账号
                  </button>
                </template>
                <template v-else-if="user.user_status === 'disabled'">
                  <button 
                    @click="handleEnableUser(user.id)"
                    class="flex items-center gap-2 px-4 py-2.5 bg-green-500/10 text-green-400 rounded-xl hover:bg-green-500/20 transition-all border border-green-500/20"
                  >
                    <Unlock class="w-4 h-4" />
                    启用账号
                  </button>
                </template>
                <button 
                  v-if="!user.is_official"
                  class="flex items-center gap-2 px-4 py-2.5 bg-amber-500/10 text-amber-400 rounded-xl hover:bg-amber-500/20 transition-all border border-amber-500/20"
                >
                  <FileText class="w-4 h-4" />
                  文件管理
                </button>
                <button 
                  v-if="!user.is_official"
                  class="flex items-center gap-2 px-4 py-2.5 bg-purple-500/10 text-purple-400 rounded-xl hover:bg-purple-500/20 transition-all border border-purple-500/20"
                >
                  <Share2 class="w-4 h-4" />
                  分享管理
                </button>
              </div>
            </div>
          </div>
        </div>

        <div v-if="filteredUsers.length === 0" class="text-center py-20">
          <div class="w-28 h-28 bg-slate-700/50 rounded-full flex items-center justify-center mx-auto">
            <Users class="w-14 h-14 text-slate-500" />
          </div>
          <h3 class="text-xl font-semibold text-white mb-2 mt-6">暂无用户</h3>
          <p class="text-slate-400">没有找到匹配的用户</p>
        </div>
      </div>
    </div>

    <div v-if="showEditModal" class="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
      <div class="bg-slate-800/90 backdrop-blur-xl rounded-2xl p-8 w-full max-w-lg border border-slate-700/50">
        <div class="flex items-center justify-between mb-6">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-blue-500/20 rounded-xl flex items-center justify-center">
              <Edit class="w-5 h-5 text-blue-400" />
            </div>
            <h3 class="text-xl font-semibold text-white">编辑用户权限</h3>
          </div>
          <button @click="showEditModal = false" class="p-2 text-slate-400 hover:text-white rounded-xl hover:bg-slate-700/40 transition-all">
            <X class="w-5 h-5" />
          </button>
        </div>
        
        <div class="space-y-5">
          <div>
            <label class="block text-sm font-medium text-slate-300 mb-3">用户名</label>
            <div class="flex items-center gap-2 px-4 py-3 bg-slate-700/30 border border-slate-600/30 rounded-xl">
              <User class="w-5 h-5 text-slate-400" />
              <span class="text-white">{{ currentUser?.username }}</span>
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium text-slate-300 mb-3">存储容量</label>
            <div class="grid grid-cols-4 gap-2">
              <button
                v-for="option in storageOptions"
                :key="option.value"
                @click="newStorageLimit = option.value"
                :class="[
                  'px-3 py-2 rounded-xl text-sm font-medium transition-all',
                  newStorageLimit === option.value
                    ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                    : 'bg-slate-700/30 text-slate-300 border border-transparent hover:bg-slate-700/50'
                ]"
              >
                {{ option.label }}
              </button>
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium text-slate-300 mb-3">上传限制</label>
            <div class="grid grid-cols-4 gap-2">
              <button
                v-for="option in uploadOptions"
                :key="option.value"
                @click="newUploadLimit = option.value"
                :class="[
                  'px-3 py-2 rounded-xl text-sm font-medium transition-all',
                  newUploadLimit === option.value
                    ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                    : 'bg-slate-700/30 text-slate-300 border border-transparent hover:bg-slate-700/50'
                ]"
              >
                {{ option.label }}
              </button>
            </div>
          </div>
        </div>

        <div class="flex gap-3 mt-8">
          <button @click="showEditModal = false" class="flex-1 px-4 py-3 bg-slate-700/30 text-slate-300 rounded-xl hover:bg-slate-700/50 transition-all">取消</button>
          <button @click="handleSaveUser" class="flex-1 px-4 py-3 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 text-white rounded-xl hover:opacity-90 transition-all">保存修改</button>
        </div>
      </div>
    </div>

    <div v-if="showBanModal" class="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
      <div class="bg-slate-800/90 backdrop-blur-xl rounded-2xl p-8 w-full max-w-lg border border-slate-700/50">
        <div class="flex items-center justify-between mb-6">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 bg-red-500/20 rounded-xl flex items-center justify-center">
              <Lock class="w-5 h-5 text-red-400" />
            </div>
            <h3 class="text-xl font-semibold text-white">封禁账号</h3>
          </div>
          <button @click="showBanModal = false" class="p-2 text-slate-400 hover:text-white rounded-xl hover:bg-slate-700/40 transition-all">
            <X class="w-5 h-5" />
          </button>
        </div>
        
        <div class="space-y-5">
          <div class="bg-red-500/10 rounded-xl p-4 border border-red-500/20">
            <div class="flex items-center gap-2">
              <AlertCircle class="w-5 h-5 text-red-400 flex-shrink-0" />
              <div>
                <p class="text-red-300 font-medium">警告</p>
                <p class="text-slate-400 text-sm">封禁后该用户将无法登录和使用服务</p>
              </div>
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium text-slate-300 mb-3">封禁原因</label>
            <textarea
              v-model="banReason"
              placeholder="请输入封禁原因..."
              rows="3"
              class="w-full px-4 py-3 bg-slate-700/30 border border-slate-600/30 rounded-xl text-white placeholder-slate-400 focus:ring-2 focus:ring-red-500/50 focus:border-red-500/50 outline-none resize-none"
            ></textarea>
          </div>
        </div>

        <div class="flex gap-3 mt-8">
          <button @click="showBanModal = false" class="flex-1 px-4 py-3 bg-slate-700/30 text-slate-300 rounded-xl hover:bg-slate-700/50 transition-all">取消</button>
          <button @click="handleBanUser" class="flex-1 px-4 py-3 bg-red-500 text-white rounded-xl hover:bg-red-600 transition-all">确认封禁</button>
        </div>
      </div>
    </div>
  </Layout>
</template>