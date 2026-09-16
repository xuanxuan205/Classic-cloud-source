<script setup lang="ts">
import { R_FILES_PING } from '@/utils/routeCodes'

import { computed, ref, watch, onMounted, onUnmounted } from "vue"
import { useRouter, useRoute } from "vue-router"
import { useAuthStore } from "@/stores/auth"
import { request } from "@/utils/axios"
import { Cloud, Home, FolderOpen, Share2, User, Shield, ShieldAlert, Settings, FileText, Users, Mail, Upload, BarChart3, ChevronDown, ChevronLeft, LogOut, Trash2, Crown, Monitor, Clock, Inbox, MessageSquare, Sparkles } from "lucide-vue-next"
import FeedbackModal from "@/components/FeedbackModal.vue"

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const sidebarCollapsed = ref(sessionStorage.getItem("sidebarCollapsed") === "true")
const adminExpanded = ref(sessionStorage.getItem("adminExpanded") === "true")
const siteName = ref("Classic Cloud")
const showFeedback = ref(false)

onMounted(async () => {
  try {
    const res = await request<any>({ url: R_FILES_PING, method: "GET" })
    if (res && res.data && res.data.site_name) { siteName.value = res.data.site_name; document.title = res.data.site_name }
  } catch (e) { /* use default */ }
})

watch(adminExpanded, (val) => sessionStorage.setItem("adminExpanded", String(val)))
watch(sidebarCollapsed, (val) => sessionStorage.setItem("sidebarCollapsed", String(val)))

watch(() => route.name, (name) => {
  if (name && String(name).startsWith("Admin")) { adminExpanded.value = true }
}, { immediate: true })
watch(() => route.path, (path) => {
  if (path && path.includes("/admin")) { adminExpanded.value = true }
})

const isAdmin = computed(() => authStore.user?.role === "admin" || authStore.user?.is_official)

const normalItems = computed(() => [
  { name: "Dashboard", label: "仪表板", icon: BarChart3 },
  { name: "Files", label: "我的文件", icon: FolderOpen },
  { name: "Shares", label: "我的分享", icon: Share2 },
  { name: "Profile", label: "个人中心", icon: User },
  { name: "RecycleBin", label: "回收站", icon: Trash2 },
])

const adminItems = [
  { name: "AdminDashboard", label: "仪表板", icon: Monitor },
  { name: "AdminUsers", label: "用户管理", icon: Users },
  { name: "AdminAnnouncements", label: "系统公告", icon: FileText },
  { name: "AdminSMTP", label: "SMTP配置", icon: Mail },
  { name: "AdminVerification", label: "用户认证", icon: Shield },
  { name: "AdminFiles", label: "文件管理", icon: FolderOpen },
  { name: "AdminShares", label: "分享管理", icon: Share2 },
  { name: "AdminUploadLimit", label: "上传限制", icon: Upload },
  { name: "AdminDownloadStats", label: "下载统计", icon: BarChart3 },
  { name: "AdminSettings", label: "系统设置", icon: Settings },
  { name: "AdminLogs", label: "系统日志", icon: Clock },
  { name: "AdminSecurity", label: "安全预警", icon: ShieldAlert },
  { name: "AdminAppeals", label: "申诉管理", icon: Inbox },
]

const currentRoute = computed(() => route.name)
async function handleLogout() {
  // IronWall v1.43.0: 先通知服务端吊销旧令牌，再跳转登录页
  await authStore.logout()
  router.push("/login")
}
function toggleSidebar() { sidebarCollapsed.value = !sidebarCollapsed.value }
function toggleAdmin() { adminExpanded.value = !adminExpanded.value }
</script>

<template>
  <div class="min-h-screen bg-slate-950 flex">
    <aside :class="['fixed left-0 top-0 h-full z-50 flex flex-col bg-slate-900 border-r border-slate-800 transition-all duration-300', sidebarCollapsed ? 'w-16' : 'w-56']">
      <div class="h-14 flex items-center px-4 border-b border-slate-800 shrink-0">
        <div class="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center shrink-0">
          <Cloud class="w-5 h-5 text-white" />
        </div>
        <span v-if="!sidebarCollapsed" class="ml-3 text-white font-bold text-sm truncate">{{ siteName }}</span>
      </div>
      <nav class="flex-1 overflow-y-auto py-2 px-2">
        <div class="space-y-0.5">
          <router-link v-for="item in normalItems" :key="item.name" :to="{ name: item.name }"
            :class="['flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors', currentRoute === item.name ? 'bg-indigo-600/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800 hover:text-white']">
            <component :is="item.icon" class="w-4 h-4 shrink-0" />
            <span v-if="!sidebarCollapsed" class="truncate">{{ item.label }}</span>
          </router-link>
        </div>
        <div class="mt-4 pt-4 border-t border-slate-800 space-y-0.5">
          <button @click="showFeedback = true"
            :class="['flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors text-slate-400 hover:bg-slate-800 hover:text-white w-full', sidebarCollapsed ? 'justify-center' : '']"
            :title="'意见反馈'">
            <MessageSquare class="w-4 h-4 shrink-0" />
            <span v-if="!sidebarCollapsed" class="truncate">意见反馈</span>
          </button>
        </div>
        <div v-if="isAdmin && !sidebarCollapsed" class="mt-4 pt-4 border-t border-slate-800">
          <button @click="toggleAdmin" class="w-full flex items-center gap-2 px-3 py-2 text-slate-400 hover:text-white text-sm font-medium">
            <Shield class="w-4 h-4" />
            <span class="flex-1 text-left">管理后台</span>
            <ChevronDown :class="['w-4 h-4 transition-transform', adminExpanded ? 'rotate-180' : '']" />
          </button>
          <div v-if="adminExpanded" class="mt-1 space-y-0.5">
            <router-link v-for="item in adminItems" :key="item.name" :to="{ name: item.name }"
              :class="['flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors', currentRoute === item.name ? 'bg-indigo-600/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800 hover:text-white']">
              <component :is="item.icon" class="w-4 h-4 shrink-0" />
              <span class="truncate">{{ item.label }}</span>
            </router-link>
          </div>
        </div>
        <div v-if="isAdmin && sidebarCollapsed" class="mt-4 pt-4 border-t border-slate-800 space-y-0.5">
          <router-link v-for="item in adminItems" :key="item.name" :to="{ name: item.name }" :title="item.label"
            :class="['flex justify-center py-2 rounded-lg text-sm transition-colors', currentRoute === item.name ? 'bg-indigo-600/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800 hover:text-white']">
            <component :is="item.icon" class="w-4 h-4" />
          </router-link>
        </div>
      </nav>
      <div class="p-2 border-t border-slate-800 shrink-0">
        <button @click="toggleSidebar" class="w-full flex justify-center py-2 rounded-lg text-slate-400 hover:bg-slate-800 hover:text-white transition-colors">
          <ChevronLeft :class="['w-4 h-4 transition-transform', sidebarCollapsed ? 'rotate-180' : '']" />
        </button>
        <div class="flex items-center gap-2 px-2 py-2">
          <div class="relative shrink-0">
            <div class="w-9 h-9 rounded-full flex items-center justify-center"
              :class="isAdmin ? 'bg-gradient-to-br from-red-500 to-rose-600' : 'bg-gradient-to-br from-emerald-500 to-teal-600'">
              <Crown v-if="isAdmin" class="w-4 h-4 text-white" />
              <User v-else class="w-4 h-4 text-white" />
            </div>
            <span class="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-slate-900"
              :class="isAdmin ? 'bg-red-500' : 'bg-emerald-500'"></span>
          </div>
          <div v-if="!sidebarCollapsed" class="flex-1 min-w-0">
            <div class="flex items-center gap-1.5">
              <p class="text-xs text-white truncate font-medium">{{ authStore.user?.username }}</p>
              <span v-if="isAdmin"
                class="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md bg-red-500/15 border border-red-500/40 text-red-400 text-[10px] font-semibold leading-none shrink-0">
                <Crown class="w-2.5 h-2.5" />官方管理员
              </span>
              <span v-else
                class="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md bg-emerald-500/15 border border-emerald-500/40 text-emerald-400 text-[10px] font-semibold leading-none shrink-0">
                <Sparkles class="w-2.5 h-2.5" />尊享用户
              </span>
            </div>
            <p class="text-[10px] mt-1 truncate" :class="isAdmin ? 'text-red-400/70' : 'text-emerald-400/70'">
              {{ isAdmin ? '官方管理 · 全域权限' : '尊享服务 · 云端畅享' }}
            </p>
          </div>
          <button v-if="!sidebarCollapsed" @click="handleLogout" class="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-colors shrink-0" title="退出登录">
            <LogOut class="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
    <div :class="['flex-1 transition-all duration-300', sidebarCollapsed ? 'ml-16' : 'ml-56']">
      <slot />
    </div>
    <FeedbackModal v-model="showFeedback" />
  </div>
</template>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition: all 0.25s ease;
}
.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateY(12px);
}
</style>
