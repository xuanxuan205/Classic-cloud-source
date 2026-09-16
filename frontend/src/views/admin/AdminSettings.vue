<script setup lang="ts">
import { R_ADMIN_SETTINGS } from '@/utils/routeCodes'

import { ref, onMounted, computed } from "vue"
import Layout from "@/components/Layout.vue"
import { request } from "@/utils/axios"
import { showToast } from "@/composables/useGlobalFeedback"
import { Save, Globe, Users, Share2, AlertTriangle, Monitor, Loader2, Check, Settings, Mail, Eye, EyeOff, RotateCcw, XCircle, Info, Sparkles } from "lucide-vue-next"

const loading = ref(false)
const saving = ref(false)
const saveSuccess = ref(false)

const settings = ref<Record<string, string>>({
  site_name: "",
  site_description: "",
  allow_registration: "true",
  allow_all_file_types: "false",
  share_settings: "{}",
  disabled_notice: "",
  system_info: "{}",
  smtp_host: "",
  smtp_port: "",
  smtp_username: "",
  smtp_password: "",
  smtp_from_name: ""
})

const original = ref("{}")
const dirty = computed(() => JSON.stringify(settings.value) !== original.value)



type TabKey = 'site' | 'users' | 'share' | 'maintain' | 'system' | 'smtp'
const activeTab = ref<TabKey>('site')
const tabs: { key: TabKey, label: string, icon: any }[] = [
  { key: 'site', label: '站点设置', icon: Globe },
  { key: 'users', label: '用户与注册', icon: Users },
  { key: 'share', label: '分享设置', icon: Share2 },
  { key: 'maintain', label: '站点维护', icon: AlertTriangle },
  { key: 'system', label: '系统信息', icon: Monitor },
  { key: 'smtp', label: '邮件服务', icon: Mail }
]

// ============ JSON Validation ============
const shareJsonError = ref("")
const systemJsonError = ref("")
const smtpPortError = ref("")

function validateShareJson(): boolean {
  shareJsonError.value = ""
  try {
    const o = JSON.parse(settings.value.share_settings || "{}")
    if (typeof o !== "object" || o === null || Array.isArray(o)) throw new Error("invalid")
    return true
  } catch {
    shareJsonError.value = "JSON 格式错误，请检查逗号、引号与括号是否匹配"
    return false
  }
}

function validateSystemJson(): boolean {
  systemJsonError.value = ""
  try {
    const o = JSON.parse(settings.value.system_info || "{}")
    if (typeof o !== "object" || o === null || Array.isArray(o)) throw new Error("invalid")
    return true
  } catch {
    systemJsonError.value = "JSON 格式错误，请检查逗号、引号与括号是否匹配"
    return false
  }
}

function validateSmtpPort(): boolean {
  smtpPortError.value = ""
  const p = settings.value.smtp_port.trim()
  if (!p) return true
  const n = Number(p)
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    smtpPortError.value = "端口必须是 1 ~ 65535 之间的数字"
    return false
  }
  return true
}

// ============ Load / Save ============
async function loadSettings() {
  loading.value = true
  try {
    const res = await request<Record<string, string>>({ url: R_ADMIN_SETTINGS, method: "GET" })
    if (res.success && res.data) {
      Object.assign(settings.value, res.data)
    }
  } catch (e: any) {
    console.error('AdminSettings load error:', e)
    showToast("设置加载失败", "error")
  }
  original.value = JSON.stringify(settings.value)
  loading.value = false
}

async function saveSettings() {
  if (!validateShareJson()) { activeTab.value = 'share'; showToast("分享设置为非法 JSON", "error"); return }
  if (!validateSystemJson()) { activeTab.value = 'system'; showToast("系统信息为非法 JSON", "error"); return }
  if (!validateSmtpPort()) { activeTab.value = 'smtp'; showToast("SMTP 端口不合法", "error"); return }
  saving.value = true
  saveSuccess.value = false
  try {
    const res = await request({ url: R_ADMIN_SETTINGS, method: "PUT", data: settings.value })
    if (res.success) {
      saveSuccess.value = true
      original.value = JSON.stringify(settings.value)
      showToast("设置已保存", "success")
      setTimeout(() => { saveSuccess.value = false }, 2000)
    } else {
      showToast(res.message || "保存失败", "error")
    }
  } catch (e: any) {
    showToast("保存失败: " + (e?.message || "未知错误"), "error")
  }
  saving.value = false
}

function resetSettings() {
  Object.assign(settings.value, JSON.parse(original.value))
  shareJsonError.value = ""
  systemJsonError.value = ""
  smtpPortError.value = ""
  showToast("已撤销未保存的修改", "success")
}

function applySharePreset(preset: 'recommended' | 'strict') {
  const value = preset === 'recommended'
    ? '{"max_downloads":100,"default_expire_days":7,"require_password":false}'
    : '{"max_downloads":20,"default_expire_days":3,"require_password":true}'
  settings.value.share_settings = value
  shareJsonError.value = ""
}

const showNoticePreview = ref(false)
const showSmtpPwd = ref(false)
const smtpConfigured = computed(() => !!(settings.value.smtp_host || settings.value.smtp_username))

onMounted(loadSettings)
</script>

<template>
<Layout>

<div class="p-3 sm:p-4 md:p-6 xl:p-8 w-full">

  <!-- ====== HEADER ====== -->
  <div class="flex flex-wrap items-center justify-between gap-3 mb-4 sm:mb-6">
    <div class="flex items-center gap-3 min-w-0">
      <div class="w-10 h-10 sm:w-12 sm:h-12 rounded-xl bg-indigo-500/10 flex items-center justify-center shrink-0 ring-1 ring-indigo-500/20">
        <Settings class="w-5 h-5 sm:w-6 sm:h-6 text-indigo-400" />
      </div>
      <div class="min-w-0">
        <h1 class="text-xl sm:text-2xl font-bold text-white">系统设置</h1>
        <p class="text-slate-500 text-xs sm:text-sm mt-0.5">管理站点信息、注册策略、分享限制、维护公告与邮件服务</p>
      </div>
    </div>
    <div class="flex items-center gap-2">
      <button @click="resetSettings" :disabled="!dirty" class="px-3.5 py-2 bg-slate-700/50 hover:bg-slate-600 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 rounded-lg text-xs sm:text-sm font-medium transition-colors flex items-center gap-1.5">
        <RotateCcw class="w-3.5 h-3.5 sm:w-4 sm:h-4" />重置
      </button>
      <button @click="saveSettings" :disabled="saving" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-60 text-white rounded-lg text-xs sm:text-sm font-medium transition-colors flex items-center gap-1.5 shadow-lg shadow-indigo-600/20">
        <Loader2 v-if="saving" class="w-3.5 h-3.5 sm:w-4 sm:h-4 animate-spin" />
        <Check v-else-if="saveSuccess" class="w-3.5 h-3.5 sm:w-4 sm:h-4" />
        <Save v-else class="w-3.5 h-3.5 sm:w-4 sm:h-4" />
        {{ saving ? '保存中...' : saveSuccess ? '已保存' : '保存设置' }}
      </button>
    </div>
  </div>

  <!-- ====== LOADING ====== -->
  <div v-if="loading" class="text-center py-16 text-slate-400">
    <Loader2 class="w-7 h-7 animate-spin mx-auto mb-3" />
    <p class="text-sm">加载中...</p>
  </div>

  <!-- ====== BODY ====== -->
  <div v-else class="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-4 sm:gap-6 items-start">

    <!-- SIDE NAV -->
    <nav class="lg:sticky lg:top-20 flex lg:flex-col gap-1.5 overflow-x-auto lg:overflow-visible pb-1 lg:pb-0 -mx-1 px-1">
      <button v-for="tab in tabs" :key="tab.key" @click="activeTab=tab.key"
        :class="['flex items-center gap-2.5 px-3.5 py-2.5 rounded-xl text-xs sm:text-sm font-medium transition-all whitespace-nowrap shrink-0',
          activeTab===tab.key ? 'bg-indigo-500/15 text-indigo-300 ring-1 ring-indigo-500/30' : 'text-slate-400 hover:text-white hover:bg-slate-800/60']">
        <component :is="tab.icon" class="w-4 h-4 shrink-0" />
        {{ tab.label }}
        <span v-if="tab.key==='smtp' && smtpConfigured" class="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" title="已配置"></span>
      </button>
    </nav>

    <!-- CONTENT -->
    <div class="space-y-4 sm:space-y-5 min-w-0">

      <!-- ====== 站点设置 ====== -->
      <section v-show="activeTab==='site'" class="bg-slate-800/40 rounded-2xl xl:rounded-3xl border border-slate-700/30 overflow-hidden">
        <div class="px-4 sm:px-6 py-3 sm:py-4 border-b border-slate-700/30 flex items-center gap-2">
          <Globe class="w-4 h-4 sm:w-5 sm:h-5 text-blue-400" />
          <h2 class="text-white font-semibold text-sm sm:text-base">站点设置</h2>
        </div>
        <div class="p-4 sm:p-6 space-y-4 sm:space-y-5">
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label class="text-slate-400 text-xs sm:text-sm">站点标题</label>
              <span class="text-slate-600 text-xs">{{ (settings.site_name||'').length }}/30</span>
            </div>
            <input v-model="settings.site_name" maxlength="30" placeholder="例如：我的网盘" class="w-full bg-slate-900/60 border border-slate-700 rounded-lg px-3.5 py-2.5 text-white text-sm focus:border-blue-500 outline-none transition-colors placeholder-slate-600" />
            <p class="text-slate-600 text-xs mt-1.5">显示在侧边栏顶部与浏览器标签页中，建议不超过 20 个字符</p>
          </div>
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label class="text-slate-400 text-xs sm:text-sm">站点描述</label>
              <span class="text-slate-600 text-xs">{{ (settings.site_description||'').length }}/200</span>
            </div>
            <textarea v-model="settings.site_description" rows="3" maxlength="200" placeholder="例如：我的网盘 - 安全可靠的个人云存储平台" class="w-full bg-slate-900/60 border border-slate-700 rounded-lg px-3.5 py-2.5 text-white text-sm focus:border-blue-500 outline-none transition-colors resize-none placeholder-slate-600"></textarea>
            <p class="text-slate-600 text-xs mt-1.5">用于 SEO 与页面底部介绍</p>
          </div>
        </div>
      </section>

      <!-- ====== 用户与注册 ====== -->
      <section v-show="activeTab==='users'" class="bg-slate-800/40 rounded-2xl xl:rounded-3xl border border-slate-700/30 overflow-hidden">
        <div class="px-4 sm:px-6 py-3 sm:py-4 border-b border-slate-700/30 flex items-center gap-2">
          <Users class="w-4 h-4 sm:w-5 sm:h-5 text-green-400" />
          <h2 class="text-white font-semibold text-sm sm:text-base">用户与注册</h2>
        </div>
        <div class="p-4 sm:p-6 space-y-1">
          <div class="flex items-center justify-between gap-4 py-3.5 border-b border-slate-700/20 last:border-0">
            <div class="min-w-0">
              <p class="text-white text-sm">允许用户注册</p>
              <p class="text-slate-500 text-xs mt-1">关闭后新用户无法创建账号，已有账号不受影响</p>
            </div>
            <div class="flex items-center gap-2.5 shrink-0">
              <span :class="['text-xs font-medium', settings.allow_registration==='true'?'text-green-400':'text-slate-500']">{{ settings.allow_registration==='true'?'已开启':'已关闭' }}</span>
              <button @click="settings.allow_registration = settings.allow_registration==='true' ? 'false' : 'true'" :class="['w-11 h-6 rounded-full transition-colors shrink-0 relative', settings.allow_registration==='true' ? 'bg-green-500' : 'bg-slate-600']">
                <span :class="['absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform', settings.allow_registration==='true' ? 'translate-x-[22px]' : 'translate-x-0.5']"></span>
              </button>
            </div>
          </div>
          <div class="flex items-center justify-between gap-4 py-3.5 border-b border-slate-700/20 last:border-0">
            <div class="min-w-0">
              <p class="text-white text-sm">允许所有文件类型</p>
              <p class="text-slate-500 text-xs mt-1">开启后支持任意扩展名上传，关闭则只允许常见安全类型</p>
            </div>
            <div class="flex items-center gap-2.5 shrink-0">
              <span :class="['text-xs font-medium', settings.allow_all_file_types==='true'?'text-amber-400':'text-slate-500']">{{ settings.allow_all_file_types==='true'?'已开启':'已关闭' }}</span>
              <button @click="settings.allow_all_file_types = settings.allow_all_file_types==='true' ? 'false' : 'true'" :class="['w-11 h-6 rounded-full transition-colors shrink-0 relative', settings.allow_all_file_types==='true' ? 'bg-amber-500' : 'bg-slate-600']">
                <span :class="['absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform', settings.allow_all_file_types==='true' ? 'translate-x-[22px]' : 'translate-x-0.5']"></span>
              </button>
            </div>
          </div>
          <div class="flex items-start gap-2.5 pt-3.5 text-slate-500 text-xs leading-relaxed">
            <Info class="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
            <p>安全建议：保持「允许所有文件类型」关闭，可显著降低可执行文件、脚本类恶意上传的风险。</p>
          </div>
        </div>
      </section>

      <!-- ====== 分享设置 ====== -->
      <section v-show="activeTab==='share'" class="bg-slate-800/40 rounded-2xl xl:rounded-3xl border border-slate-700/30 overflow-hidden">
        <div class="px-4 sm:px-6 py-3 sm:py-4 border-b border-slate-700/30 flex items-center gap-2">
          <Share2 class="w-4 h-4 sm:w-5 sm:h-5 text-purple-400" />
          <h2 class="text-white font-semibold text-sm sm:text-base">分享管理设置</h2>
        </div>
        <div class="p-4 sm:p-6 space-y-3">
          <div class="flex flex-wrap items-center gap-2">
            <button @click="applySharePreset('recommended')" class="px-3 py-1.5 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 rounded-lg text-xs transition-colors flex items-center gap-1.5"><Sparkles class="w-3.5 h-3.5" />推荐默认</button>
            <button @click="applySharePreset('strict')" class="px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 rounded-lg text-xs transition-colors flex items-center gap-1.5"><AlertTriangle class="w-3.5 h-3.5" />强化安全</button>
          </div>
          <textarea v-model="settings.share_settings" rows="7" spellcheck="false"
            :class="['w-full bg-slate-900/60 border rounded-lg px-3.5 py-2.5 text-white text-sm font-mono focus:outline-none transition-colors resize-none placeholder-slate-600', shareJsonError ? 'border-red-500/60' : 'border-slate-700 focus:border-purple-500']"
            placeholder='{"max_downloads": 100, "default_expire_days": 7, "require_password": false}'></textarea>
          <p v-if="shareJsonError" class="text-red-400 text-xs flex items-center gap-1.5"><XCircle class="w-3.5 h-3.5 shrink-0" />{{ shareJsonError }}</p>
          <p v-else class="text-slate-600 text-xs leading-relaxed">JSON 格式配置分享限制。支持字段：<code class="text-slate-400">max_downloads</code> 最大下载次数、<code class="text-slate-400">default_expire_days</code> 默认过期天数、<code class="text-slate-400">require_password</code> 是否强制密码。</p>
        </div>
      </section>

      <!-- ====== 站点维护 ====== -->
      <section v-show="activeTab==='maintain'" class="bg-slate-800/40 rounded-2xl xl:rounded-3xl border border-slate-700/30 overflow-hidden">
        <div class="px-4 sm:px-6 py-3 sm:py-4 border-b border-slate-700/30 flex items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <AlertTriangle class="w-4 h-4 sm:w-5 sm:h-5 text-amber-400" />
            <h2 class="text-white font-semibold text-sm sm:text-base">站点维护公告</h2>
          </div>
          <button @click="showNoticePreview=!showNoticePreview" class="px-3 py-1.5 bg-slate-700/50 hover:bg-slate-600 text-slate-300 rounded-lg text-xs transition-colors flex items-center gap-1.5">
            <Eye v-if="!showNoticePreview" class="w-3.5 h-3.5" /><EyeOff v-else class="w-3.5 h-3.5" />{{ showNoticePreview?'返回编辑':'预览效果' }}
          </button>
        </div>
        <div class="p-4 sm:p-6 space-y-3">
          <textarea v-if="!showNoticePreview" v-model="settings.disabled_notice" rows="6"
            class="w-full bg-slate-900/60 border border-slate-700 rounded-lg px-3.5 py-2.5 text-white text-sm focus:border-amber-500 outline-none transition-colors resize-none placeholder-slate-600"
            placeholder="<div><h3>系统维护中</h3><p>预计维护时间：1小时，请稍后再试...</p></div>"></textarea>
          <div v-else class="min-h-[120px] bg-slate-900/60 border border-slate-700 rounded-lg p-4 overflow-auto">
            <div v-if="settings.disabled_notice" class="text-white text-sm" v-html="settings.disabled_notice"></div>
            <p v-else class="text-slate-600 text-sm">留空时首页不显示公告</p>
          </div>
          <p class="text-slate-600 text-xs leading-relaxed">当系统维护或出现问题时，此处内容将显示在网站首页告知用户。支持 HTML 标签，留空则不显示。</p>
        </div>
      </section>

      <!-- ====== 系统信息 ====== -->
      <section v-show="activeTab==='system'" class="bg-slate-800/40 rounded-2xl xl:rounded-3xl border border-slate-700/30 overflow-hidden">
        <div class="px-4 sm:px-6 py-3 sm:py-4 border-b border-slate-700/30 flex items-center gap-2">
          <Monitor class="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" />
          <h2 class="text-white font-semibold text-sm sm:text-base">系统信息</h2>
        </div>
        <div class="p-4 sm:p-6 space-y-3">
          <textarea v-model="settings.system_info" rows="5" spellcheck="false"
            :class="['w-full bg-slate-900/60 border rounded-lg px-3.5 py-2.5 text-white text-sm font-mono focus:outline-none transition-colors resize-none placeholder-slate-600', systemJsonError ? 'border-red-500/60' : 'border-slate-700 focus:border-cyan-500']"
            placeholder='{"version": "3.0", "contact": "admin@example.com", "announcement": "欢迎使用我的网盘！"}'></textarea>
          <p v-if="systemJsonError" class="text-red-400 text-xs flex items-center gap-1.5"><XCircle class="w-3.5 h-3.5 shrink-0" />{{ systemJsonError }}</p>
          <p v-else class="text-slate-600 text-xs leading-relaxed">「系统信息」公开页面展示的内容，JSON 格式。推荐字段：<code class="text-slate-400">version</code> 版本号、<code class="text-slate-400">contact</code> 联系方式、<code class="text-slate-400">announcement</code> 公告。</p>
        </div>
      </section>

      <!-- ====== 邮件服务 ====== -->
      <section v-show="activeTab==='smtp'" class="bg-slate-800/40 rounded-2xl xl:rounded-3xl border border-slate-700/30 overflow-hidden">
        <div class="px-4 sm:px-6 py-3 sm:py-4 border-b border-slate-700/30 flex items-center gap-2">
          <Mail class="w-4 h-4 sm:w-5 sm:h-5 text-pink-400" />
          <h2 class="text-white font-semibold text-sm sm:text-base">邮件服务（SMTP）</h2>
        </div>
        <div class="p-4 sm:p-6 space-y-4">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
            <div>
              <label class="text-slate-400 text-xs sm:text-sm block mb-1.5">SMTP 服务器</label>
              <input v-model="settings.smtp_host" placeholder="例如：smtp.qq.com" class="w-full bg-slate-900/60 border border-slate-700 rounded-lg px-3.5 py-2.5 text-white text-sm focus:border-pink-500 outline-none transition-colors placeholder-slate-600" />
            </div>
            <div>
              <label class="text-slate-400 text-xs sm:text-sm block mb-1.5">端口</label>
              <input v-model="settings.smtp_port" inputmode="numeric" placeholder="例如：465" :class="['w-full bg-slate-900/60 border rounded-lg px-3.5 py-2.5 text-white text-sm focus:outline-none transition-colors placeholder-slate-600', smtpPortError ? 'border-red-500/60' : 'border-slate-700 focus:border-pink-500']" />
              <p v-if="smtpPortError" class="text-red-400 text-xs mt-1.5">{{ smtpPortError }}</p>
            </div>
            <div>
              <label class="text-slate-400 text-xs sm:text-sm block mb-1.5">授权账号（邮箱）</label>
              <input v-model="settings.smtp_username" type="email" placeholder="例如：noreply@example.com" class="w-full bg-slate-900/60 border border-slate-700 rounded-lg px-3.5 py-2.5 text-white text-sm focus:border-pink-500 outline-none transition-colors placeholder-slate-600" />
            </div>
            <div>
              <label class="text-slate-400 text-xs sm:text-sm block mb-1.5">发件人显示名</label>
              <input v-model="settings.smtp_from_name" placeholder="例如：我的网盘官方" class="w-full bg-slate-900/60 border border-slate-700 rounded-lg px-3.5 py-2.5 text-white text-sm focus:border-pink-500 outline-none transition-colors placeholder-slate-600" />
            </div>
            <div class="sm:col-span-2">
              <label class="text-slate-400 text-xs sm:text-sm block mb-1.5">授权密码 / 授权码</label>
              <div class="relative">
                <input v-model="settings.smtp_password" :type="showSmtpPwd?'text':'password'" placeholder="请输入 SMTP 授权码（非邮箱登录密码）" class="w-full bg-slate-900/60 border border-slate-700 rounded-lg px-3.5 py-2.5 pr-11 text-white text-sm focus:border-pink-500 outline-none transition-colors placeholder-slate-600" />
                <button @click="showSmtpPwd=!showSmtpPwd" class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors">
                  <EyeOff v-if="showSmtpPwd" class="w-4 h-4" /><Eye v-else class="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
          <div class="flex items-start gap-2.5 bg-indigo-500/5 border border-indigo-500/10 rounded-xl p-3.5 text-slate-500 text-xs leading-relaxed">
            <Info class="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
            <p>发件邮箱地址需与 SMTP 授权账号保持一致（QQ 邮箱 501 校验）；端口 465 走 SSL、587 走 STARTTLS。修改后新发出的邮件将使用新配置。</p>
          </div>
        </div>
      </section>
    </div>
  </div>

  <!-- ====== STICKY ACTION BAR ====== -->
  <div class="sticky bottom-4 mt-6 flex flex-wrap items-center justify-between gap-3 bg-slate-800/90 backdrop-blur border border-slate-700/40 rounded-2xl px-4 py-3 shadow-2xl">
    <div class="flex items-center gap-2 min-w-0">
      <span :class="['w-2 h-2 rounded-full shrink-0', dirty?'bg-amber-400':'bg-emerald-400']"></span>
      <p class="text-slate-400 text-xs sm:text-sm truncate">{{ dirty ? '有未保存的修改' : '所有更改均已保存' }}</p>
    </div>
    <div class="flex items-center gap-2">
      <button @click="resetSettings" :disabled="!dirty" class="px-3.5 py-2 bg-slate-700/60 hover:bg-slate-600 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 rounded-lg text-xs sm:text-sm transition-colors flex items-center gap-1.5">
        <RotateCcw class="w-3.5 h-3.5" />重置
      </button>
      <button @click="saveSettings" :disabled="saving" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-60 text-white rounded-lg text-xs sm:text-sm font-medium transition-colors flex items-center gap-1.5">
        <Loader2 v-if="saving" class="w-3.5 h-3.5 animate-spin" />
        <Check v-else-if="saveSuccess" class="w-3.5 h-3.5" />
        <Save v-else class="w-3.5 h-3.5" />
        {{ saving ? '保存中...' : saveSuccess ? '已保存' : '保存设置' }}
      </button>
    </div>
  </div>
</div>
</Layout>
</template>
