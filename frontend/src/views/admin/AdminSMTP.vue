<script setup lang="ts">
import { R_ADMIN_SETTINGS, R_AUTH_SEND_CODE } from '@/utils/routeCodes'

import { ref, onMounted } from 'vue'
import Layout from '@/components/Layout.vue'
import { request } from '@/utils/axios'
import { showToast } from '@/composables/useGlobalFeedback'
import { Mail, Save, Send, Loader2, Check } from 'lucide-vue-next'

const smtpConfig = ref({
  host: 'smtp.qq.com',
  port: 587,
  username: '',
  password: '',
  from_name: 'Classic Cloud'
})
const testEmail = ref('')
const saving = ref(false)
const testing = ref(false)
const saveSuccess = ref(false)
const testSuccess = ref(false)
const loading = ref(true)

// Load existing SMTP settings from system config
async function loadConfig() {
  loading.value = true
  try {
    const res = await request<Record<string, string>>({ url: R_ADMIN_SETTINGS, method: 'GET' })
    if (res.success && res.data) {
      if (res.data.smtp_host) smtpConfig.value.host = res.data.smtp_host
      if (res.data.smtp_port) smtpConfig.value.port = parseInt(res.data.smtp_port) || 587
      if (res.data.smtp_username) smtpConfig.value.username = res.data.smtp_username
      if (res.data.smtp_password) smtpConfig.value.password = res.data.smtp_password
      if (res.data.smtp_from_name) smtpConfig.value.from_name = res.data.smtp_from_name
    }
  } catch (e: any) { console.error('loadConfig error:', e) }
  loading.value = false
}

async function saveConfig() {
  saving.value = true
  saveSuccess.value = false
  try {
    const res = await request({ url: R_ADMIN_SETTINGS, method: 'PUT', data: {
      smtp_host: smtpConfig.value.host,
      smtp_port: String(smtpConfig.value.port),
      smtp_username: smtpConfig.value.username,
      smtp_password: smtpConfig.value.password,
      smtp_from_name: smtpConfig.value.from_name
    }})
    if (res.success) {
      saveSuccess.value = true
      setTimeout(() => saveSuccess.value = false, 3000)
    } else {
      showToast(res.message || '保存失败', 'error')
    }
  } catch (e: any) {
    showToast('保存失败: ' + (e?.message || '网络错误'), 'error')
  }
  saving.value = false
}

async function testEmailSend() {
  if (!testEmail.value) { showToast('请输入测试邮箱', 'error'); return }
  testing.value = true
  testSuccess.value = false
  try {
    // First save SMTP config, then test
    await saveConfig()
    const res = await request({ url: R_AUTH_SEND_CODE, method: 'POST', data: { email: testEmail.value } })
    if (res.success) {
      testSuccess.value = true
      setTimeout(() => testSuccess.value = false, 3000)
    } else {
      showToast('发送失败: ' + (res.message || '请检查SMTP配置'), 'error')
    }
  } catch (e: any) {
    showToast('发送失败，请检查SMTP配置: ' + (e?.message || ''), 'error')
  }
  testing.value = false
}

onMounted(loadConfig)
</script>

<template>
  <Layout>
    <div class="p-6 space-y-6">
      <div>
        <h1 class="text-2xl font-bold text-white">SMTP配置</h1>
        <p class="text-slate-400 mt-2 text-sm">配置邮件发送服务，用于验证码和通知邮件。修改后需重启后端服务生效。</p>
      </div>

      <div v-if="loading" class="text-center py-12 text-slate-400"><Loader2 class="w-6 h-6 animate-spin mx-auto mb-2" />加载中...</div>

      <div v-else class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="bg-slate-800/50 rounded-xl border border-slate-700/30 p-5">
          <h3 class="text-white font-medium flex items-center gap-2 mb-4"><Mail class="w-4 h-4 text-blue-400" />SMTP 服务器设置</h3>
          <div class="space-y-3">
            <div><label class="text-slate-400 text-sm block mb-1">SMTP 主机</label><input v-model="smtpConfig.host" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-indigo-500" /></div>
            <div><label class="text-slate-400 text-sm block mb-1">端口</label><input v-model.number="smtpConfig.port" type="number" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-indigo-500" /></div>
            <div><label class="text-slate-400 text-sm block mb-1">发件邮箱</label><input v-model="smtpConfig.username" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-indigo-500" placeholder="your@email.com" /></div>
            <div><label class="text-slate-400 text-sm block mb-1">SMTP 密码/授权码</label><input v-model="smtpConfig.password" type="password" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-indigo-500" /></div>
            <div><label class="text-slate-400 text-sm block mb-1">发件人名称</label><input v-model="smtpConfig.from_name" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-indigo-500" /></div>
          </div>
          <button @click="saveConfig" :disabled="saving" class="w-full mt-4 py-3 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-lg font-medium transition-all flex items-center justify-center gap-2">
            <Loader2 v-if="saving" class="w-4 h-4 animate-spin" />
            <Check v-else-if="saveSuccess" class="w-4 h-4" />
            <Save v-else class="w-4 h-4" />
            {{ saving ? '保存中...' : saveSuccess ? '已保存' : '保存配置' }}
          </button>
        </div>

        <div class="bg-slate-800/50 rounded-xl border border-slate-700/30 p-5">
          <h3 class="text-white font-medium flex items-center gap-2 mb-4"><Send class="w-4 h-4 text-green-400" />发送测试邮件</h3>
          <p class="text-slate-400 text-sm mb-4">保存配置后，发送测试邮件验证SMTP设置是否正确</p>
          <div class="space-y-3">
            <div><label class="text-slate-400 text-sm block mb-1">测试收件邮箱</label><input v-model="testEmail" type="email" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-indigo-500" placeholder="test@email.com" /></div>
          </div>
          <button @click="testEmailSend" :disabled="testing" class="w-full mt-4 py-3 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded-lg font-medium transition-all flex items-center justify-center gap-2">
            <Loader2 v-if="testing" class="w-4 h-4 animate-spin" />
            <Check v-else-if="testSuccess" class="w-4 h-4" />
            <Send v-else class="w-4 h-4" />
            {{ testing ? '发送中...' : testSuccess ? '发送成功' : '发送测试邮件' }}
          </button>
        </div>
      </div>
    </div>
  </Layout>
</template>
