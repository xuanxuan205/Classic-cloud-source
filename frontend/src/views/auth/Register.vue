<script setup lang="ts">
import { SITE_NAME } from '@/config/site'
import { R_AUTH_CHECK_EMAIL } from '@/utils/routeCodes'

import { ref, watch, onMounted, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { request } from '@/utils/axios'
import {  Eye, EyeOff, Mail, Lock, User, ArrowRight, Shield, CloudUpload, Users, CheckCircle, Loader2, Send, ChevronLeft } from 'lucide-vue-next'

const router = useRouter()
const authStore = useAuthStore()

const username = ref('')
const email = ref('')
const password = ref('')
const confirmPassword = ref('')
const emailCode = ref('')
const showPassword = ref(false)
const showConfirmPassword = ref(false)
const isLoading = ref(false)
const isSendingCode = ref(false)
const countdown = ref(0)
const errorMessage = ref('')
const successMessage = ref('')
const checkingEmail = ref(false)
const emailFormatOk = ref(false)
const emailRegistered = ref(false)
const isVisible = ref(false)

const usernameInput = ref<HTMLInputElement | null>(null)

const meteors = ref<Array<{ id: number; left: number; delay: number; duration: number; size: number }>>([])
const stars = ref<Array<{ id: number; left: number; top: number; size: number; delay: number; duration: number }>>([])
const bubbles = ref<Array<{ id: number; left: number; delay: number; duration: number; size: number }>>([])

// Clear error on input
watch([username, email, password, confirmPassword, emailCode], () => {
  if (errorMessage.value) errorMessage.value = ''
})

// Email check with debounce
let emailCheckTimer: ReturnType<typeof setTimeout> | null = null
watch(email, (val) => {
  emailFormatOk.value = false
  emailRegistered.value = false
  checkingEmail.value = false
  if (emailCheckTimer) clearTimeout(emailCheckTimer)
  if (!val || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) return
  checkingEmail.value = true
  emailCheckTimer = setTimeout(async () => {
    // IronWall v1.27.5: 注册页邮箱自动识别，实时提示是否已注册
    try {
      const res = await request<any>({ url: R_AUTH_CHECK_EMAIL, method: 'GET', params: { email: val } })
      if (res && res.success && res.data) {
        // IronWall v1.39.0: 后端匿名态不再返回注册状态（registered=null），
        // 前端三态：true=已注册 / false=可注册 / null=未知（仅提示格式正确）
        emailRegistered.value = res.data.registered === true
        emailFormatOk.value = res.data.format_ok === true && res.data.registered !== true
      } else {
        emailFormatOk.value = true
      }
    } catch {
      emailFormatOk.value = true
    }
    checkingEmail.value = false
  }, 500)
})

function createMeteors() {
  const newMeteors = []
  for (let i = 0; i < 8; i++) {
    newMeteors.push({
      id: i, left: Math.random() * 100, delay: Math.random() * 8,
      duration: Math.random() * 3 + 2, size: Math.random() * 2 + 1
    })
  }
  meteors.value = newMeteors
}

function createStars() {
  const newStars = []
  for (let i = 0; i < 50; i++) {
    newStars.push({
      id: i, left: Math.random() * 100, top: Math.random() * 100,
      size: Math.random() * 3 + 1, delay: Math.random() * 3, duration: Math.random() * 2 + 1
    })
  }
  stars.value = newStars
}

function createBubbles() {
  const newBubbles = []
  for (let i = 0; i < 20; i++) {
    newBubbles.push({
      id: i, left: Math.random() * 100, delay: Math.random() * 10,
      duration: Math.random() * 8 + 6, size: Math.random() * 40 + 20
    })
  }
  bubbles.value = newBubbles
}

async function handleSendCode() {
  if (!email.value) { errorMessage.value = '请输入邮箱'; return }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) { errorMessage.value = '请输入有效的邮箱地址'; return }
  if (emailRegistered.value) { errorMessage.value = '该邮箱已注册，请重新更换邮箱'; return }
  isSendingCode.value = true; errorMessage.value = ''
  try {
    const response = await authStore.sendEmailCode(email.value)
    if (response.success) {
      countdown.value = 60
      const timer = setInterval(() => { countdown.value--; if (countdown.value <= 0) clearInterval(timer) }, 1000)
    } else { errorMessage.value = response.message }
  } catch { errorMessage.value = '发送验证码失败，请稍后重试' }
  isSendingCode.value = false
}

async function handleRegister() {
  errorMessage.value = ''
  if (emailRegistered.value) { errorMessage.value = '该邮箱已注册，请重新更换邮箱'; return }
  if (!username.value || !email.value || !password.value || !confirmPassword.value) { errorMessage.value = '请填写所有必填项'; return }
  if (password.value !== confirmPassword.value) { errorMessage.value = '两次输入的密码不一致'; return }
  if (!emailCode.value) { errorMessage.value = '请输入邮箱验证码'; return }
  isLoading.value = true
  try {
    const response = await authStore.register(username.value, email.value, password.value, emailCode.value)
    if (response.success) {
      successMessage.value = '注册成功！即将跳转到登录页面...'
      setTimeout(() => router.push('/login'), 2000)
    } else { errorMessage.value = response.message }
  } catch { errorMessage.value = '注册失败，请稍后重试' }
  isLoading.value = false
}

onMounted(async () => {
  setTimeout(() => { isVisible.value = true }, 100)
  createMeteors()
  createStars()
  createBubbles()
  await nextTick()
  usernameInput.value?.focus()
})
</script>

<template>
  <div class="min-h-screen flex overflow-hidden">
    <router-link to="/" title="返回首页" class="fixed top-4 right-4 z-50 flex items-center gap-1.5 px-4 py-2 rounded-full bg-white/10 backdrop-blur border border-white/15 text-white/80 hover:text-white hover:bg-white/20 transition-all text-sm shadow-lg">
      <ChevronLeft class="w-4 h-4" />返回首页
    </router-link>
    <!-- ===== Left Brand Section ===== -->
    <div class="login-bg-left">
      <div class="stars-container" aria-hidden="true">
        <div v-for="star in stars" :key="star.id" class="star"
          :style="{ left: `${star.left}%`, top: `${star.top}%`, width: `${star.size}px`, height: `${star.size}px`, animationDelay: `${star.delay}s`, animationDuration: `${star.duration}s` }"></div>
      </div>
      <div class="meteors-container" aria-hidden="true">
        <div v-for="meteor in meteors" :key="meteor.id" class="meteor"
          :style="{ left: `${meteor.left}%`, animationDelay: `${meteor.delay}s`, animationDuration: `${meteor.duration}s`, '--meteor-size': `${meteor.size}px` }">
          <div class="meteor-head"></div>
          <div class="meteor-trail"></div>
        </div>
      </div>
      <div class="login-brand-content">
        <div class="w-24 h-24 bg-gradient-to-br from-purple-500 via-violet-500 to-indigo-600 rounded-3xl flex items-center justify-center shadow-xl mb-8 animate-float">
          <svg viewBox="0 0 24 24" fill="white" class="w-12 h-12">
            <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M13 12H3"/>
          </svg>
        </div>
        <h1 class="brand-title">加入{{ SITE_NAME }}</h1>
        <p class="brand-subtitle-class text-white/70 mb-12 max-w-lg">创建您的账号，开启安全可靠的云端存储之旅</p>

        <div class="grid grid-cols-3 gap-6 mb-10">
          <div class="bg-white/10 backdrop-blur rounded-xl p-6 text-center border border-white/10 hover:scale-105 transition-transform duration-300">
            <CloudUpload class="w-8 h-8 text-blue-400 mx-auto mb-3" aria-hidden="true" />
            <div class="text-white/90 text-base font-medium">文件上传</div>
            <div class="text-white/50 text-xs mt-1">断点续传</div>
          </div>
          <div class="bg-white/10 backdrop-blur rounded-xl p-6 text-center border border-white/10 hover:scale-105 transition-transform duration-300">
            <Shield class="w-8 h-8 text-cyan-400 mx-auto mb-3" aria-hidden="true" />
            <div class="text-white/90 text-base font-medium">安全保障</div>
            <div class="text-white/50 text-xs mt-1">加密存储</div>
          </div>
          <div class="bg-white/10 backdrop-blur rounded-xl p-6 text-center border border-white/10 hover:scale-105 transition-transform duration-300">
            <Users class="w-8 h-8 text-purple-400 mx-auto mb-3" aria-hidden="true" />
            <div class="text-white/90 text-base font-medium">分享协作</div>
            <div class="text-white/50 text-xs mt-1">团队共享</div>
          </div>
        </div>

        <div class="bg-gradient-to-r from-purple-500/20 to-indigo-500/20 backdrop-blur rounded-2xl p-8 border border-purple-500/20">
          <div class="flex items-center gap-6">
            <div class="w-16 h-16 bg-gradient-to-br from-purple-400 to-indigo-500 rounded-full flex items-center justify-center shadow-lg">
              <CheckCircle class="w-8 h-8 text-white" aria-hidden="true" />
            </div>
            <div>
              <p class="text-white font-bold text-2xl">免费注册</p>
              <p class="text-white/70 text-lg">赠300MB存储空间</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ===== Right Register Form ===== -->
    <div class="w-full lg:w-1/2 flex items-center justify-center px-8 py-12 bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 relative overflow-hidden">
      <!-- Mobile brand strip -->
      <div class="lg:hidden absolute top-0 left-0 right-0 z-20 px-6 py-4 flex items-center gap-3" style="background: linear-gradient(180deg, rgba(15,23,42,0.95), transparent);">
        <div class="w-9 h-9 bg-gradient-to-br from-purple-500 via-violet-500 to-indigo-600 rounded-xl flex items-center justify-center shadow-lg">
          <svg viewBox="0 0 24 24" fill="white" class="w-5 h-5">
            <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M13 12H3"/>
          </svg>
        </div>
        <div>
          <h2 class="text-white font-bold text-sm leading-tight">{{ SITE_NAME }}</h2>
          <p class="text-white/40 text-xs">创建您的账号</p>
        </div>
      </div>

      <div class="bubbles-container" aria-hidden="true">
        <div v-for="bubble in bubbles" :key="bubble.id" class="bubble"
          :style="{ left: `${bubble.left}%`, width: `${bubble.size}px`, height: `${bubble.size}px`, animationDelay: `${bubble.delay}s`, animationDuration: `${bubble.duration}s` }"></div>
      </div>

      <div class="w-full form-wrapper relative z-10">
        <!-- Success Message -->
        <div v-if="successMessage" class="mb-6">
          <div class="login-card" style="padding: 32px 40px;">
            <div class="text-center">
              <div class="w-16 h-16 bg-gradient-to-br from-green-400 to-emerald-500 rounded-full flex items-center justify-center mx-auto mb-4 shadow-lg shadow-green-500/30">
                <CheckCircle class="w-8 h-8 text-white" />
              </div>
              <h3 class="text-xl font-bold text-white mb-2">注册成功！</h3>
              <p class="text-white/60">即将跳转到登录页面...</p>
            </div>
          </div>
        </div>

        <!-- Register Card -->
        <div v-if="!successMessage" :class="['login-card transition-all duration-700', isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10']">
          <div class="card-border-glow" aria-hidden="true"></div>
          <div class="card-corner card-corner-tl" aria-hidden="true"></div>
          <div class="card-corner card-corner-tr" aria-hidden="true"></div>
          <div class="card-corner card-corner-bl" aria-hidden="true"></div>
          <div class="card-corner card-corner-br" aria-hidden="true"></div>

          <div class="relative z-10">
            <div class="text-center mb-8">
              <h2 class="text-3xl font-bold text-white mb-3">创建账号</h2>
              <p class="text-white/60 text-base">填写以下信息，加入{{ SITE_NAME }}</p>
            </div>

            <form @submit.prevent="handleRegister" novalidate class="space-y-5">
              <!-- Username -->
              <div>
                <label for="reg-username" class="block text-sm font-medium text-white/80 mb-2">用户名</label>
                <div class="relative group">
                  <div class="input-border-gradient" aria-hidden="true"></div>
                  <User class="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/40 group-focus-within:text-purple-400 transition-colors" aria-hidden="true" />
                  <input
                    id="reg-username"
                    ref="usernameInput"
                    v-model="username"
                    type="text"
                    autocomplete="username"
                    placeholder="请输入用户名"
                    :disabled="isLoading"
                    :aria-invalid="!!errorMessage"
                    aria-describedby="reg-error"
                    class="w-full pl-12 pr-4 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-base focus:ring-2 focus:ring-purple-500/30 focus:border-purple-500/50 outline-none transition-all relative z-10"
                  />
                </div>
              </div>

              <!-- Email -->
              <div>
                <label for="reg-email" class="block text-sm font-medium text-white/80 mb-2">邮箱</label>
                <div class="relative group">
                  <div class="input-border-gradient" aria-hidden="true"></div>
                  <Mail class="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/40 group-focus-within:text-purple-400 transition-colors" aria-hidden="true" />
                  <input
                    id="reg-email"
                    v-model="email"
                    type="email"
                    autocomplete="email"
                    placeholder="请输入邮箱地址"
                    :disabled="isLoading"
                    :aria-invalid="!!errorMessage"
                    aria-describedby="reg-error reg-email-hint"
                    :class="['w-full pl-12 pr-4 py-5 bg-white/5 border text-white placeholder-white/40 rounded-xl text-base focus:ring-2 outline-none transition-all relative z-10', emailRegistered ? 'border-red-500/60 focus:ring-red-500/30 focus:border-red-500/60' : 'border-white/10 focus:ring-purple-500/30 focus:border-purple-500/50']"
                  />
                </div>
                <p v-if="checkingEmail" class="text-white/40 text-xs mt-1.5">正在检测邮箱…</p>
                <p v-else-if="emailRegistered" id="reg-email-hint" class="text-red-400 text-xs mt-1.5">该邮箱已注册，请重新更换邮箱</p>
                <p v-else-if="emailFormatOk" id="reg-email-hint" class="text-emerald-400 text-xs mt-1.5">邮箱格式正确</p>
              </div>

              <!-- Password -->
              <div>
                <label for="reg-password" class="block text-sm font-medium text-white/80 mb-2">密码</label>
                <div class="relative group">
                  <div class="input-border-gradient" aria-hidden="true"></div>
                  <Lock class="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/40 group-focus-within:text-purple-400 transition-colors" aria-hidden="true" />
                  <input
                    id="reg-password"
                    v-model="password"
                    :type="showPassword ? 'text' : 'password'"
                    autocomplete="new-password"
                    placeholder="8-64位，至少三种字符类型"
                    :disabled="isLoading"
                    :aria-invalid="!!errorMessage"
                    aria-describedby="reg-error"
                    class="w-full pl-12 pr-14 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-base focus:ring-2 focus:ring-purple-500/30 focus:border-purple-500/50 outline-none transition-all relative z-10"
                  />
                  <button type="button" @click="showPassword = !showPassword"
                    :aria-label="showPassword ? '隐藏密码' : '显示密码'"
                    class="absolute right-4 top-1/2 transform -translate-y-1/2 text-white/40 hover:text-white/60 transition-colors z-20">
                    <Eye v-if="showPassword" class="w-5 h-5" />
                    <EyeOff v-else class="w-5 h-5" />
                  </button>
                </div>
              </div>

              <!-- Confirm Password -->
              <div>
                <label for="reg-confirm" class="block text-sm font-medium text-white/80 mb-2">确认密码</label>
                <div class="relative group">
                  <div class="input-border-gradient" aria-hidden="true"></div>
                  <Lock class="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/40 group-focus-within:text-purple-400 transition-colors" aria-hidden="true" />
                  <input
                    id="reg-confirm"
                    v-model="confirmPassword"
                    :type="showConfirmPassword ? 'text' : 'password'"
                    autocomplete="new-password"
                    placeholder="请再次输入密码"
                    :disabled="isLoading"
                    :aria-invalid="!!errorMessage"
                    aria-describedby="reg-error"
                    class="w-full pl-12 pr-14 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-base focus:ring-2 focus:ring-purple-500/30 focus:border-purple-500/50 outline-none transition-all relative z-10"
                  />
                  <button type="button" @click="showConfirmPassword = !showConfirmPassword"
                    :aria-label="showConfirmPassword ? '隐藏确认密码' : '显示确认密码'"
                    class="absolute right-4 top-1/2 transform -translate-y-1/2 text-white/40 hover:text-white/60 transition-colors z-20">
                    <Eye v-if="showConfirmPassword" class="w-5 h-5" />
                    <EyeOff v-else class="w-5 h-5" />
                  </button>
                </div>
              </div>

              <!-- Verification Code -->
              <div>
                <label for="reg-code" class="block text-sm font-medium text-white/80 mb-2">邮箱验证码</label>
                <div class="flex gap-3">
                  <div class="relative group flex-1">
                    <div class="input-border-gradient" aria-hidden="true"></div>
                    <input
                      id="reg-code"
                      v-model="emailCode"
                      type="text"
                      maxlength="6"
                      placeholder="请输入验证码"
                      :disabled="isLoading"
                      :aria-invalid="!!errorMessage"
                      aria-describedby="reg-error"
                      class="w-full px-4 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-base focus:ring-2 focus:ring-purple-500/30 focus:border-purple-500/50 outline-none transition-all relative z-10 tracking-[0.5em] text-center font-mono"
                    />
                  </div>
                  <button type="button" @click="handleSendCode"
                    :disabled="isSendingCode || countdown > 0 || !email"
                    class="px-5 py-5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 disabled:from-gray-700 disabled:to-gray-700 text-white rounded-xl text-sm font-semibold whitespace-nowrap transition-all flex items-center gap-2 disabled:cursor-not-allowed shadow-lg shadow-purple-600/20">
                    <Loader2 v-if="isSendingCode" class="w-4 h-4 animate-spin" />
                    <Send v-else-if="countdown === 0" class="w-4 h-4" />
                    <span>{{ countdown > 0 ? countdown + 's' : isSendingCode ? '发送中' : '获取验证码' }}</span>
                  </button>
                </div>
              </div>

              <!-- Error -->
              <div v-if="errorMessage" id="reg-error" role="alert" aria-live="assertive"
                class="flex items-center gap-2 p-4 bg-red-500/15 border border-red-500/30 text-red-300 rounded-xl text-sm animate-shake">
                <svg class="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <span>{{ errorMessage }}</span>
              </div>

              <!-- Submit -->
              <button type="submit" :disabled="isLoading"
                class="w-full py-5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 disabled:from-purple-600/50 disabled:to-indigo-600/50 text-white rounded-xl text-lg font-semibold transition-all duration-300 transform hover:scale-[1.02] active:scale-[0.98] flex items-center justify-center gap-2 group shadow-lg shadow-purple-600/20">
                <Loader2 v-if="isLoading" class="w-5 h-5 animate-spin" aria-hidden="true" />
                <template v-else>
                  <span>立即注册</span>
                  <ArrowRight class="w-5 h-5 group-hover:translate-x-1 transition-transform" aria-hidden="true" />
                </template>
              </button>

              <!-- Login Link -->
              <div class="text-center text-white/60 text-sm space-y-1 pt-2">
                <p>已有账号？</p>
                <router-link to="/login" class="text-purple-400 hover:text-purple-300 font-medium transition-colors inline-flex items-center gap-1 group">
                  立即登录
                  <ArrowRight class="w-4 h-4 group-hover:translate-x-1 transition-transform" aria-hidden="true" />
                </router-link>
              </div>
            </form>
          </div>
        </div>

        <div class="text-center mt-8">
          <p class="text-white/20 text-xs">注册即表示同意 <router-link to="/terms" class="text-white/40 hover:text-white/60">服务条款</router-link> 和 <router-link to="/privacy" class="text-white/40 hover:text-white/60">隐私政策</router-link></p>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.login-bg-left { display: none; }

@media (min-width: 1024px) {
  .login-bg-left {
    display: flex;
    width: 50%;
    position: relative;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 30%, #0f172a 60%, #1a1a2e 100%);
    overflow: hidden;
    padding: clamp(40px, 5vh, 80px) clamp(24px, 4vw, 60px);
  }
  .login-brand-content {
    position: relative;
    z-index: 1;
    width: 100%;
    max-width: clamp(320px, 36vw, 560px);
    display: flex;
    flex-direction: column;
    align-items: center;
  }
}

/* Particles */
.stars-container { position: absolute; inset: 0; overflow: hidden; z-index: 0; }
.star { position: absolute; background: white; border-radius: 50%; animation: twinkle ease-in-out infinite; will-change: opacity, transform; }
@keyframes twinkle { 0%, 100% { opacity: 0.2; transform: scale(1); } 50% { opacity: 1; transform: scale(1.5); } }

.meteors-container { position: absolute; inset: 0; overflow: hidden; z-index: 0; }
.meteor { position: absolute; top: -20px; animation: meteor-fall linear infinite; will-change: transform, opacity; }
.meteor-head { width: var(--meteor-size, 2px); height: var(--meteor-size, 2px); background: white; border-radius: 50%; box-shadow: 0 0 6px 2px rgba(255,255,255,0.8), 0 0 10px 4px rgba(168,139,250,0.6); }
.meteor-trail { position: absolute; top: 50%; right: 100%; width: 100px; height: 1px; background: linear-gradient(to left, rgba(255,255,255,0.8), transparent); transform: translateY(-50%); }
@keyframes meteor-fall { 0% { transform: translateY(0) rotate(35deg); opacity: 1; } 70% { opacity: 1; } 100% { transform: translateY(100vh) rotate(35deg); opacity: 0; } }

.bubbles-container { position: absolute; inset: 0; overflow: hidden; z-index: 0; pointer-events: none; }
.bubble { position: absolute; bottom: -60px; border-radius: 50%; border: 1px solid rgba(255,255,255,0.1); background: radial-gradient(circle at 30% 30%, rgba(168,139,250,0.08), transparent); animation: bubble-rise linear infinite; will-change: transform, opacity; }
@keyframes bubble-rise { 0% { transform: translateY(0) scale(1); opacity: 0; } 10% { opacity: 0.5; } 90% { opacity: 0.5; } 100% { transform: translateY(-100vh) scale(0.8); opacity: 0; } }

/* Card */
.login-card { background: rgba(255,255,255,0.05); backdrop-filter: blur(20px); border-radius: 28px; border: 1px solid rgba(255,255,255,0.1); padding: clamp(28px, 5vw, 56px) clamp(20px, 5vw, 56px); box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5), 0 0 80px rgba(139,92,246,0.1); position: relative; overflow: hidden; transition: box-shadow 0.3s ease; }
.login-card:hover { box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5), 0 0 100px rgba(139,92,246,0.2); }

.card-border-glow { position: absolute; inset: -2px; border-radius: 30px; background: linear-gradient(45deg, rgba(139,92,246,0.2), rgba(99,102,241,0.2), rgba(168,85,247,0.2), rgba(139,92,246,0.2)); background-size: 400% 400%; animation: border-flow 8s linear infinite; z-index: -1; opacity: 0.6; }
@keyframes border-flow { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }

.card-corner { position: absolute; width: 24px; height: 24px; border-radius: 6px; }
.card-corner-tl { top: 24px; left: 24px; background: linear-gradient(135deg, rgba(139,92,246,0.6), transparent); }
.card-corner-tr { top: 24px; right: 24px; background: linear-gradient(225deg, rgba(168,85,247,0.6), transparent); }
.card-corner-bl { bottom: 24px; left: 24px; background: linear-gradient(45deg, rgba(99,102,241,0.6), transparent); }
.card-corner-br { bottom: 24px; right: 24px; background: linear-gradient(315deg, rgba(139,92,246,0.6), transparent); }

.input-border-gradient { position: absolute; inset: -2px; border-radius: 16px; background: linear-gradient(45deg, rgba(139,92,246,0), rgba(99,102,241,0), rgba(168,85,247,0)); opacity: 0; transition: opacity 0.3s; z-index: 0; }
.group:focus-within .input-border-gradient { opacity: 1; background: linear-gradient(45deg, rgba(139,92,246,0.4), rgba(99,102,241,0.4), rgba(168,85,247,0.4)); }

/* Animations */
@keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
@keyframes shake { 0%, 100% { transform: translateX(0); } 10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); } 20%, 40%, 60%, 80% { transform: translateX(5px); } }
@keyframes spin { to { transform: rotate(360deg); } }
.animate-float { animation: float 6s ease-in-out infinite; }
.animate-shake { animation: shake 0.5s ease-in-out; }
.animate-spin { animation: spin 1s linear infinite; }

/* Typography */
.brand-title { font-size: clamp(2rem, 5vw, 3.75rem); }
.brand-subtitle-class { font-size: clamp(1rem, 2.2vw, 1.5rem); }

/* Form wrapper */
.form-wrapper { max-width: 100%; }

/* Responsive */
@media (min-width: 640px) {
  .form-wrapper { max-width: 480px; }
  .login-card { padding: 48px 40px; }
}

@media (min-width: 1024px) {
  .form-wrapper { max-width: 512px; }
  .login-card { padding: 56px 48px; }
}

@media (min-width: 1440px) {
  .login-bg-left { width: 48%; }
  .form-wrapper { max-width: 576px; }
  .login-card { padding: 60px 56px; }
}

@media (min-width: 1920px) {
  .login-bg-left { width: 46%; }
  .form-wrapper { max-width: 640px; }
  .login-card { padding: 68px 64px; border-radius: 32px; }
  .card-border-glow { border-radius: 34px; }
}

@media (min-width: 2560px) {
  .login-bg-left { width: 44%; }
  .form-wrapper { max-width: 720px; }
  .login-card { padding: 80px 72px; border-radius: 36px; }
  .card-border-glow { border-radius: 38px; }
}
</style>
