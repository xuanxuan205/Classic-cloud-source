<script setup lang="ts">
import { SITE_NAME } from '@/config/site'
import { ref, watch, onMounted, nextTick } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import {  Eye, EyeOff, Mail, Lock, ArrowRight, Shield, CloudUpload, Users, CheckCircle, RefreshCw, Loader2, ShieldAlert, AlertCircle, Clock, ChevronLeft } from 'lucide-vue-next'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const username = ref('')
const password = ref('')
const showPassword = ref(false)
const isLoading = ref(false)
const errorMessage = ref('')
const errorKind = ref<'error' | 'banned' | 'rate' | 'locked'>('error')
const isVisible = ref(false)
const rememberMe = ref(false)
const captchaText = ref('')
const userCaptcha = ref('')
const usernameInput = ref<HTMLInputElement | null>(null)
const suppressClearError = ref(false)
const twoFactorRequired = ref(false)
const twoFactorToken = ref('')
const twoFactorCode = ref('')
const twoFactorError = ref('')

const meteors = ref<Array<{ id: number; left: number; delay: number; duration: number; size: number }>>([])
const stars = ref<Array<{ id: number; left: number; top: number; size: number; delay: number; duration: number }>>([])
const bubbles = ref<Array<{ id: number; left: number; delay: number; duration: number; size: number }>>([])

watch([username, password, userCaptcha, twoFactorCode], () => {
  // 登录失败后程序化重置验证码时保留错误提示，避免提示一闪而过
  if (suppressClearError.value) {
    suppressClearError.value = false
    return
  }
  if (errorMessage.value) {
    errorMessage.value = ''
    errorKind.value = 'error'
  }
  if (twoFactorError.value) {
    twoFactorError.value = ''
  }
})

function setError(msg: string) {
  errorMessage.value = msg
  if (msg.includes('封禁')) errorKind.value = 'banned'
  else if (msg.includes('频繁') || msg.includes('过多')) errorKind.value = 'rate'
  else if (msg.includes('锁定')) errorKind.value = 'locked'
  else errorKind.value = 'error'
}

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

function generateCaptcha() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let result = ''
  for (let i = 0; i < 4; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  captchaText.value = result
}

async function handleLogin() {
  errorMessage.value = ''
  errorKind.value = 'error'
  if (!username.value || !password.value) {
    setError('请输入用户名和密码')
    return
  }
  if (!userCaptcha.value) {
    setError('请输入验证码')
    return
  }
  if (userCaptcha.value.toLowerCase() !== captchaText.value.toLowerCase()) {
    setError('验证码错误，请重新输入')
    suppressClearError.value = true
    generateCaptcha()
    userCaptcha.value = ''
    return
  }

  isLoading.value = true
  try {
    const response = await authStore.login(username.value, password.value, rememberMe.value)
    if (response.success) {
      // IronWall v1.28.0: 已开启两步验证的账号先进入动态码第二步
      const data: any = (response as any).data || {}
      if (data.two_factor_required) {
        twoFactorRequired.value = true
        twoFactorToken.value = data.two_factor_token || ''
        twoFactorCode.value = ''
        twoFactorError.value = ''
        return
      }
      const redirect = route.query.redirect as string || '/dashboard'
      router.push(redirect)
    } else {
      setError(response.message || '账号或密码错误')
      suppressClearError.value = true
      generateCaptcha()
      userCaptcha.value = ''
    }
  } catch (e: any) {
    if (e?.response?.data?.message) {
      setError(e.response.data.message)
    } else if (e?.message) {
      setError(e.message)
    } else {
      setError('登录失败，请检查网络连接')
    }
    suppressClearError.value = true
    generateCaptcha()
    userCaptcha.value = ''
  } finally {
    isLoading.value = false
  }
}

function backToPasswordStep() {
  twoFactorRequired.value = false
  twoFactorToken.value = ''
  twoFactorCode.value = ''
  twoFactorError.value = ''
}

async function handleTwoFactorSubmit() {
  twoFactorError.value = ''
  const code = twoFactorCode.value.trim()
  if (!/^\d{6}$/.test(code)) {
    twoFactorError.value = '请输入 6 位动态验证码'
    return
  }
  isLoading.value = true
  try {
    const response = await authStore.completeTwoFactorLogin(twoFactorToken.value, code)
    if (response.success) {
      const redirect = route.query.redirect as string || '/dashboard'
      router.push(redirect)
    } else {
      twoFactorError.value = response.message || '动态验证码错误或已过期'
    }
  } catch (e: any) {
    twoFactorError.value = e?.response?.data?.message || e?.message || '验证失败，请重试'
  } finally {
    isLoading.value = false
  }
}

onMounted(async () => {
  setTimeout(() => { isVisible.value = true }, 100)
  createMeteors()
  createStars()
  createBubbles()
  generateCaptcha()
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
        <div class="w-24 h-24 bg-gradient-to-br from-blue-500 via-cyan-500 to-blue-600 rounded-3xl flex items-center justify-center shadow-xl mb-8 animate-float">
          <svg viewBox="0 0 24 24" fill="white" class="w-12 h-12">
            <path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/>
          </svg>
        </div>
        <h1 class="brand-title font-bold text-white mb-6">{{ SITE_NAME }}</h1>
        <p class="brand-subtitle-class text-white/70 mb-12 max-w-lg">安全可靠的云端存储服务，让您的文件随时随地安全访问</p>

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

        <div class="bg-gradient-to-r from-green-500/20 to-emerald-500/20 backdrop-blur rounded-2xl p-8 border border-green-500/20">
          <div class="flex items-center gap-6">
            <div class="w-16 h-16 bg-gradient-to-br from-green-400 to-emerald-500 rounded-full flex items-center justify-center shadow-lg">
              <CheckCircle class="w-8 h-8 text-white" aria-hidden="true" />
            </div>
            <div>
              <p class="text-white font-bold text-2xl">免费使用</p>
              <p class="text-white/70 text-lg">无需会员，赠300MB</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ===== Right Login Form ===== -->
    <div class="w-full lg:w-1/2 flex items-center justify-center px-8 py-12 bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 relative overflow-hidden">
      <!-- Mobile brand strip -->
      <div class="lg:hidden absolute top-0 left-0 right-0 z-20 px-6 py-4 flex items-center gap-3" style="background: linear-gradient(180deg, rgba(15,23,42,0.95), transparent);">
        <div class="w-9 h-9 bg-gradient-to-br from-blue-500 via-cyan-500 to-blue-600 rounded-xl flex items-center justify-center shadow-lg">
          <svg viewBox="0 0 24 24" fill="white" class="w-5 h-5">
            <path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/>
          </svg>
        </div>
        <div>
          <h2 class="text-white font-bold text-sm leading-tight">{{ SITE_NAME }}</h2>
          <p class="text-white/40 text-xs">安全可靠的云端存储</p>
        </div>
      </div>

      <div class="bubbles-container" aria-hidden="true">
        <div v-for="bubble in bubbles" :key="bubble.id" class="bubble"
          :style="{ left: `${bubble.left}%`, width: `${bubble.size}px`, height: `${bubble.size}px`, animationDelay: `${bubble.delay}s`, animationDuration: `${bubble.duration}s` }"></div>
      </div>

      <div class="w-full form-wrapper relative z-10">
        <div :class="['login-card transition-all duration-700', isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10']">
          <div class="card-border-glow" aria-hidden="true"></div>
          <div class="card-corner card-corner-tl" aria-hidden="true"></div>
          <div class="card-corner card-corner-tr" aria-hidden="true"></div>
          <div class="card-corner card-corner-bl" aria-hidden="true"></div>
          <div class="card-corner card-corner-br" aria-hidden="true"></div>

          <div class="relative z-10">
            <div class="text-center mb-10">
              <h2 class="text-3xl font-bold text-white mb-3">欢迎回来</h2>
              <p class="text-white/60 text-lg">输入您的账号信息，开始使用{{ SITE_NAME }}服务</p>
            </div>

            <form v-if="!twoFactorRequired" @submit.prevent="handleLogin" novalidate class="space-y-6">
              <div>
                <label for="login-username" class="block text-sm font-medium text-white/80 mb-2">用户名或邮箱</label>
                <div class="relative group">
                  <div class="input-border-gradient" aria-hidden="true"></div>
                  <Mail class="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/40 group-focus-within:text-blue-400 transition-colors" aria-hidden="true" />
                  <input
                    id="login-username"
                    ref="usernameInput"
                    v-model="username"
                    type="text"
                    autocomplete="username"
                    placeholder="用户名 / 邮箱 / 用户ID"
                    :disabled="isLoading"
                    :aria-invalid="!!errorMessage"
                    aria-describedby="login-error"
                    class="w-full pl-12 pr-4 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-base focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50 outline-none transition-all relative z-10"
                  />
                </div>
              </div>

              <div>
                <label for="login-password" class="block text-sm font-medium text-white/80 mb-2">密码</label>
                <div class="relative group">
                  <div class="input-border-gradient" aria-hidden="true"></div>
                  <Lock class="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/40 group-focus-within:text-blue-400 transition-colors" aria-hidden="true" />
                  <input
                    id="login-password"
                    v-model="password"
                    :type="showPassword ? 'text' : 'password'"
                    autocomplete="current-password"
                    placeholder="请输入密码"
                    :disabled="isLoading"
                    :aria-invalid="!!errorMessage"
                    aria-describedby="login-error"
                    class="w-full pl-12 pr-14 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-base focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50 outline-none transition-all relative z-10"
                  />
                  <button type="button" @click="showPassword = !showPassword"
                    :aria-label="showPassword ? '隐藏密码' : '显示密码'"
                    class="absolute right-4 top-1/2 transform -translate-y-1/2 text-white/40 hover:text-white/60 transition-colors z-20">
                    <Eye v-if="showPassword" class="w-5 h-5" />
                    <EyeOff v-else class="w-5 h-5" />
                  </button>
                </div>
              </div>

              <div>
                <label for="login-captcha" class="block text-sm font-medium text-white/80 mb-2">验证码</label>
                <div class="relative group">
                  <div class="input-border-gradient" aria-hidden="true"></div>
                  <input
                    id="login-captcha"
                    v-model="userCaptcha"
                    type="text"
                    placeholder="请输入验证码"
                    maxlength="4"
                    :disabled="isLoading"
                    :aria-invalid="!!errorMessage"
                    aria-describedby="login-error"
                    class="w-full pl-4 pr-36 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-base focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50 outline-none transition-all relative z-10 tracking-widest"
                  />
                  <button type="button" @click="generateCaptcha()" :disabled="isLoading"
                    aria-label="刷新验证码"
                    class="absolute right-3 top-1/2 transform -translate-y-1/2 bg-gray-800/80 border border-white/20 rounded-lg px-4 py-2 cursor-pointer hover:bg-gray-700/80 transition-colors flex items-center gap-2 z-20">
                    <span class="captcha-display">{{ captchaText }}</span>
                    <RefreshCw class="w-4 h-4 text-white/50" />
                  </button>
                </div>
              </div>

              <div class="flex items-center justify-between">
                <label class="flex items-center gap-2 cursor-pointer select-none">
                  <input v-model="rememberMe" type="checkbox" :disabled="isLoading"
                    class="w-4 h-4 rounded border-white/30 bg-white/5 text-blue-500 focus:ring-blue-500/30 cursor-pointer accent-blue-500" />
                  <span class="text-white/50 text-sm hover:text-white/70 transition-colors">记住我（7天内自动登录）</span>
                </label>
                <router-link to="/forgot-password" class="text-blue-400 hover:text-blue-300 text-sm transition-colors">忘记密码？</router-link>
              </div>

              <div v-if="errorMessage" id="login-error" role="alert" aria-live="assertive"
                :class="['flex items-center gap-2 p-4 border rounded-xl text-sm animate-shake',
                  errorKind === 'banned' ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                  : (errorKind === 'rate' || errorKind === 'locked') ? 'bg-yellow-500/15 border-yellow-500/30 text-yellow-300'
                  : 'bg-red-500/15 border-red-500/30 text-red-300']">
                <ShieldAlert v-if="errorKind === 'banned'" class="w-5 h-5 shrink-0" aria-hidden="true" />
                <Clock v-else-if="errorKind === 'rate' || errorKind === 'locked'" class="w-5 h-5 shrink-0" aria-hidden="true" />
                <AlertCircle v-else class="w-5 h-5 shrink-0" aria-hidden="true" />
                <span>
                  {{ errorMessage }}
                  <router-link v-if="errorKind === 'banned'" to="/contact"
                    class="block mt-1 text-amber-200 underline underline-offset-4 hover:text-white transition-colors">
                    如有疑问，可联系管理员申诉 →
                  </router-link>
                </span>
              </div>

              <button type="submit" :disabled="isLoading"
                class="w-full py-5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 disabled:from-blue-600/50 disabled:to-cyan-600/50 text-white rounded-xl text-lg font-semibold transition-all duration-300 transform hover:scale-[1.02] active:scale-[0.98] flex items-center justify-center gap-2 group shadow-lg shadow-blue-600/20">
                <Loader2 v-if="isLoading" class="w-5 h-5 animate-spin" aria-hidden="true" />
                <template v-else>
                  <span>登录</span>
                  <ArrowRight class="w-5 h-5 group-hover:translate-x-1 transition-transform" aria-hidden="true" />
                </template>
              </button>

              <div class="text-center text-white/60 text-sm space-y-1">
                <p>还没有账号？</p>
                <router-link to="/register" class="text-blue-400 hover:text-blue-300 font-medium transition-colors inline-flex items-center gap-1 group">
                  立即注册
                  <ArrowRight class="w-4 h-4 group-hover:translate-x-1 transition-transform" aria-hidden="true" />
                </router-link>
              </div>
            </form>
<form v-else @submit.prevent="handleTwoFactorSubmit" novalidate class="space-y-6">
              <div class="text-center">
                <div class="w-16 h-16 mx-auto mb-4 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-2xl flex items-center justify-center shadow-lg shadow-cyan-600/20">
                  <Shield class="w-8 h-8 text-white" aria-hidden="true" />
                </div>
                <h3 class="text-white font-semibold text-lg">两步验证</h3>
                <p class="text-white/60 text-sm mt-1">您的账号已开启安全保护，请输入验证器 App 中的 6 位动态验证码</p>
              </div>
              <div>
                <label for="login-2fa-code" class="block text-sm font-medium text-white/80 mb-2">动态验证码</label>
                <div class="relative group">
                  <div class="input-border-gradient" aria-hidden="true"></div>
                  <Lock class="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-white/40 group-focus-within:text-cyan-400 transition-colors" aria-hidden="true" />
                  <input
                    id="login-2fa-code"
                    v-model="twoFactorCode"
                    type="text"
                    inputmode="numeric"
                    autocomplete="one-time-code"
                    maxlength="6"
                    placeholder="6 位动态验证码"
                    :disabled="isLoading"
                    aria-describedby="login-2fa-error"
                    class="w-full pl-12 pr-4 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-center text-2xl tracking-[0.4em] focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500/50 outline-none transition-all relative z-10"
                  />
                </div>
              </div>
              <div v-if="twoFactorError" id="login-2fa-error" role="alert" aria-live="assertive"
                class="flex items-center gap-2 p-4 bg-red-500/15 border border-red-500/30 text-red-300 rounded-xl text-sm animate-shake">
                <AlertCircle class="w-5 h-5 shrink-0" aria-hidden="true" />
                <span>{{ twoFactorError }}</span>
              </div>
              <button type="submit" :disabled="isLoading"
                class="w-full py-5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:from-cyan-600/50 disabled:to-blue-600/50 text-white rounded-xl text-lg font-semibold transition-all duration-300 transform hover:scale-[1.02] active:scale-[0.98] flex items-center justify-center gap-2 group shadow-lg shadow-cyan-600/20">
                <Loader2 v-if="isLoading" class="w-5 h-5 animate-spin" aria-hidden="true" />
                <template v-else>
                  <span>验证并登录</span>
                  <ArrowRight class="w-5 h-5 group-hover:translate-x-1 transition-transform" aria-hidden="true" />
                </template>
              </button>
              <button type="button" @click="backToPasswordStep" :disabled="isLoading"
                class="w-full py-3 text-white/60 hover:text-white/90 text-sm transition-colors flex items-center justify-center gap-1">
                <ChevronLeft class="w-4 h-4" aria-hidden="true" /> 返回上一步
              </button>
            </form>          </div>
        </div>

        <div class="text-center mt-8">
          <p class="text-white/30 text-sm">&copy; 2026 {{ SITE_NAME }} All rights reserved.</p>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* ============================================
   BASE: Mobile First ( < 640px )
   ============================================ */
.login-bg-left { display: none; }

/* Full viewport coverage */
.min-h-screen { min-height: 100dvh; }

/* Card full width on mobile */
.login-card {
  background: rgba(255,255,255,0.05);
  backdrop-filter: blur(20px);
  border-radius: 28px;
  border: 1px solid rgba(255,255,255,0.1);
  padding: clamp(28px, 5vw, 56px) clamp(20px, 5vw, 56px);
  box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5), 0 0 80px rgba(59,130,246,0.1);
  position: relative;
  overflow: hidden;
  transition: box-shadow 0.3s ease;
}
.login-card:hover { box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5), 0 0 100px rgba(59,130,246,0.2); }

/* Responsive typography */
.card-header-title {
  font-size: clamp(1.5rem, 4vw, 2rem);
}

/* Stars & animations */
.stars-container { position: absolute; inset: 0; overflow: hidden; z-index: 0; }
.star { position: absolute; background: white; border-radius: 50%; animation: twinkle ease-in-out infinite; will-change: opacity, transform; }
@keyframes twinkle { 0%, 100% { opacity: 0.2; transform: scale(1); } 50% { opacity: 1; transform: scale(1.5); } }

.meteors-container { position: absolute; inset: 0; overflow: hidden; z-index: 0; }
.meteor { position: absolute; top: -20px; animation: meteor-fall linear infinite; will-change: transform, opacity; }
.meteor-head { width: var(--meteor-size, 2px); height: var(--meteor-size, 2px); background: white; border-radius: 50%; box-shadow: 0 0 6px 2px rgba(255,255,255,0.8), 0 0 10px 4px rgba(100,200,255,0.6); }
.meteor-trail { position: absolute; top: 50%; right: 100%; width: 100px; height: 1px; background: linear-gradient(to left, rgba(255,255,255,0.8), transparent); transform: translateY(-50%); }
@keyframes meteor-fall { 0% { transform: translateY(0) rotate(35deg); opacity: 1; } 70% { opacity: 1; } 100% { transform: translateY(100vh) rotate(35deg); opacity: 0; } }

.bubbles-container { position: absolute; inset: 0; overflow: hidden; z-index: 0; pointer-events: none; }
.bubble { position: absolute; bottom: -60px; border-radius: 50%; border: 1px solid rgba(255,255,255,0.1); background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.1), transparent); animation: bubble-rise linear infinite; will-change: transform, opacity; }
@keyframes bubble-rise { 0% { transform: translateY(0) scale(1); opacity: 0; } 10% { opacity: 0.5; } 90% { opacity: 0.5; } 100% { transform: translateY(-100vh) scale(0.8); opacity: 0; } }

.card-border-glow { position: absolute; inset: -2px; border-radius: 30px; background: linear-gradient(45deg, rgba(59,130,246,0.2), rgba(6,182,212,0.2), rgba(147,51,234,0.2), rgba(59,130,246,0.2)); background-size: 400% 400%; animation: border-flow 8s linear infinite; z-index: -1; opacity: 0.6; }
@keyframes border-flow { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }

.card-corner { position: absolute; width: 24px; height: 24px; border-radius: 6px; }
.card-corner-tl { top: 24px; left: 24px; background: linear-gradient(135deg, rgba(59,130,246,0.6), transparent); }
.card-corner-tr { top: 24px; right: 24px; background: linear-gradient(225deg, rgba(147,51,234,0.6), transparent); }
.card-corner-bl { bottom: 24px; left: 24px; background: linear-gradient(45deg, rgba(6,182,212,0.6), transparent); }
.card-corner-br { bottom: 24px; right: 24px; background: linear-gradient(315deg, rgba(59,130,246,0.6), transparent); }

.input-border-gradient { position: absolute; inset: -2px; border-radius: 16px; background: linear-gradient(45deg, rgba(59,130,246,0), rgba(6,182,212,0), rgba(147,51,234,0)); opacity: 0; transition: opacity 0.3s; z-index: 0; }
.group:focus-within .input-border-gradient { opacity: 1; background: linear-gradient(45deg, rgba(59,130,246,0.4), rgba(6,182,212,0.4), rgba(147,51,234,0.4)); }

@keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
@keyframes shake { 0%, 100% { transform: translateX(0); } 10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); } 20%, 40%, 60%, 80% { transform: translateX(5px); } }
@keyframes spin { to { transform: rotate(360deg); } }
.animate-float { animation: float 6s ease-in-out infinite; }
.animate-shake { animation: shake 0.5s ease-in-out; }
.animate-spin { animation: spin 1s linear infinite; }
.captcha-display { font-size: clamp(1.1rem, 2vw, 1.35rem); font-weight: bold; letter-spacing: 0.4em; color: #ffffff; font-family: 'Courier New', 'Consolas', monospace; text-shadow: 0 0 10px rgba(59,130,246,0.5), 0 0 20px rgba(6,182,212,0.3); user-select: none; }

/* Form wrapper: full width on mobile */
.form-wrapper { max-width: 100%; }

/* Brand title responsive */
.brand-title { font-size: clamp(2rem, 5vw, 3.75rem); }
.brand-subtitle-class { font-size: clamp(1rem, 2.2vw, 1.5rem); }

/* Input field responsive padding */
input[class*="py-5"] { padding-top: clamp(14px, 2vw, 20px); padding-bottom: clamp(14px, 2vw, 20px); }


/* ============================================
   TABLET: 640px - 1023px
   ============================================ */
@media (min-width: 640px) {
  .form-wrapper { max-width: 480px; }
  .login-card { padding: 48px 40px; }
}


/* ============================================
   DESKTOP: 1024px - 1439px
   ============================================ */
@media (min-width: 1024px) {
  .login-bg-left {
    display: flex;
    width: 50%;
    position: relative;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 30%, #0f172a 60%, #1a1a2e 100%);
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
  .form-wrapper { max-width: 512px; }
  .login-card { padding: 56px 48px; }
}


/* ============================================
   LARGE DESKTOP: 1440px - 1919px
   ============================================ */
@media (min-width: 1440px) {
  .login-bg-left { width: 48%; }
  .form-wrapper { max-width: 576px; }
  .login-card { padding: 60px 56px; }
  input[class*="py-5"] {
    padding-top: 22px;
    padding-bottom: 22px;
    font-size: 1.05rem;
  }
}


/* ============================================
   XL DESKTOP / ULTRAWIDE: 1920px+
   ============================================ */
@media (min-width: 1920px) {
  .login-bg-left { width: 46%; }
  .form-wrapper { max-width: 640px; }
  .login-card {
    padding: 68px 64px;
    border-radius: 32px;
  }
  .card-border-glow { border-radius: 34px; }
  input[class*="py-5"] {
    padding-top: 24px;
    padding-bottom: 24px;
    font-size: 1.1rem;
  }
  .brand-title { font-size: clamp(3rem, 4vw, 4.5rem); }
  .brand-subtitle-class { font-size: clamp(1.2rem, 1.6vw, 1.8rem); }
}


/* ============================================
   4K: 2560px+
   ============================================ */
@media (min-width: 2560px) {
  .login-bg-left { width: 44%; }
  .form-wrapper { max-width: 720px; }
  .login-card {
    padding: 80px 72px;
    border-radius: 36px;
  }
  .card-border-glow { border-radius: 38px; }
  input[class*="py-5"] {
    padding-top: 28px;
    padding-bottom: 28px;
    font-size: 1.15rem;
  }
}
</style>
