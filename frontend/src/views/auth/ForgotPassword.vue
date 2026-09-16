<script setup lang="ts">
import { SITE_NAME } from '@/config/site'
import { R_AUTH_RESET_PASSWORD, R_AUTH_VERIFY_CODE } from '@/utils/routeCodes'

import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { request } from '@/utils/axios'
import {  Mail, Shield, Eye, EyeOff, ArrowRight, CheckCircle, Clock, Send, ChevronLeft } from 'lucide-vue-next'

const router = useRouter()
const authStore = useAuthStore()

const email = ref('')
const verificationCode = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const showPassword = ref(false)
const showConfirmPassword = ref(false)
const isLoading = ref(false)
const errorMessage = ref('')
const successMessage = ref('')
const isVisible = ref(false)
const currentStep = ref(1)
const countdown = ref(0)

const meteors = ref<Array<{ id: number; left: number; delay: number; duration: number; size: number }>>([])
const stars = ref<Array<{ id: number; left: number; top: number; size: number; delay: number; duration: number }>>([])
const bubbles = ref<Array<{ id: number; left: number; delay: number; duration: number; size: number }>>([])

function createMeteors() {
  const newMeteors = []
  for (let i = 0; i < 8; i++) {
    newMeteors.push({
      id: i,
      left: Math.random() * 100,
      delay: Math.random() * 8,
      duration: Math.random() * 3 + 2,
      size: Math.random() * 2 + 1
    })
  }
  meteors.value = newMeteors
}

function createStars() {
  const newStars = []
  for (let i = 0; i < 50; i++) {
    newStars.push({
      id: i,
      left: Math.random() * 100,
      top: Math.random() * 100,
      size: Math.random() * 3 + 1,
      delay: Math.random() * 3,
      duration: Math.random() * 2 + 1
    })
  }
  stars.value = newStars
}

function createBubbles() {
  const newBubbles = []
  for (let i = 0; i < 20; i++) {
    newBubbles.push({
      id: i,
      left: Math.random() * 100,
      delay: Math.random() * 10,
      duration: Math.random() * 8 + 6,
      size: Math.random() * 40 + 20
    })
  }
  bubbles.value = newBubbles
}

async function sendVerificationCode() {
  if (!email.value) {
    errorMessage.value = '请输入邮箱地址'
    return
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  if (!emailRegex.test(email.value)) {
    errorMessage.value = '请输入有效的邮箱地址'
    return
  }

  isLoading.value = true
  errorMessage.value = ''

  try {
    const response = await authStore.sendEmailCode(email.value)
    
    if (response.success) {
      countdown.value = 60
      const timer = setInterval(() => {
        countdown.value--
        if (countdown.value <= 0) {
          clearInterval(timer)
        }
      }, 1000)
      
      successMessage.value = '验证码已发送至您的邮箱，请查收'
      currentStep.value = 2
    } else {
      errorMessage.value = response.message
    }
  } catch {
    errorMessage.value = '发送失败，请稍后重试'
  } finally {
    isLoading.value = false
  }
}

async function verifyCode() {
  if (!verificationCode.value) {
    errorMessage.value = '请输入验证码'
    return
  }

  isLoading.value = true
  errorMessage.value = ''

  try {
    const response = await request({
      url: R_AUTH_VERIFY_CODE,
      method: 'POST',
      data: {
        email: email.value,
        code: verificationCode.value
      }
    })
    
    if (response.success) {
      currentStep.value = 3
      successMessage.value = ''
    } else {
      errorMessage.value = response.message
    }
  } catch {
    errorMessage.value = '验证码错误，请重新输入'
  } finally {
    isLoading.value = false
  }
}

async function resetPassword() {
  if (!newPassword.value) {
    errorMessage.value = '请输入新密码'
    return
  }

  if (newPassword.value.length < 6) {
    errorMessage.value = '密码长度不能少于6位'
    return
  }

  if (newPassword.value !== confirmPassword.value) {
    errorMessage.value = '两次输入的密码不一致'
    return
  }

  isLoading.value = true
  errorMessage.value = ''

  try {
    const response = await request({
      url: R_AUTH_RESET_PASSWORD,
      method: 'POST',
      data: {
        email: email.value,
        code: verificationCode.value,
        newPassword: newPassword.value
      }
    })
    
    if (response.success) {
      successMessage.value = '密码重置成功！即将跳转到登录页面...'
      setTimeout(() => {
        router.push('/login')
      }, 2000)
    } else {
      errorMessage.value = response.message
    }
  } catch {
    errorMessage.value = '密码重置失败，请稍后重试'
  } finally {
    isLoading.value = false
  }
}

function goBack() {
  router.push('/login')
}

function resendCode() {
  verificationCode.value = ''
  sendVerificationCode()
}

onMounted(() => {
  setTimeout(() => {
    isVisible.value = true
  }, 100)
  
  createMeteors()
  createStars()
  createBubbles()
})
</script>

<template>
  <div class="min-h-screen flex overflow-hidden">
    <router-link to="/" title="返回首页" class="fixed top-4 right-4 z-50 flex items-center gap-1.5 px-4 py-2 rounded-full bg-white/10 backdrop-blur border border-white/15 text-white/80 hover:text-white hover:bg-white/20 transition-all text-sm shadow-lg">
      <ChevronLeft class="w-4 h-4" />返回首页
    </router-link>
    <div class="login-bg-left">
      <div class="stars-container">
        <div
          v-for="star in stars"
          :key="star.id"
          class="star"
          :style="{
            left: `${star.left}%`,
            top: `${star.top}%`,
            width: `${star.size}px`,
            height: `${star.size}px`,
            animationDelay: `${star.delay}s`,
            animationDuration: `${star.duration}s`
          }"
        ></div>
      </div>

      <div class="meteors-container">
        <div
          v-for="meteor in meteors"
          :key="meteor.id"
          class="meteor"
          :style="{
            left: `${meteor.left}%`,
            animationDelay: `${meteor.delay}s`,
            animationDuration: `${meteor.duration}s`,
            '--meteor-size': `${meteor.size}px`
          }"
        >
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
            <Shield class="w-8 h-8 text-cyan-400 mx-auto mb-3" />
            <div class="text-white/90 text-base font-medium">安全保障</div>
            <div class="text-white/50 text-xs mt-1">加密存储</div>
          </div>
          <div class="bg-white/10 backdrop-blur rounded-xl p-6 text-center border border-white/10 hover:scale-105 transition-transform duration-300">
            <Mail class="w-8 h-8 text-blue-400 mx-auto mb-3" />
            <div class="text-white/90 text-base font-medium">邮件验证</div>
            <div class="text-white/50 text-xs mt-1">安全可靠</div>
          </div>
          <div class="bg-white/10 backdrop-blur rounded-xl p-6 text-center border border-white/10 hover:scale-105 transition-transform duration-300">
            <CheckCircle class="w-8 h-8 text-green-400 mx-auto mb-3" />
            <div class="text-white/90 text-base font-medium">重置成功</div>
            <div class="text-white/50 text-xs mt-1">即时生效</div>
          </div>
        </div>

        <div class="bg-gradient-to-r from-green-500/20 to-emerald-500/20 backdrop-blur rounded-2xl p-8 border border-green-500/20">
          <div class="flex items-center gap-6">
            <div class="w-16 h-16 bg-gradient-to-br from-green-400 to-emerald-500 rounded-full flex items-center justify-center shadow-lg">
              <CheckCircle class="w-8 h-8 text-white" />
            </div>
            <div>
              <p class="text-white font-bold text-2xl">免费使用</p>
              <p class="text-white/70 text-lg">无需会员，赠送300MB</p>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <div class="w-full lg:w-1/2 flex items-center justify-center px-8 py-12 bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 relative overflow-hidden">
      <div class="lg:hidden absolute top-0 left-0 right-0 z-20 px-6 py-4 flex items-center gap-3" style="background: linear-gradient(180deg, rgba(15,23,42,0.95), transparent);">
        <div class="w-9 h-9 bg-gradient-to-br from-blue-500 via-cyan-500 to-blue-600 rounded-xl flex items-center justify-center shadow-lg">
          <svg viewBox="0 0 24 24" fill="white" class="w-5 h-5">
            <path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/>
          </svg>
        </div>
        <div>
          <h2 class="text-white font-bold text-sm leading-tight">{{ SITE_NAME }}</h2>
          <p class="text-white/40 text-xs">找回密码</p>
        </div>
      </div>
      <div class="bubbles-container">
        <div
          v-for="bubble in bubbles"
          :key="bubble.id"
          class="bubble"
          :style="{
            left: `${bubble.left}%`,
            width: `${bubble.size}px`,
            height: `${bubble.size}px`,
            animationDelay: `${bubble.delay}s`,
            animationDuration: `${bubble.duration}s`
          }"
        ></div>
      </div>

      <div 
        class="w-full form-wrapper relative z-10 transition-all duration-1000 ease-out"
        :class="isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-10'"
      >
        <div class="login-card">
          <div class="card-border-glow"></div>
          <div class="card-corner card-corner-tl"></div>
          <div class="card-corner card-corner-tr"></div>
          <div class="card-corner card-corner-bl"></div>
          <div class="card-corner card-corner-br"></div>
          
          <div class="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 via-cyan-500 to-purple-500"></div>

          <div class="relative z-10">
            <div class="text-center mb-10">
              <div class="inline-flex items-center gap-2 px-6 py-3 bg-white/10 rounded-full mb-6">
                <Shield class="w-5 h-5 text-blue-400" />
                <span class="text-white/70 text-base">安全重置</span>
              </div>
              <h2 class="text-4xl font-bold text-white mb-4">找回密码</h2>
              <p class="text-white/60 text-lg">通过邮箱验证安全重置您的密码</p>
            </div>

            <div class="flex justify-center gap-4 mb-10">
              <div 
                class="w-12 h-12 rounded-full flex items-center justify-center transition-all duration-300"
                :class="currentStep >= 1 ? 'bg-blue-500 text-white' : 'bg-white/10 text-white/40'"
              >
                <span class="font-bold text-lg">1</span>
              </div>
              <div class="w-16 h-1 bg-white/20 self-center"></div>
              <div 
                class="w-12 h-12 rounded-full flex items-center justify-center transition-all duration-300"
                :class="currentStep >= 2 ? 'bg-blue-500 text-white' : 'bg-white/10 text-white/40'"
              >
                <span class="font-bold text-lg">2</span>
              </div>
              <div class="w-16 h-1 bg-white/20 self-center"></div>
              <div 
                class="w-12 h-12 rounded-full flex items-center justify-center transition-all duration-300"
                :class="currentStep >= 3 ? 'bg-blue-500 text-white' : 'bg-white/10 text-white/40'"
              >
                <span class="font-bold text-lg">3</span>
              </div>
            </div>

            <div class="flex justify-center gap-8 mb-8 text-sm">
              <span :class="currentStep >= 1 ? 'text-blue-400' : 'text-white/40'">输入邮箱</span>
              <span :class="currentStep >= 2 ? 'text-blue-400' : 'text-white/40'">验证身份</span>
              <span :class="currentStep >= 3 ? 'text-blue-400' : 'text-white/40'">设置新密码</span>
            </div>

            <form v-if="currentStep === 1" @submit.prevent="sendVerificationCode" class="space-y-6">
              <div>
                <label class="block text-base font-medium text-white/80 mb-3">邮箱地址</label>
                <div class="relative group">
                  <div class="input-border-gradient"></div>
                  <Mail class="absolute left-5 top-1/2 transform -translate-y-1/2 w-6 h-6 text-white/40 group-focus-within:text-blue-400 transition-colors" />
                  <input
                    v-model="email"
                    id="forgot-email"
                    name="email"
                    autocomplete="email"
                    type="email"
                    placeholder="请输入注册时使用的邮箱"
                    class="w-full pl-14 pr-5 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-lg focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50 outline-none transition-all relative z-10"
                  />
                </div>
              </div>

              <div v-if="successMessage" class="p-5 bg-green-500/15 border border-green-500/30 text-green-300 rounded-xl text-base">
                {{ successMessage }}
              </div>

              <div v-if="errorMessage" class="p-5 bg-red-500/15 border border-red-500/30 text-red-300 rounded-xl text-base animate-shake">
                {{ errorMessage }}
              </div>

              <button
                type="submit"
                :disabled="isLoading"
                class="w-full py-6 bg-gradient-to-r from-blue-500 via-cyan-500 to-blue-600 text-white rounded-xl hover:from-blue-600 hover:via-cyan-600 hover:to-blue-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed font-semibold text-xl shadow-lg hover:shadow-xl hover:shadow-blue-500/20 flex items-center justify-center gap-3 relative overflow-hidden group"
              >
                <span class="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700"></span>
                <span v-if="isLoading" class="relative z-10">发送中...</span>
                <template v-else>
                  <Send class="w-6 h-6 relative z-10" />
                  <span class="relative z-10">发送验证码</span>
                </template>
              </button>

              <div class="text-center">
                <button type="button" @click="goBack" class="text-white/60 hover:text-white/80 transition-colors text-base">
                  返回登录
                </button>
              </div>
            </form>

            <form v-else-if="currentStep === 2" @submit.prevent="verifyCode" class="space-y-6">
              <div>
                <label class="block text-base font-medium text-white/80 mb-3">验证码</label>
                <div class="relative group">
                  <div class="input-border-gradient"></div>
                  <input
                    v-model="verificationCode"
                    id="forgot-code"
                    name="code"
                    autocomplete="off"
                    type="text"
                    placeholder="请输入6位验证码"
                    maxlength="6"
                    class="w-full pl-5 pr-40 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-lg focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50 outline-none transition-all relative z-10 tracking-widest"
                  />
                  <button
                    type="button"
                    @click="resendCode"
                    :disabled="countdown > 0 || isLoading"
                    class="absolute right-3 top-1/2 transform -translate-y-1/2 bg-gray-700/80 border border-white/20 rounded-lg px-4 py-2.5 text-white/70 text-base cursor-pointer hover:bg-gray-600/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 z-20"
                  >
                    <Clock v-if="countdown > 0" class="w-5 h-5" />
                    <Send v-else class="w-5 h-5" />
                    <span>{{ countdown > 0 ? `${countdown}s` : '重新发送' }}</span>
                  </button>
                </div>
              </div>

              <div v-if="successMessage" class="p-5 bg-green-500/15 border border-green-500/30 text-green-300 rounded-xl text-base">
                {{ successMessage }}
              </div>

              <div v-if="errorMessage" class="p-5 bg-red-500/15 border border-red-500/30 text-red-300 rounded-xl text-base animate-shake">
                {{ errorMessage }}
              </div>

              <button
                type="submit"
                :disabled="isLoading"
                class="w-full py-6 bg-gradient-to-r from-blue-500 via-cyan-500 to-blue-600 text-white rounded-xl hover:from-blue-600 hover:via-cyan-600 hover:to-blue-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed font-semibold text-xl shadow-lg hover:shadow-xl hover:shadow-blue-500/20 flex items-center justify-center gap-3 relative overflow-hidden group"
              >
                <span class="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700"></span>
                <span v-if="isLoading" class="relative z-10">验证中...</span>
                <template v-else>
                  <span class="relative z-10">确认验证</span>
                  <ArrowRight class="w-6 h-6 relative z-10 group-hover:translate-x-1 transition-transform" />
                </template>
              </button>

              <div class="text-center">
                <button type="button" @click="goBack" class="text-white/60 hover:text-white/80 transition-colors text-base">
                  返回登录
                </button>
              </div>
            </form>

            <form v-else-if="currentStep === 3" @submit.prevent="resetPassword" class="space-y-6">
              <div>
                <label class="block text-base font-medium text-white/80 mb-3">新密码</label>
                <div class="relative group">
                  <div class="input-border-gradient"></div>
                  <Shield class="absolute left-5 top-1/2 transform -translate-y-1/2 w-6 h-6 text-white/40 group-focus-within:text-blue-400 transition-colors" />
                  <input
                    v-model="newPassword"
                    id="forgot-password"
                    name="password"
                    autocomplete="new-password"
                    :type="showPassword ? 'text' : 'password'"
                    placeholder="请输入新密码（至少6位）"
                    class="w-full pl-14 pr-16 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-lg focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50 outline-none transition-all relative z-10"
                  />
                  <button
                    type="button"
                    @click="showPassword = !showPassword"
                    class="absolute right-5 top-1/2 transform -translate-y-1/2 text-white/40 hover:text-white/60 transition-colors z-20"
                  >
                    <Eye v-if="showPassword" class="w-6 h-6" />
                    <EyeOff v-else class="w-6 h-6" />
                  </button>
                </div>
              </div>

              <div>
                <label class="block text-base font-medium text-white/80 mb-3">确认新密码</label>
                <div class="relative group">
                  <div class="input-border-gradient"></div>
                  <Shield class="absolute left-5 top-1/2 transform -translate-y-1/2 w-6 h-6 text-white/40 group-focus-within:text-blue-400 transition-colors" />
                  <input
                    v-model="confirmPassword"
                    id="forgot-confirm-password"
                    name="confirm_password"
                    autocomplete="new-password"
                    :type="showConfirmPassword ? 'text' : 'password'"
                    placeholder="请再次输入新密码"
                    class="w-full pl-14 pr-16 py-5 bg-white/5 border border-white/10 text-white placeholder-white/40 rounded-xl text-lg focus:ring-2 focus:ring-blue-500/30 focus:border-blue-500/50 outline-none transition-all relative z-10"
                  />
                  <button
                    type="button"
                    @click="showConfirmPassword = !showConfirmPassword"
                    class="absolute right-5 top-1/2 transform -translate-y-1/2 text-white/40 hover:text-white/60 transition-colors z-20"
                  >
                    <Eye v-if="showConfirmPassword" class="w-6 h-6" />
                    <EyeOff v-else class="w-6 h-6" />
                  </button>
                </div>
              </div>

              <div v-if="successMessage" class="p-5 bg-green-500/15 border border-green-500/30 text-green-300 rounded-xl text-base flex items-center gap-3">
                <CheckCircle class="w-6 h-6" />
                {{ successMessage }}
              </div>

              <div v-if="errorMessage" class="p-5 bg-red-500/15 border border-red-500/30 text-red-300 rounded-xl text-base animate-shake">
                {{ errorMessage }}
              </div>

              <button
                type="submit"
                :disabled="isLoading"
                class="w-full py-6 bg-gradient-to-r from-green-500 via-emerald-500 to-green-600 text-white rounded-xl hover:from-green-600 hover:via-emerald-600 hover:to-green-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed font-semibold text-xl shadow-lg hover:shadow-xl hover:shadow-green-500/20 flex items-center justify-center gap-3 relative overflow-hidden group"
              >
                <span class="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700"></span>
                <span v-if="isLoading" class="relative z-10">重置中...</span>
                <template v-else>
                  <CheckCircle class="w-6 h-6 relative z-10" />
                  <span class="relative z-10">确认重置密码</span>
                </template>
              </button>

              <div class="text-center">
                <button type="button" @click="goBack" class="text-white/60 hover:text-white/80 transition-colors text-base">
                  返回登录
                </button>
              </div>
            </form>
          </div>
        </div>

        <div class="text-center mt-8">
          <p class="text-white/40 text-base">© 2026 {{ SITE_NAME }}. All rights reserved.</p>
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
}

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

.login-card { background: rgba(255,255,255,0.05); backdrop-filter: blur(20px); border-radius: 28px; border: 1px solid rgba(255,255,255,0.1); padding: clamp(28px, 5vw, 60px) clamp(20px, 5vw, 60px); box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5), 0 0 80px rgba(59,130,246,0.1); position: relative; overflow: hidden; transition: box-shadow 0.3s ease; }
.login-card:hover { box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5), 0 0 100px rgba(59,130,246,0.2); }

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
.animate-float { animation: float 6s ease-in-out infinite; }
.animate-shake { animation: shake 0.5s ease-in-out; }

/* Brand typography */
.brand-title { font-size: clamp(2rem, 5vw, 3.75rem); }
.brand-subtitle-class { font-size: clamp(1rem, 2.2vw, 1.5rem); }

.form-wrapper { max-width: 100%; }

/* ========== RESPONSIVE ========== */
@media (min-width: 640px) {
  .form-wrapper { max-width: 520px; }
  .login-card { padding: 48px 40px; }
}

@media (min-width: 1024px) {
  .form-wrapper { max-width: 580px; }
  .login-card { padding: 56px 48px; }
}

@media (min-width: 1440px) {
  .login-bg-left { width: 48%; }
  .form-wrapper { max-width: 640px; }
  .login-card { padding: 60px 56px; }
}

@media (min-width: 1920px) {
  .login-bg-left { width: 46%; }
  .form-wrapper { max-width: 700px; }
  .login-card { padding: 68px 64px; border-radius: 32px; }
  .card-border-glow { border-radius: 34px; }
}

@media (min-width: 2560px) {
  .login-bg-left { width: 44%; }
  .form-wrapper { max-width: 780px; }
  .login-card { padding: 80px 72px; border-radius: 36px; }
  .card-border-glow { border-radius: 38px; }
}
</style>
