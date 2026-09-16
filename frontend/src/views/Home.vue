<script setup lang="ts">
import { SITE_NAME, RECOMMEND_URL, RECOMMEND_ENABLED, RECOMMEND_TITLE, RECOMMEND_DESC, STUDIO_NAME } from '@/config/site'
import { R_SITE_INFO } from '@/utils/routeCodes'

import { ref, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { request } from '@/utils/axios'
import { Upload, Download, Shield, Users, ArrowRight, ChevronDown, Cloud, Smartphone, Globe, Lock, Server } from 'lucide-vue-next'
import BrandLogo from '@/components/BrandLogo.vue'

const authStore = useAuthStore()
const isLoaded = ref(false)
const maintenanceNotice = ref('')
const showMaintenance = ref(false)

onMounted(async () => {
  setTimeout(() => { isLoaded.value = true }, 100)
  try {
    const siteRes = await request<{ site_name?: string; disabled_notice?: string }>({ url: R_SITE_INFO, method: 'GET' })
    const notice = (siteRes.data?.disabled_notice || '').trim()
    if (notice && sessionStorage.getItem('maintenance_dismissed') !== '1') {
      maintenanceNotice.value = notice
      showMaintenance.value = true
    }
  } catch (e) { /* silent */ }
})

function dismissMaintenance() {
  showMaintenance.value = false
  sessionStorage.setItem('maintenance_dismissed', '1')
}

const features = [
  {
    icon: Upload,
    title: '文件上传',
    description: '支持多种文件格式，大文件上传，断点续传',
    color: 'from-blue-500 to-cyan-500',
    bgGlow: 'rgba(59,130,246,0.3)'
  },
  {
    icon: Download,
    title: '文件下载',
    description: '稳定下载，支持断点续传，多种下载方式',
    color: 'from-green-500 to-emerald-500',
    bgGlow: 'rgba(34,197,94,0.3)'
  },
  {
    icon: Shield,
    title: '安全保障',
    description: '端到端加密，多重安全防护，文件防篡改',
    color: 'from-purple-500 to-pink-500',
    bgGlow: 'rgba(168,85,247,0.3)'
  },
  {
    icon: Users,
    title: '分享协作',
    description: '文件分享，密码保护，访问权限控制',
    color: 'from-orange-500 to-yellow-500',
    bgGlow: 'rgba(251,146,60,0.3)'
  }
]

const stats = [
  { icon: Cloud, value: '99.9%', label: '服务可用性', color: 'text-blue-400' },
  { icon: Smartphone, value: '多端', label: '随时访问', color: 'text-amber-400' },
  { icon: Globe, value: '300MB', label: '免费存储', color: 'text-emerald-400' },
  { icon: Lock, value: 'AES-256', label: '加密标准', color: 'text-purple-400' },
]

function scrollToFeatures() {
  document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' })
}
</script>

<template>
  <div class="min-h-screen relative overflow-hidden">
    <!-- 站点维护公告：管理员在「系统设置 → 站点维护」发布后全屏展示，可手动关闭（本次会话内不再弹出） -->
    <div v-if="showMaintenance" class="fixed inset-0 z-[90] flex items-center justify-center p-4 sm:p-6 bg-slate-950/85 backdrop-blur-md overflow-y-auto">
      <div class="relative w-full max-w-3xl">
        <button @click="dismissMaintenance" aria-label="关闭维护公告" class="absolute -top-3 -right-3 z-10 w-9 h-9 rounded-full bg-slate-800 border border-slate-600 text-slate-300 hover:bg-slate-700 hover:text-white flex items-center justify-center shadow-lg transition-colors">✕</button>
        <div v-html="maintenanceNotice"></div>
      </div>
    </div>
    <!-- ===== BACKGROUND (KEPT) ===== -->
    <div class="fixed inset-0 z-0">
      <img 
        src="/app-screenshot.png" 
        alt="背景" 
        class="w-full h-full object-cover"
      />
      <div class="absolute inset-0 bg-gradient-to-b from-black/40 via-black/20 to-black/80"></div>
    </div>

    <!-- ===== DECORATIVE ORBS (KEPT) ===== -->
    <div class="fixed inset-0 z-0 pointer-events-none">
      <div class="absolute top-20 left-10 w-32 h-32 bg-white/5 rounded-full blur-3xl animate-pulse"></div>
      <div class="absolute top-40 right-20 w-48 h-48 bg-blue-500/10 rounded-full blur-3xl animate-pulse" style="animation-delay: 1s;"></div>
      <div class="absolute bottom-40 left-1/4 w-40 h-40 bg-cyan-500/10 rounded-full blur-3xl animate-pulse" style="animation-delay: 2s;"></div>
    </div>

    <!-- ===== NAV BAR ===== -->
    <nav class="fixed top-0 left-0 right-0 z-50 nav-glass">
      <div class="max-w-6xl mx-auto px-4 sm:px-6 py-3 sm:py-4 flex items-center justify-between">
        <router-link to="/" class="flex items-center gap-3 group">
          <BrandLogo :size="38" with-text />
        </router-link>

        <div class="flex items-center gap-2 sm:gap-3">
          <router-link v-if="authStore.isLoggedIn" to="/dashboard"
            class="px-4 sm:px-6 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-lg text-sm font-medium hover:from-blue-500 hover:to-cyan-500 transition-all shadow-lg shadow-blue-600/20">
            进入控制台
          </router-link>
          <template v-else>
            <router-link to="/login" class="px-3 sm:px-4 py-2 text-white/70 hover:text-white text-sm transition-colors">登录</router-link>
            <router-link to="/register" class="px-3 sm:px-5 py-2 bg-white/90 text-gray-900 rounded-lg text-sm font-semibold hover:bg-white transition-all shadow-lg shadow-white/10">注册</router-link>
          </template>
        </div>
      </div>
    </nav>

    <!-- ===== HERO SECTION ===== -->
    <section class="relative z-10 min-h-screen flex items-center justify-center px-4 sm:px-6">
      <div :class="['text-center max-w-4xl mx-auto transition-all duration-1000', isLoaded ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8']">
        <!-- Badge -->
        <div class="inline-flex items-center gap-2 px-4 py-2 bg-white/5 backdrop-blur-md rounded-full border border-white/10 mb-8">
          <span class="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></span>
          <span class="text-white/60 text-sm">免费注册，赠 300MB 存储空间</span>
        </div>

        <!-- Title -->
        <h1 class="hero-title">
          安全可靠的<br class="sm:hidden" />
          <span class="hero-gradient-text">云端存储</span>平台
        </h1>

        <p class="hero-subtitle">
          {{ SITE_NAME }}为您提供安全、稳定、便捷的文件存储与管理服务。<br class="hidden sm:block" />随时随地访问您的文件，轻松分享与协作。
        </p>

        <!-- CTA Buttons -->
        <div class="flex flex-col sm:flex-row items-center justify-center gap-3 sm:gap-4 mb-12">
          <router-link v-if="authStore.isLoggedIn" to="/dashboard"
            class="w-full sm:w-auto px-8 py-4 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-xl text-lg font-semibold hover:from-blue-500 hover:to-cyan-500 transition-all shadow-xl shadow-blue-600/30 flex items-center justify-center gap-2 group hover:-translate-y-0.5">
            进入控制台
            <ArrowRight class="w-5 h-5 group-hover:translate-x-1 transition-transform" />
          </router-link>
          <template v-else>
            <router-link to="/register"
              class="w-full sm:w-auto px-8 py-4 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-xl text-lg font-semibold hover:from-blue-500 hover:to-cyan-500 transition-all shadow-xl shadow-blue-600/30 flex items-center justify-center gap-2 group hover:-translate-y-0.5">
              免费注册
              <ArrowRight class="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            </router-link>
            <router-link to="/login"
              class="w-full sm:w-auto px-8 py-4 bg-white/10 backdrop-blur-md border border-white/20 text-white rounded-xl text-lg font-medium hover:bg-white/20 transition-all hover:-translate-y-0.5">
              已有账号？立即登录
            </router-link>
          </template>
        </div>

        <!-- Scroll Indicator -->
        <button @click="scrollToFeatures" class="scroll-indicator mx-auto">
          <ChevronDown class="w-5 h-5" />
        </button>
      </div>
    </section>

    <!-- ===== STATS SECTION ===== -->
    <section class="relative z-10 py-16 sm:py-20 px-4 sm:px-6">
      <div class="max-w-5xl mx-auto">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 sm:gap-6">
          <div v-for="(stat, i) in stats" :key="stat.label"
            class="stat-card"
            :style="{ animationDelay: `${0.2 + i * 0.1}s` }">
            <component :is="stat.icon" :class="['w-6 h-6 sm:w-7 sm:h-7 mb-3', stat.color]" />
            <div class="text-2xl sm:text-3xl font-bold text-white mb-1">{{ stat.value }}</div>
            <div class="text-white/40 text-xs sm:text-sm">{{ stat.label }}</div>
          </div>
        </div>
      </div>
    </section>

    <!-- ===== FEATURES SECTION ===== -->
    <section id="features" class="relative z-10 py-16 sm:py-24 px-4 sm:px-6">
      <div class="max-w-6xl mx-auto">
        <div class="text-center mb-12 sm:mb-16">
          <span class="inline-block px-3 py-1 bg-white/5 rounded-full text-blue-400 text-xs sm:text-sm font-medium mb-4 border border-white/5">核心功能</span>
          <h3 class="text-3xl sm:text-4xl font-bold text-white mb-4">功能特性</h3>
          <p class="text-white/50 text-base sm:text-lg max-w-xl mx-auto">全方位满足您的云端存储需求</p>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 sm:gap-6">
          <div 
            v-for="(feature, index) in features" 
            :key="feature.title"
            class="feature-card group"
            :style="{
              animationDelay: `${0.1 + index * 0.1}s`,
              '--glow-color': feature.bgGlow
            }"
          >
            <!-- Icon -->
            <div class="feature-icon" :class="feature.color">
              <component :is="feature.icon" class="w-7 h-7 text-white" />
            </div>
            
            <h4 class="text-lg font-semibold text-white mb-2 group-hover:text-blue-300 transition-colors">{{ feature.title }}</h4>
            <p class="text-white/40 text-sm leading-relaxed">{{ feature.description }}</p>
            
            <!-- Hover glow -->
            <div class="feature-glow"></div>
          </div>
        </div>
      </div>
    </section>

    <!-- ===== RECOMMEND SECTION: 友情推荐（未配置 VITE_RECOMMEND_URL 时整块隐藏） ===== -->
    <section v-if="RECOMMEND_ENABLED" class="relative z-10 py-14 sm:py-20 px-4 sm:px-6">
      <div class="max-w-4xl mx-auto">
        <div class="recommend-card">
          <div class="flex flex-col sm:flex-row items-center gap-6 sm:gap-8">
            <div class="recommend-icon">
              <Server class="w-8 h-8 text-white" />
            </div>
            <div class="flex-1 text-center sm:text-left">
              <div class="inline-flex items-center gap-2 px-3 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-full mb-3">
                <span class="text-emerald-300 text-xs">友情推荐</span>
              </div>
              <h4 class="text-xl sm:text-2xl font-bold text-white mb-2">{{ RECOMMEND_TITLE }}</h4>
              <p class="text-white/50 text-sm sm:text-base leading-relaxed">
                {{ RECOMMEND_DESC }}
              </p>
            </div>
            <a
              :href="RECOMMEND_URL"
              target="_blank"
              rel="noopener noreferrer nofollow sponsored"
              class="recommend-btn shrink-0"
            >
              <span>看看服务器</span>
              <ArrowRight class="w-4 h-4" />
            </a>
          </div>
        </div>
      </div>
    </section>
    <!-- ===== FOOTER (品牌化) ===== -->
    <footer class="relative z-10 bg-black/40 backdrop-blur-sm border-t border-white/10">
      <div class="max-w-6xl mx-auto px-4 sm:px-6 py-14">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-10">
          <div class="space-y-5">
            <BrandLogo :size="44" with-text show-subtitle />
            <p class="text-white/55 text-sm leading-relaxed">
              让每个普通人都能安心存储，<br class="hidden sm:block" />这是{{ SITE_NAME }}不变的初心。
            </p>
            <div class="inline-flex items-center gap-2 px-3 py-1.5 bg-blue-500/10 border border-blue-500/20 rounded-full">
              <Shield class="w-3.5 h-3.5 text-blue-300" />
              <span class="text-blue-200 text-xs">7×24 全天候守护</span>
            </div>
          </div>

          <div>
            <h4 class="text-white font-semibold mb-4">产品</h4>
            <ul class="space-y-3 text-sm">
              <li><button @click="scrollToFeatures" class="text-white/55 hover:text-white transition-colors">核心功能</button></li>
              <li><router-link to="/dashboard" class="text-white/55 hover:text-white transition-colors">进入控制台</router-link></li>
              <li><router-link to="/register" class="text-white/55 hover:text-white transition-colors">免费注册</router-link></li>
              <li><router-link to="/system" class="text-white/55 hover:text-white transition-colors">系统信息</router-link></li>
            </ul>
          </div>

          <div>
            <h4 class="text-white font-semibold mb-4">支持</h4>
            <ul class="space-y-3 text-sm">
              <li><router-link to="/help" class="text-white/55 hover:text-white transition-colors">帮助中心</router-link></li>
              <li><router-link to="/contact" class="text-white/55 hover:text-white transition-colors">联系我们</router-link></li>
              <li><router-link to="/terms" class="text-white/55 hover:text-white transition-colors">服务条款</router-link></li>
              <li><router-link to="/privacy" class="text-white/55 hover:text-white transition-colors">隐私政策</router-link></li>
            </ul>
          </div>

          <div>
            <h4 class="text-white font-semibold mb-4">关于我们</h4>
            <ul class="space-y-3 text-sm">
              <li><router-link to="/about" class="text-white/55 hover:text-white transition-colors">关于我们</router-link></li>
              <li><router-link to="/about#story" class="text-white/55 hover:text-white transition-colors">我们的故事</router-link></li>
              <li><router-link to="/about#journey" class="text-white/55 hover:text-white transition-colors">发展历程</router-link></li>
            </ul>
          </div>
        </div>

        <div class="border-t border-white/10 mt-12 pt-8 flex flex-col md:flex-row items-center justify-between gap-5">
          <div v-if="STUDIO_NAME" class="studio-signature">
            <span class="studio-text">{{ STUDIO_NAME }}</span>
            <span class="studio-dot"></span>
            <span class="studio-tag">出品</span>
          </div>
          <p class="text-white/40 text-sm">© 2025–2026 {{ SITE_NAME }} ClassicCloud · All rights reserved.</p>
        </div>
      </div>
    </footer>
  </div>
</template>

<style scoped>
/* ===== NAV ===== */
.nav-glass {
  background: rgba(255, 255, 255, 0.06);
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

/* ===== HERO ===== */
.hero-title {
  font-size: clamp(2rem, 6vw, 3.75rem);
  font-weight: 800;
  color: white;
  line-height: 1.15;
  margin-bottom: clamp(16px, 2vh, 24px);
  letter-spacing: -0.02em;
}

.hero-gradient-text {
  background: linear-gradient(135deg, #60a5fa, #06b6d4, #a78bfa);
  background-size: 200% 200%;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  animation: heroGradient 4s ease-in-out infinite;
}

@keyframes heroGradient {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

.hero-subtitle {
  font-size: clamp(0.95rem, 1.5vw, 1.15rem);
  color: rgba(255, 255, 255, 0.5);
  margin-bottom: clamp(28px, 4vh, 40px);
  max-width: 600px;
  margin-left: auto;
  margin-right: auto;
  line-height: 1.7;
}

/* Scroll indicator */
.scroll-indicator {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  border-radius: 50%;
  border: 1px solid rgba(255, 255, 255, 0.2);
  color: rgba(255, 255, 255, 0.4);
  background: none;
  cursor: pointer;
  transition: all 0.3s;
  animation: scrollBounce 2s ease-in-out infinite;
}
.scroll-indicator:hover {
  border-color: rgba(255, 255, 255, 0.4);
  color: rgba(255, 255, 255, 0.7);
}

@keyframes scrollBounce {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(8px); }
}

/* ===== STATS ===== */
.stat-card {
  background: rgba(255, 255, 255, 0.04);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 16px;
  padding: clamp(20px, 3vw, 28px) clamp(14px, 2vw, 20px);
  text-align: center;
  opacity: 0;
  transform: translateY(20px);
  animation: fadeInUp 0.6s ease-out forwards;
  transition: transform 0.3s, border-color 0.3s;
}
.stat-card:hover {
  transform: translateY(-4px);
  border-color: rgba(255, 255, 255, 0.12);
}

@keyframes fadeInUp {
  to { opacity: 1; transform: translateY(0); }
}

/* ===== RECOMMEND ===== */
.recommend-card {
  position: relative;
  background: linear-gradient(135deg, rgba(16, 185, 129, 0.10), rgba(59, 130, 246, 0.08));
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  border: 1px solid rgba(255, 255, 255, 0.10);
  border-radius: 22px;
  padding: clamp(22px, 4vw, 34px);
  transition: border-color 0.3s, transform 0.3s;
}
.recommend-card:hover {
  transform: translateY(-3px);
  border-color: rgba(255, 255, 255, 0.2);
}

.recommend-icon {
  width: 60px;
  height: 60px;
  border-radius: 18px;
  background: linear-gradient(135deg, #10b981, #3b82f6);
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 10px 28px rgba(16, 185, 129, 0.28);
}

.recommend-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border-radius: 12px;
  background: linear-gradient(135deg, #10b981, #3b82f6);
  color: #fff;
  font-size: 14px;
  font-weight: 600;
  text-decoration: none;
  box-shadow: 0 8px 22px rgba(16, 185, 129, 0.25);
  transition: transform 0.25s, box-shadow 0.25s;
}
.recommend-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 12px 28px rgba(16, 185, 129, 0.38);
}
/* ===== FEATURES ===== */
.feature-card {
  position: relative;
  background: rgba(255, 255, 255, 0.03);
  backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 20px;
  padding: clamp(24px, 4vw, 32px);
  overflow: hidden;
  opacity: 0;
  transform: translateY(24px);
  animation: fadeInUp 0.6s ease-out forwards;
  transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
}

.feature-card:hover {
  transform: translateY(-6px);
  border-color: rgba(255, 255, 255, 0.15);
  background: rgba(255, 255, 255, 0.06);
}

.feature-icon {
  width: 52px;
  height: 52px;
  border-radius: 14px;
  background: linear-gradient(135deg, var(--tw-gradient-from), var(--tw-gradient-to));
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 20px;
  box-shadow: 0 8px 24px var(--glow-color);
  transition: transform 0.3s;
}

.feature-card:hover .feature-icon {
  transform: scale(1.1);
}

.feature-glow {
  position: absolute;
  inset: 0;
  border-radius: 20px;
  background: radial-gradient(600px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), var(--glow-color, rgba(59,130,246,0.08)), transparent 40%);
  opacity: 0;
  transition: opacity 0.4s;
  pointer-events: none;
}

.feature-card:hover .feature-glow {
  opacity: 1;
}

/* ===== STUDIO SIGNATURE ===== */
.studio-signature {
  display: flex;
  align-items: center;
  gap: 8px;
}

.studio-text {
  font-size: 16px;
  font-weight: 600;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
  background-size: 200% 200%;
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: studioGradient 3s ease-in-out infinite;
  letter-spacing: 2px;
}

.studio-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: linear-gradient(135deg, #667eea, #764ba2);
  animation: studioPulse 2s ease-in-out infinite;
}

.studio-tag {
  font-size: 12px;
  padding: 2px 8px;
  border-radius: 10px;
  background: linear-gradient(135deg, rgba(102, 126, 234, 0.2), rgba(118, 75, 162, 0.2));
  border: 1px solid rgba(102, 126, 234, 0.3);
  color: rgba(255, 255, 255, 0.8);
  animation: studioGlow 2.5s ease-in-out infinite;
}

@keyframes studioGradient {
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
}

@keyframes studioPulse {
  0%, 100% { transform: scale(1); opacity: 1; box-shadow: 0 0 0 0 rgba(102, 126, 234, 0.7); }
  50% { transform: scale(1.2); opacity: 0.8; box-shadow: 0 0 0 6px rgba(102, 126, 234, 0); }
}

@keyframes studioGlow {
  0%, 100% { box-shadow: 0 0 5px rgba(102, 126, 234, 0.3), 0 0 10px rgba(118, 75, 162, 0.2); }
  50% { box-shadow: 0 0 15px rgba(102, 126, 234, 0.5), 0 0 25px rgba(118, 75, 162, 0.3); }
}
</style>
