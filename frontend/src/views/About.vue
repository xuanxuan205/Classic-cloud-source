<script setup lang="ts">
import { SITE_NAME, CONTACT_EMAIL, STUDIO_NAME } from '@/config/site'
import {
  BookOpen, Heart, ShieldCheck, TrendingUp,
  Mail, Clock, MessageSquare, Rocket, Sparkles
} from 'lucide-vue-next'
import AnimatedCloud from '@/components/AnimatedCloud.vue'
</script>

<template>
  <div class="min-h-screen relative overflow-hidden">
    <div class="fixed inset-0 z-0">
      <img 
        src="/app-screenshot.png" 
        alt="背景" 
        class="w-full h-full object-cover"
      />
      <div class="absolute inset-0 bg-gradient-to-b from-black/50 via-black/30 to-black/70"></div>
    </div>

    <nav class="fixed top-0 left-0 right-0 bg-white/10 backdrop-blur-lg shadow-sm z-50 border-b border-white/20">
      <div class="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <AnimatedCloud size="small" />
          <div>
            <h1 class="text-xl font-bold text-white">{{ SITE_NAME }}</h1>
          </div>
        </div>

        <div class="flex items-center gap-4">
          <router-link to="/" class="px-4 py-2 text-white/80 hover:text-white transition-all">首页</router-link>
          <router-link to="/about" class="px-4 py-2 bg-white/20 text-white rounded-lg hover:bg-white/30 transition-all backdrop-blur">关于我们</router-link>
          <router-link to="/terms" class="px-4 py-2 text-white/80 hover:text-white transition-all">服务条款</router-link>
          <router-link to="/privacy" class="px-4 py-2 text-white/80 hover:text-white transition-all">隐私政策</router-link>
          <router-link to="/contact" class="px-4 py-2 text-white/80 hover:text-white transition-all">联系我们</router-link>
          <router-link to="/login" class="px-4 py-2 text-white/80 hover:text-white transition-all">登录</router-link>
          <router-link to="/register" class="px-4 py-2 bg-white text-primary-600 rounded-lg hover:bg-white/90 transition-all font-medium">注册</router-link>
        </div>
      </div>
    </nav>

    <section class="relative z-10 pt-32 pb-12 px-6">
      <div class="max-w-4xl mx-auto text-center">
        <AnimatedCloud size="large" class="mx-auto mb-8" />
        <div class="inline-flex items-center gap-2 px-4 py-2 bg-white/10 backdrop-blur rounded-full border border-white/20 mb-6 about-badge">
          <Sparkles class="w-4 h-4 text-amber-300" />
          <span class="text-white/80 text-sm">从数据安全出发</span>
        </div>
        <h2 class="text-5xl font-bold text-white mb-6">关于我们</h2>
        <p class="text-xl text-white/80 max-w-2xl mx-auto">
          一个关于数据、信任与梦想的故事
        </p>
      </div>
    </section>

    <section class="relative z-10 py-8 px-6">
      <div class="max-w-5xl mx-auto">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-6 border border-white/10 text-center hover:border-white/30 hover:scale-105 transition-all stat-card">
            <div class="text-3xl font-bold text-white mb-1">100%</div>
            <div class="text-white/60 text-sm">免费使用</div>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-6 border border-white/10 text-center hover:border-white/30 hover:scale-105 transition-all stat-card">
            <div class="text-3xl font-bold text-white mb-1">300MB</div>
            <div class="text-white/60 text-sm">新用户赠送空间</div>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-6 border border-white/10 text-center hover:border-white/30 hover:scale-105 transition-all stat-card">
            <div class="text-3xl font-bold text-white mb-1">7层</div>
            <div class="text-white/60 text-sm">安全防护体系</div>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-6 border border-white/10 text-center hover:border-white/30 hover:scale-105 transition-all stat-card">
            <div class="text-3xl font-bold text-white mb-1">7×24</div>
            <div class="text-white/60 text-sm">全天候守护</div>
          </div>
        </div>
      </div>
    </section>

    <section id="story" class="relative z-10 py-16 px-6">
      <div class="max-w-3xl mx-auto">
        <div class="bg-white/5 backdrop-blur-xl rounded-2xl p-12 border border-white/10 story-card">
          <div class="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-amber-500 to-orange-500 rounded-2xl mb-8 mx-auto block">
            <BookOpen class="w-8 h-8 text-white" />
          </div>
          
          <h3 class="text-2xl font-bold text-white mb-6 text-center">故事的开始</h3>
          
          <div class="space-y-6 text-white/70 text-lg leading-relaxed">
            <p>
              2025年的一个普通下午，我们团队的创始人小路正在整理电脑里的文件。
              用着别人的云盘，空间不够要付费，数据还不掌握在自己手里，他心里总不踏实。
              一个念头冒了出来：为什么不亲手做一个真正属于大家的存储云？
              说干就干，他一个人写代码、搭服务，熬过无数个深夜，
              2025年5月13日，{{ SITE_NAME }}的第一个版本正式推出。
             </p>
             
             <p>
              第一个版本上线后，我们收获了第一批用户，也听到了许多真诚的建议。
              我们渐渐意识到，它还远远不够完整。与其修修补补，不如推倒重来——
              2026年7月20日，我们静下心从零开始自主研发第二个版本，
              历经无数个日夜的打磨，2026年9月5日，第二版本完成研发并正式推出。
             </p>
             
             <p>
              从那一刻起，他心里认定了一件事：<span class="text-white font-medium">数据安全，不应该是一件奢侈的事。</span>
            </p>
            
            <p>
              于是，{{ SITE_NAME }}的雏形就在那个小小的公寓里一天天长大。我们不想做一个复杂难懂的产品，
              只想做一个让普通人都能轻松用好的网盘——简单、安心、稳定。
            </p>
            
            <p>
              从最初的一个人，到现在的小团队，我们一直没有停下脚步。每一次优化，
              都是为了让您的数据更安全；每一次更新，都是为了让使用更省心。
            </p>
            
            <p>
              为了让这份承诺真正落地，我们没有选择现成的安全方案，而是从零自主研发了{{ SITE_NAME }}铁壁安全引擎，
              让层层防护成为每一位用户的标配，而不是付费才能享受的特权。
            </p>
            
            <p>
              我们深知，您存放在这里的不只是文件，可能是孩子的成长记录，
              可能是工作的心血成果，也可能是再也找不回的珍贵回忆。所以我们不敢有丝毫懈怠。
            </p>
            
            <p class="text-center pt-4">
              <span class="text-white font-medium">让每个普通人都能安心存储，这就是我们不变的初心。</span>
            </p>
          </div>
        </div>
      </div>
    </section>

    <section class="relative z-10 py-16 px-6">
      <div class="max-w-5xl mx-auto">
        <div class="text-center mb-10">
          <div class="inline-flex items-center gap-2 px-4 py-2 bg-green-500/10 backdrop-blur rounded-full border border-green-500/30 mb-6">
            <ShieldCheck class="w-4 h-4 text-green-400" />
            <span class="text-green-300 text-sm font-medium">数据绝对安全</span>
          </div>
          <h3 class="text-3xl font-bold text-white mb-4">自主研发安全引擎</h3>
          <p class="text-white/70 max-w-2xl mx-auto leading-relaxed">
            面对层出不穷的网络风险，{{ SITE_NAME }}铁壁安全引擎自动运行、全天候守护，
            将风险拦截在数据之外，让每一位用户安心存储。
          </p>
        </div>

        <div class="bg-white/5 backdrop-blur-xl rounded-2xl border border-white/10 p-6 md:p-10 overflow-hidden">
          <svg viewBox="0 0 1000 500" class="w-full h-auto engine-svg" role="img" aria-label="铁壁安全引擎动态防护示意图">
            <defs>
              <linearGradient id="aboutShieldGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#22d3ee" />
                <stop offset="100%" stop-color="#3b82f6" />
              </linearGradient>
              <linearGradient id="aboutAttackGrad" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stop-color="#ef4444" />
                <stop offset="100%" stop-color="#f97316" />
              </linearGradient>
              <linearGradient id="aboutDataGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="#34d399" />
                <stop offset="100%" stop-color="#059669" />
              </linearGradient>
              <radialGradient id="aboutGlowGrad">
                <stop offset="0%" stop-color="#fbbf24" stop-opacity="0.95" />
                <stop offset="100%" stop-color="#fbbf24" stop-opacity="0" />
              </radialGradient>
            </defs>

            <!-- 攻击源 -->
            <g class="attacker">
              <rect x="150" y="72" width="116" height="36" rx="10" fill="url(#aboutAttackGrad)" opacity="0.9" />
              <text x="208" y="96" text-anchor="middle" fill="#fff" font-size="16" font-weight="600">异常请求</text>
            </g>
            <g class="attacker" style="animation-delay: 0.5s;">
              <rect x="150" y="157" width="116" height="36" rx="10" fill="url(#aboutAttackGrad)" opacity="0.9" />
              <text x="208" y="181" text-anchor="middle" fill="#fff" font-size="16" font-weight="600">恶意脚本</text>
            </g>
            <g class="attacker" style="animation-delay: 1s;">
              <rect x="150" y="325" width="116" height="36" rx="10" fill="url(#aboutAttackGrad)" opacity="0.9" />
              <text x="208" y="349" text-anchor="middle" fill="#fff" font-size="16" font-weight="600">暴力尝试</text>
            </g>
            <g class="attacker" style="animation-delay: 1.5s;">
              <rect x="150" y="410" width="116" height="36" rx="10" fill="url(#aboutAttackGrad)" opacity="0.9" />
              <text x="208" y="434" text-anchor="middle" fill="#fff" font-size="16" font-weight="600">端口探测</text>
            </g>

            <!-- 攻击轨迹 -->
            <g stroke="#ef4444" stroke-width="2" fill="none" stroke-dasharray="6 6" opacity="0.7">
              <path id="aboutAtk1" d="M266 90 C 370 90, 410 250, 505 250">
                <animate attributeName="stroke-dashoffset" from="24" to="0" dur="0.8s" repeatCount="indefinite" />
              </path>
              <path id="aboutAtk2" d="M266 175 C 370 175, 410 250, 505 250">
                <animate attributeName="stroke-dashoffset" from="24" to="0" dur="0.8s" begin="0.2s" repeatCount="indefinite" />
              </path>
              <path id="aboutAtk3" d="M266 343 C 370 343, 410 250, 505 250">
                <animate attributeName="stroke-dashoffset" from="24" to="0" dur="0.8s" begin="0.4s" repeatCount="indefinite" />
              </path>
              <path id="aboutAtk4" d="M266 428 C 370 428, 410 250, 505 250">
                <animate attributeName="stroke-dashoffset" from="24" to="0" dur="0.8s" begin="0.6s" repeatCount="indefinite" />
              </path>
            </g>

            <!-- 攻击弹丸 -->
            <g fill="#fca5a5" opacity="0.9">
              <g>
                <circle r="10" opacity="0.35" />
                <circle r="5" />
                <animateMotion dur="2.8s" repeatCount="indefinite">
                  <mpath href="#aboutAtk1" />
                </animateMotion>
              </g>
              <g>
                <circle r="10" opacity="0.35" />
                <circle r="5" />
                <animateMotion dur="3.4s" begin="1.4s" repeatCount="indefinite">
                  <mpath href="#aboutAtk2" />
                </animateMotion>
              </g>
              <g>
                <circle r="10" opacity="0.35" />
                <circle r="5" />
                <animateMotion dur="3s" begin="0.7s" repeatCount="indefinite">
                  <mpath href="#aboutAtk3" />
                </animateMotion>
              </g>
              <g>
                <circle r="10" opacity="0.35" />
                <circle r="5" />
                <animateMotion dur="3.6s" begin="2.1s" repeatCount="indefinite">
                  <mpath href="#aboutAtk4" />
                </animateMotion>
              </g>
            </g>

            <!-- 拦截爆点 -->
            <g>
              <circle class="impact-dot" cx="505" cy="250" r="8" fill="url(#aboutGlowGrad)" />
              <circle class="impact-dot" cx="505" cy="250" r="8" fill="url(#aboutGlowGrad)" style="animation-delay: 0.4s;" />
              <circle class="impact-dot" cx="505" cy="250" r="8" fill="url(#aboutGlowGrad)" style="animation-delay: 0.8s;" />
            </g>

            <!-- 防护盾 -->
            <text x="640" y="118" text-anchor="middle" fill="#67e8f9" font-size="15" class="guard-label">全天候自动防护</text>
            <g fill="none" opacity="0.5">
              <circle cx="640" cy="250" r="128" stroke="#22d3ee" stroke-width="2" stroke-dasharray="8 8">
                <animateTransform attributeName="transform" type="rotate" from="0 640 250" to="360 640 250" dur="30s" repeatCount="indefinite" />
              </circle>
              <circle cx="640" cy="250" r="102" stroke="#60a5fa" stroke-width="2" stroke-dasharray="4 10">
                <animateTransform attributeName="transform" type="rotate" from="360 640 250" to="0 640 250" dur="20s" repeatCount="indefinite" />
              </circle>
              <circle cx="640" cy="250" r="78" stroke="#a78bfa" stroke-width="2" stroke-dasharray="2 8">
                <animateTransform attributeName="transform" type="rotate" from="0 640 250" to="360 640 250" dur="15s" repeatCount="indefinite" />
              </circle>
            </g>
            <path d="M640 165 L698 190 L698 250 Q698 302 640 332 Q582 302 582 250 L582 190 Z" fill="url(#aboutShieldGrad)" stroke="#e0f2fe" stroke-width="2" opacity="0.95" />
            <path d="M615 250 l18 18 l32 -38" fill="none" stroke="#fff" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" />
            <text x="640" y="292" text-anchor="middle" fill="#fff" font-size="14" font-weight="700">铁壁安全引擎</text>

            <!-- 安全通道 -->
            <g stroke="#22c55e" stroke-width="2" fill="none" stroke-dasharray="6 6" opacity="0.7">
              <path id="aboutSafe1" d="M705 250 L845 250">
                <animate attributeName="stroke-dashoffset" from="24" to="0" dur="0.8s" repeatCount="indefinite" />
              </path>
            </g>
            <g fill="#4ade80">
              <g>
                <circle r="9" opacity="0.4" />
                <circle r="4.5" />
                <animateMotion dur="1.8s" repeatCount="indefinite">
                  <mpath href="#aboutSafe1" />
                </animateMotion>
              </g>
            </g>

            <!-- 数据节点 -->
            <g class="data-node">
              <circle cx="890" cy="250" r="40" fill="url(#aboutDataGrad)" stroke="#bbf7d0" stroke-width="2" />
              <rect x="876" y="240" width="28" height="22" rx="4" fill="#fff" />
              <path d="M881 240 v-7 a9 9 0 0 1 18 0 v7" fill="none" stroke="#fff" stroke-width="3" />
              <text x="890" y="315" text-anchor="middle" fill="#bbf7d0" font-size="17" font-weight="600">数据绝对安全</text>
            </g>

            <!-- 漂浮粒子 -->
            <g fill="#fbbf24" opacity="0.6">
              <circle r="3">
                <animateMotion dur="6s" repeatCount="indefinite" path="M320 180 C 360 140, 430 150, 470 120" />
              </circle>
              <circle r="2.5">
                <animateMotion dur="7s" begin="2s" repeatCount="indefinite" path="M310 330 C 370 300, 420 340, 480 300" />
              </circle>
              <circle r="2">
                <animateMotion dur="5s" begin="4s" repeatCount="indefinite" path="M300 250 C 350 210, 400 260, 460 220" />
              </circle>
            </g>
          </svg>

          <div class="flex flex-wrap items-center justify-center gap-3 mt-6">
            <div class="px-4 py-2 bg-red-500/10 border border-red-500/30 rounded-full text-red-300 text-sm">攻击实时拦截</div>
            <div class="px-4 py-2 bg-cyan-500/10 border border-cyan-500/30 rounded-full text-cyan-300 text-sm">引擎自动运行</div>
            <div class="px-4 py-2 bg-green-500/10 border border-green-500/30 rounded-full text-green-300 text-sm">数据绝对安全</div>
          </div>
          <p class="text-white/40 text-xs text-center mt-4">示意图仅为防护概念演示，不包含任何技术细节</p>
        </div>
      </div>
    </section>

    <section class="relative z-10 py-16 px-6">
      <div class="max-w-4xl mx-auto">
        <h3 class="text-2xl font-bold text-white text-center mb-10">我们相信</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-8 border border-white/10 text-center hover:border-rose-400/40 hover:scale-105 transition-all">
            <div class="w-14 h-14 mx-auto bg-gradient-to-br from-rose-500 to-pink-500 rounded-xl flex items-center justify-center mb-4">
              <Heart class="w-7 h-7 text-white" />
            </div>
            <div class="text-white font-medium text-lg mb-2">用心做好产品</div>
            <div class="text-white/60">不搞花哨的功能，只做真正有用的事</div>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-8 border border-white/10 text-center hover:border-green-400/40 hover:scale-105 transition-all">
            <div class="w-14 h-14 mx-auto bg-gradient-to-br from-green-500 to-emerald-500 rounded-xl flex items-center justify-center mb-4">
              <ShieldCheck class="w-7 h-7 text-white" />
            </div>
            <div class="text-white font-medium text-lg mb-2">数据安全第一</div>
            <div class="text-white/60">您的数据属于您，永远不会被滥用</div>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-8 border border-white/10 text-center hover:border-blue-400/40 hover:scale-105 transition-all">
            <div class="w-14 h-14 mx-auto bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl flex items-center justify-center mb-4">
              <TrendingUp class="w-7 h-7 text-white" />
            </div>
            <div class="text-white font-medium text-lg mb-2">持续改进</div>
            <div class="text-white/60">倾听用户反馈，不断优化体验</div>
          </div>
        </div>
      </div>
    </section>

    <section id="journey" class="relative z-10 py-16 px-6">
      <div class="max-w-4xl mx-auto">
        <h3 class="text-2xl font-bold text-white text-center mb-10">我们的历程</h3>
        <div class="relative">
          <div class="absolute left-6 top-0 bottom-0 w-px bg-gradient-to-b from-transparent via-white/20 to-transparent"></div>
          <div class="space-y-8">
            <div class="flex items-start gap-6 relative">
              <div class="w-12 h-12 bg-gradient-to-br from-amber-500 to-orange-500 rounded-full flex items-center justify-center flex-shrink-0 z-10">
                <Sparkles class="w-6 h-6 text-white" />
              </div>
              <div class="bg-white/5 backdrop-blur-xl rounded-xl p-6 border border-white/10 flex-1 hover:border-white/30 transition-all">
                <div class="text-white font-semibold mb-1">2025 · 灵感诞生</div>
                <div class="text-white/60 text-sm">整理文件时萌生「做一个属于自己的存储云」的想法</div>
              </div>
            </div>
            <div class="flex items-start gap-6 relative">
              <div class="w-12 h-12 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-full flex items-center justify-center flex-shrink-0 z-10">
                <Rocket class="w-6 h-6 text-white" />
              </div>
              <div class="bg-white/5 backdrop-blur-xl rounded-xl p-6 border border-white/10 flex-1 hover:border-white/30 transition-all">
                <div class="text-white font-semibold mb-1">2025 · 第一版推出</div>
                <div class="text-white/60 text-sm">2025年5月13日，{{ SITE_NAME }}第一版正式推出</div>
              </div>
            </div>
            <div class="flex items-start gap-6 relative">
              <div class="w-12 h-12 bg-gradient-to-br from-purple-500 to-violet-500 rounded-full flex items-center justify-center flex-shrink-0 z-10">
                <ShieldCheck class="w-6 h-6 text-white" />
              </div>
              <div class="bg-white/5 backdrop-blur-xl rounded-xl p-6 border border-white/10 flex-1 hover:border-white/30 transition-all">
                <div class="text-white font-semibold mb-1">2026 · 从零重做</div>
                <div class="text-white/60 text-sm">2026年7月20日启动第二版研发，从零重写核心并自研铁壁安全引擎</div>
              </div>
            </div>
            <div class="flex items-start gap-6 relative">
              <div class="w-12 h-12 bg-gradient-to-br from-green-500 to-emerald-500 rounded-full flex items-center justify-center flex-shrink-0 z-10">
                <Heart class="w-6 h-6 text-white" />
              </div>
              <div class="bg-white/5 backdrop-blur-xl rounded-xl p-6 border border-white/10 flex-1 hover:border-white/30 transition-all">
                <div class="text-white font-semibold mb-1">今天 · 正式推出</div>
                <div class="text-white/60 text-sm">2026年9月5日，第二版完成研发并正式推出，开启全新篇章</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="relative z-10 py-16 px-6">
      <div class="max-w-4xl mx-auto">
        <h3 class="text-2xl font-bold text-white text-center mb-10">联系方式</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-6 border border-white/10 text-center hover:border-blue-400/40 hover:scale-105 transition-all">
            <div class="w-12 h-12 mx-auto bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl flex items-center justify-center mb-4">
              <Mail class="w-6 h-6 text-white" />
            </div>
            <div class="text-white font-medium mb-1">邮箱</div>
            <div class="text-white/60 text-sm">{{ CONTACT_EMAIL }}</div>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-6 border border-white/10 text-center hover:border-green-400/40 hover:scale-105 transition-all">
            <div class="w-12 h-12 mx-auto bg-gradient-to-br from-green-500 to-emerald-500 rounded-xl flex items-center justify-center mb-4">
              <Clock class="w-6 h-6 text-white" />
            </div>
            <div class="text-white font-medium mb-1">客服</div>
            <div class="text-white/60 text-sm">工作日 8:00-22:00</div>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-6 border border-white/10 text-center hover:border-purple-400/40 hover:scale-105 transition-all">
            <div class="w-12 h-12 mx-auto bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl flex items-center justify-center mb-4">
              <MessageSquare class="w-6 h-6 text-white" />
            </div>
            <div class="text-white font-medium mb-1">反馈</div>
            <div class="text-white/60 text-sm">欢迎提出建议</div>
          </div>
        </div>
      </div>
    </section>

    <footer class="relative z-10 py-12 px-6 bg-black/40 backdrop-blur-sm border-t border-white/10">
      <div class="max-w-6xl mx-auto">
        <div class="flex flex-col md:flex-row justify-between items-center gap-6">
          <div class="flex items-center gap-3">
            <AnimatedCloud size="small" />
            <div>
              <h4 class="text-xl font-bold text-white">{{ SITE_NAME }}</h4>
              <p class="text-white/50 text-sm">安全可靠的云端存储服务</p>
            </div>
          </div>
          
          <div class="flex items-center gap-6">
            <router-link to="/about" class="text-white/60 hover:text-white transition-colors">关于我们</router-link>
            <router-link to="/terms" class="text-white/60 hover:text-white transition-colors">服务条款</router-link>
            <router-link to="/privacy" class="text-white/60 hover:text-white transition-colors">隐私政策</router-link>
            <router-link to="/contact" class="text-white/60 hover:text-white transition-colors">联系我们</router-link>
          </div>
        </div>
        
        <div class="border-t border-white/10 mt-8 pt-8">
          <div class="flex flex-col items-center gap-4">
            <div v-if="STUDIO_NAME" class="studio-signature">
              <span class="studio-text">{{ STUDIO_NAME }}</span>
              <span class="studio-dot"></span>
              <span class="studio-tag">出品</span>
            </div>
            <p class="text-white/50">© 2026 {{ SITE_NAME }}. All rights reserved.</p>
          </div>
        </div>
      </div>
    </footer>
  </div>
</template>

<style scoped>
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

.about-badge {
  animation: badgeFloat 3s ease-in-out infinite;
}

.story-card {
  position: relative;
  overflow: hidden;
}

.story-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: linear-gradient(90deg, transparent, #f59e0b, #f97316, transparent);
}

.attacker {
  animation: attackerPulse 2s ease-in-out infinite;
  transform-box: fill-box;
  transform-origin: center;
}

@keyframes attackerPulse {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.08); }
}

.impact-dot {
  animation: impactBurst 1.2s ease-out infinite;
  transform-box: fill-box;
  transform-origin: center;
}

@keyframes impactBurst {
  0% { transform: scale(0.5); opacity: 1; }
  70% { transform: scale(2.4); opacity: 0; }
  100% { transform: scale(2.4); opacity: 0; }
}

.data-node {
  animation: dataPulse 2s ease-in-out infinite;
  transform-box: fill-box;
  transform-origin: center;
}

@keyframes dataPulse {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.05); }
}

.guard-label {
  animation: labelGlow 2.5s ease-in-out infinite;
}

@keyframes labelGlow {
  0%, 100% { opacity: 0.6; }
  50% { opacity: 1; }
}

.stat-card {
  animation: fadeUp 0.6s ease both;
}

.stat-card:nth-child(1) { animation-delay: 0s; }
.stat-card:nth-child(2) { animation-delay: 0.1s; }
.stat-card:nth-child(3) { animation-delay: 0.2s; }
.stat-card:nth-child(4) { animation-delay: 0.3s; }

@keyframes badgeFloat {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-6px); }
}

@keyframes fadeUp {
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 1; transform: translateY(0); }
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
