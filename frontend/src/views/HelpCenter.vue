<script setup lang="ts">
import { SITE_NAME, CONTACT_EMAIL, CONTACT_MAILTO, CONTACT_QQ_URL } from '@/config/site'
import { HelpCircle, Mail, Clock, ShieldCheck, CloudUpload, Trash2, RefreshCw, Zap, Users, MessageCircle } from 'lucide-vue-next'
import AnimatedCloud from '@/components/AnimatedCloud.vue'

const faqGroups = [
  {
    icon: CloudUpload,
    color: 'from-blue-500 to-cyan-500',
    title: '上传与传输',
    items: [
      { q: '什么是“秒传”？', a: '上传文件时，系统会先计算文件指纹。如果服务器上已有完全相同的文件，将直接为你登记文件，无需再次传输，几秒内完成“上传”。' },
      { q: '什么是“分片续传”？', a: '大文件会被切成 10MB 的分片逐个上传。网络中断或刷新页面后，已上传的分片会保留，重新上传同一文件时自动跳过已传分片，从断点继续。' },
      { q: '单文件最大支持多大？', a: '单文件最大支持 850MB。更大文件请压缩或拆分后上传。' },
      { q: '上传会做安全检查吗？', a: '会。铁壁安全引擎在上传时自动核对文件后缀与真实内容是否一致，并识别可执行程序、脚本与病毒特征——改名伪装、木马、Webshell 都会被拦截，官方管理员上传同样接受体检。' },
      { q: '上传失败怎么办？', a: '分片上传失败不会丢失已传进度，稍后重新选择同一文件即可继续；若多次失败，请检查网络后重试。' }
    ]
  },
  {
    icon: Trash2,
    color: 'from-amber-500 to-orange-500',
    title: '文件与回收站',
    items: [
      { q: '删除的文件能恢复吗？', a: '删除的文件会先进入回收站，你可以在回收站中随时恢复。' },
      { q: '回收站会自动清理吗？', a: '会。回收站中的文件默认保留 30 天，超过保留期将自动彻底删除，删除前系统会向你的注册邮箱发送清理清单，请留意查收。' },
      { q: '彻底删除的文件能找回吗？', a: '不能。彻底删除后文件与数据均无法恢复，请谨慎操作。' }
    ]
  },
  {
    icon: ShieldCheck,
    color: 'from-emerald-500 to-green-500',
    title: '账号安全',
    items: [
      { q: '什么是两步验证？', a: '两步验证（2FA）是一种额外的登录保护。开启后，登录时除了密码，还需输入验证器 App（如 Google Authenticator）中的 6 位动态验证码。' },
      { q: '如何开启两步验证？', a: '登录后进入「个人中心 → 安全中心 → 两步验证」，按提示用验证器 App 扫码绑定并输入动态码即可开启。' },
      { q: '收到“异地登录提醒”邮件怎么办？', a: '如果登录地点并非本人操作，请立即修改密码、开启两步验证，并在「安全中心 → 设备管理」中撤销陌生设备。' },
      { q: '忘记密码怎么办？', a: '在登录页点击「忘记密码」，通过注册邮箱获取验证码后即可重置密码。' }
    ]
  },
  {
    icon: Users,
    color: 'from-purple-500 to-violet-500',
    title: '分享与协作',
    items: [
      { q: '如何分享文件？', a: '在文件列表中点击文件右侧的分享按钮，可生成公开链接或带提取码的链接，并设置有效期。' },
      { q: '分享链接可以撤回吗？', a: '可以。在「分享管理」中随时关闭或删除分享，链接将立即失效。' }
    ]
  },
  {
    icon: Zap,
    color: 'from-cyan-500 to-sky-500',
    title: '存储与配额',
    items: [
      { q: '免费账号有多少空间？', a: '新用户注册即赠 300MB 免费空间，个人中心可查看当前用量与剩余空间。' },
      { q: '空间不够怎么办？', a: '可以清理回收站与不常用文件，或将大文件压缩后上传。' }
    ]
  },
  {
    icon: RefreshCw,
    color: 'from-rose-500 to-pink-500',
    title: '更新与反馈',
    items: [
      { q: '如何更新网站版本？', a: '官方发布新版本后，登录后在个人中心的「版本更新」中点击更新按钮，即可手动切换到新版本，更新日志可查看每个版本的改进内容。' },
      { q: '有问题或建议怎么反馈？', a: '登录后进入个人中心「意见反馈」，填写内容提交即可，官方会通过你预留的联系方式回复；也可直接联系官方 QQ 或邮箱。' }
    ]
  }
]
</script>

<template>
  <div class="min-h-screen relative overflow-hidden">
    <div class="fixed inset-0 z-0">
      <img src="/app-screenshot.png" alt="背景" class="w-full h-full object-cover" />
      <div class="absolute inset-0 bg-gradient-to-b from-black/60 via-black/40 to-black/70"></div>
    </div>

    <nav class="fixed top-0 left-0 right-0 bg-white/10 backdrop-blur-lg shadow-sm z-50 border-b border-white/20">
      <div class="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
        <router-link to="/" class="flex items-center gap-3">
          <AnimatedCloud size="small" />
          <h1 class="text-xl font-bold text-white">{{ SITE_NAME }}</h1>
        </router-link>
        <div class="flex items-center gap-4">
          <router-link to="/" class="px-4 py-2 text-white/80 hover:text-white transition-all">首页</router-link>
          <router-link to="/help" class="px-4 py-2 bg-white/20 text-white rounded-lg hover:bg-white/30 transition-all backdrop-blur">帮助中心</router-link>
          <router-link to="/about" class="px-4 py-2 text-white/80 hover:text-white transition-all">关于我们</router-link>
          <router-link to="/contact" class="px-4 py-2 text-white/80 hover:text-white transition-all">联系我们</router-link>
          <router-link to="/login" class="px-4 py-2 text-white/80 hover:text-white transition-all">登录</router-link>
          <router-link to="/register" class="px-4 py-2 bg-white text-primary-600 rounded-lg hover:bg-white/90 transition-all font-medium">注册</router-link>
        </div>
      </div>
    </nav>

    <section class="relative z-10 pt-32 pb-14 px-6">
      <div class="max-w-4xl mx-auto text-center">
        <div class="inline-flex items-center justify-center w-20 h-20 bg-white/20 backdrop-blur rounded-2xl mb-8">
          <HelpCircle class="w-10 h-10 text-white" />
        </div>
        <h2 class="text-5xl font-bold text-white mb-6">帮助中心</h2>
        <p class="text-xl text-white/80 max-w-2xl mx-auto">
          常见问题与使用指南，快速了解上传、分享、安全与存储功能
        </p>
      </div>
    </section>

    <section class="relative z-10 pb-16 px-6">
      <div class="max-w-5xl mx-auto space-y-8">
        <div v-for="(group, gi) in faqGroups" :key="gi" class="bg-white/5 backdrop-blur-xl rounded-2xl border border-white/10 overflow-hidden">
          <div class="px-6 sm:px-8 py-5 border-b border-white/10 flex items-center gap-4">
            <div :class="'w-11 h-11 rounded-xl bg-gradient-to-br flex items-center justify-center shrink-0 ' + group.color">
              <component :is="group.icon" class="w-5 h-5 text-white" />
            </div>
            <h3 class="text-white font-semibold text-lg sm:text-xl">{{ group.title }}</h3>
          </div>
          <div class="divide-y divide-white/5">
            <details v-for="(item, ii) in group.items" :key="ii" class="group px-6 sm:px-8">
              <summary class="py-4 cursor-pointer select-none flex items-start justify-between gap-4 text-white/90 hover:text-white transition-colors text-sm sm:text-base">
                <span>{{ item.q }}</span>
                <span class="text-white/40 group-open:rotate-90 transition-transform duration-200 mt-0.5">›</span>
              </summary>
              <p class="pb-4 text-white/60 text-sm leading-relaxed pl-0">{{ item.a }}</p>
            </details>
          </div>
        </div>

        <div class="bg-gradient-to-r from-blue-500/15 to-cyan-500/15 backdrop-blur-xl rounded-2xl border border-white/10 p-6 sm:p-8">
          <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-5">
            <div class="flex items-start gap-4">
              <div class="w-11 h-11 rounded-xl bg-white/15 flex items-center justify-center shrink-0">
                <MessageCircle class="w-5 h-5 text-white" />
              </div>
              <div>
                <h3 class="text-white font-semibold text-lg">还没有解决您的问题？</h3>
                <p class="text-white/60 text-sm mt-1">意见反馈、联系我们，官方会尽快为您处理</p>
              </div>
            </div>
            <div class="flex gap-3 w-full sm:w-auto">
              <router-link to="/contact" class="flex-1 sm:flex-none px-5 py-2.5 bg-white text-gray-900 rounded-lg hover:bg-white/90 transition-all font-medium text-sm text-center">联系我们</router-link>
              <router-link to="/login" class="flex-1 sm:flex-none px-5 py-2.5 bg-white/15 border border-white/20 text-white rounded-lg hover:bg-white/25 transition-all font-medium text-sm text-center">意见反馈</router-link>
            </div>
          </div>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div class="bg-white/5 backdrop-blur-xl rounded-xl border border-white/10 p-5 text-center">
            <Mail class="w-6 h-6 text-blue-300 mx-auto mb-3" />
            <p class="text-white/80 text-sm font-medium mb-1">官方邮箱</p>
            <a :href="CONTACT_MAILTO" class="text-white/50 text-sm hover:text-white transition-colors break-all">{{ CONTACT_EMAIL }}</a>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl border border-white/10 p-5 text-center">
            <MessageCircle class="w-6 h-6 text-green-300 mx-auto mb-3" />
            <p class="text-white/80 text-sm font-medium mb-1">官方 QQ</p>
            <a v-if="CONTACT_QQ_URL" :href="CONTACT_QQ_URL" target="_blank" rel="noopener" class="text-white/50 text-sm hover:text-white transition-colors break-all">点击加为 QQ 好友</a>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl border border-white/10 p-5 text-center">
            <Clock class="w-6 h-6 text-amber-300 mx-auto mb-3" />
            <p class="text-white/80 text-sm font-medium mb-1">响应时间</p>
            <p class="text-white/50 text-sm">一般 24 小时内回复</p>
          </div>
        </div>
      </div>
    </section>

    <footer class="relative z-10 py-10 px-6 bg-black/40 backdrop-blur-sm border-t border-white/10">
      <div class="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        <p class="text-white/50 text-sm">&copy; 2026 {{ SITE_NAME }} All rights reserved.</p>
        <div class="flex flex-wrap items-center gap-5">
          <router-link to="/about" class="text-white/60 hover:text-white text-sm transition-colors">关于我们</router-link>
          <router-link to="/terms" class="text-white/60 hover:text-white text-sm transition-colors">服务条款</router-link>
          <router-link to="/privacy" class="text-white/60 hover:text-white text-sm transition-colors">隐私政策</router-link>
          <router-link to="/contact" class="text-white/60 hover:text-white text-sm transition-colors">联系我们</router-link>
        </div>
      </div>
    </footer>
  </div>
</template>
