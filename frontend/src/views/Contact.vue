<script setup lang="ts">
import { SITE_NAME, CONTACT_EMAIL, CONTACT_MAILTO, CONTACT_QQ_URL, STUDIO_NAME } from '@/config/site'
import { Mail, Clock, MessageSquare, HelpCircle, CheckCircle, Send, MessageCircle } from 'lucide-vue-next'
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
          <router-link to="/about" class="px-4 py-2 text-white/80 hover:text-white transition-all">关于我们</router-link>
          <router-link to="/terms" class="px-4 py-2 text-white/80 hover:text-white transition-all">服务条款</router-link>
          <router-link to="/privacy" class="px-4 py-2 text-white/80 hover:text-white transition-all">隐私政策</router-link>
          <router-link to="/contact" class="px-4 py-2 bg-white/20 text-white rounded-lg hover:bg-white/30 transition-all backdrop-blur">联系我们</router-link>
          <router-link to="/login" class="px-4 py-2 text-white/80 hover:text-white transition-all">登录</router-link>
          <router-link to="/register" class="px-4 py-2 bg-white text-primary-600 rounded-lg hover:bg-white/90 transition-all font-medium">注册</router-link>
        </div>
      </div>
    </nav>

    <section class="relative z-10 pt-32 pb-16 px-6">
      <div class="max-w-4xl mx-auto text-center">
        <div class="inline-flex items-center justify-center w-20 h-20 bg-white/20 backdrop-blur rounded-2xl mb-8">
          <MessageSquare class="w-10 h-10 text-white" />
        </div>
        <h2 class="text-5xl font-bold text-white mb-6">联系我们</h2>
        <p class="text-xl text-white/80 max-w-2xl mx-auto">
          有问题？我们随时在线，期待听到您的声音
        </p>
      </div>
    </section>

    <section class="relative z-10 py-16 px-6">
      <div class="max-w-4xl mx-auto">
        <h3 class="text-2xl font-bold text-white text-center mb-10">联系方式</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-8 border border-white/10 text-center">
            <div class="w-14 h-14 mx-auto bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl flex items-center justify-center mb-4">
              <Mail class="w-7 h-7 text-white" />
            </div>
            <div class="text-white font-medium text-lg mb-2">官方邮箱</div>
            <a :href="CONTACT_MAILTO" class="text-white/70 hover:text-white transition-colors break-all">
              {{ CONTACT_EMAIL }}
            </a>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-8 border border-white/10 text-center">
            <div class="w-14 h-14 mx-auto bg-gradient-to-br from-green-500 to-emerald-500 rounded-xl flex items-center justify-center mb-4">
              <Clock class="w-7 h-7 text-white" />
            </div>
            <div class="text-white font-medium text-lg mb-2">客服时间</div>
            <div class="text-white/70">工作日 8:00-22:00</div>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-8 border border-white/10 text-center">
            <div class="w-14 h-14 mx-auto bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl flex items-center justify-center mb-4">
              <Send class="w-7 h-7 text-white" />
            </div>
            <div class="text-white font-medium text-lg mb-2">意见反馈</div>
            <div class="text-white/70">登录后在个人后台提交</div>
          </div>
        </div>
      </div>
    </section>

    <section class="relative z-10 py-16 px-6">
      <div class="max-w-4xl mx-auto">
        <div class="bg-white/5 backdrop-blur-xl rounded-2xl p-12 border border-white/10">
          <h3 class="text-2xl font-bold text-white mb-8 text-center">意见反馈指南</h3>
          <div class="space-y-6">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">1</span>
              </div>
              <div>
                <h4 class="text-lg font-semibold text-white mb-2">登录您的账号</h4>
                <p class="text-white/70 leading-relaxed">
                  登录后进入个人后台，在侧边栏找到「意见反馈」入口。为了保护您的隐私并方便我们跟进处理，意见反馈功能仅对登录用户开放。
                </p>
              </div>
            </div>
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-green-500 to-emerald-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">2</span>
              </div>
              <div>
                <h4 class="text-lg font-semibold text-white mb-2">选择问题类型</h4>
                <p class="text-white/70 leading-relaxed">
                  选择您遇到的问题类型，例如登录问题、文件上传失败、忘记密码等，方便我们快速定位并处理。
                </p>
              </div>
            </div>
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">3</span>
              </div>
              <div>
                <h4 class="text-lg font-semibold text-white mb-2">填写详细描述</h4>
                <p class="text-white/70 leading-relaxed">
                  尽量描述问题发生的具体时间、操作步骤和现象，并留下有效的联系方式，我们会尽快通过邮箱与您联系。
                </p>
              </div>
            </div>
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-orange-500 to-amber-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">4</span>
              </div>
              <div>
                <h4 class="text-lg font-semibold text-white mb-2">提交反馈</h4>
                <p class="text-white/70 leading-relaxed">
                  提交后，反馈内容会直接发送到官方管理员邮箱，我们会在客服时间内尽快回复您。
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="relative z-10 py-16 px-6">
      <div class="max-w-4xl mx-auto">
        <h3 class="text-2xl font-bold text-white text-center mb-10">常见问题</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-8 border border-white/10">
            <div class="flex items-center gap-3 mb-4">
              <HelpCircle class="w-6 h-6 text-blue-400 flex-shrink-0" />
              <h4 class="text-lg font-semibold text-white">无法正常登录怎么办？</h4>
            </div>
            <p class="text-white/70 leading-relaxed">
              请先确认账号和密码输入正确，注意区分大小写。如忘记密码，可使用注册邮箱通过「找回密码」功能重置。
            </p>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-8 border border-white/10">
            <div class="flex items-center gap-3 mb-4">
              <HelpCircle class="w-6 h-6 text-green-400 flex-shrink-0" />
              <h4 class="text-lg font-semibold text-white">文件上传失败？</h4>
            </div>
            <p class="text-white/70 leading-relaxed">
              请检查网络连接和存储空间是否充足，并确认文件大小未超过单个文件限制。仍有问题请通过意见反馈联系我们。
            </p>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-8 border border-white/10">
            <div class="flex items-center gap-3 mb-4">
              <HelpCircle class="w-6 h-6 text-purple-400 flex-shrink-0" />
              <h4 class="text-lg font-semibold text-white">收不到验证码邮件？</h4>
            </div>
            <p class="text-white/70 leading-relaxed">
              请检查垃圾邮件文件夹，或稍等几分钟后重新获取。验证码有效期为10分钟，请勿将验证码告知他人。
            </p>
          </div>
          <div class="bg-white/5 backdrop-blur-xl rounded-xl p-8 border border-white/10">
            <div class="flex items-center gap-3 mb-4">
              <HelpCircle class="w-6 h-6 text-orange-400 flex-shrink-0" />
              <h4 class="text-lg font-semibold text-white">账号被误封怎么办？</h4>
            </div>
            <p class="text-white/70 leading-relaxed">
              如果您认为账号被误封，可以在拦截页面使用「人工申诉」通道提交申诉，管理员审核后会尽快处理。
            </p>
          </div>
        </div>
      </div>
    </section>

    <section class="relative z-10 py-16 px-6">
      <div class="max-w-4xl mx-auto">
        <div class="bg-gradient-to-r from-blue-500/10 via-purple-500/10 to-blue-500/10 backdrop-blur-xl rounded-2xl p-10 border border-blue-500/20 text-center">
          <div class="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-2xl mb-6">
            <MessageCircle class="w-8 h-8 text-white" />
          </div>
          <h3 class="text-2xl font-bold text-white mb-4">官方QQ</h3>
          <p class="text-white/70 max-w-xl mx-auto mb-6 leading-relaxed">
            未注册用户、安全报告、合作咨询等事宜，可点击下方链接添加官方QQ好友，请备注来意，我们会尽快回复。
          </p>
          <a v-if="CONTACT_QQ_URL" :href="CONTACT_QQ_URL" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-2 px-6 py-3 bg-white text-primary-600 rounded-lg hover:bg-white/90 transition-all font-medium">
            <MessageCircle class="w-5 h-5" />
            点击链接加我为QQ好友
          </a>
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
