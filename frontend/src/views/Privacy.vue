<script setup lang="ts">
import { SITE_NAME, CONTACT_EMAIL, STUDIO_NAME } from '@/config/site'
import { Lock, Shield, CheckCircle } from 'lucide-vue-next'
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
          <router-link to="/privacy" class="px-4 py-2 bg-white/20 text-white rounded-lg hover:bg-white/30 transition-all backdrop-blur">隐私政策</router-link>
          <router-link to="/contact" class="px-4 py-2 text-white/80 hover:text-white transition-all">联系我们</router-link>
          <router-link to="/login" class="px-4 py-2 text-white/80 hover:text-white transition-all">登录</router-link>
          <router-link to="/register" class="px-4 py-2 bg-white text-primary-600 rounded-lg hover:bg-white/90 transition-all font-medium">注册</router-link>
        </div>
      </div>
    </nav>

    <section class="relative z-10 pt-32 pb-16 px-6">
      <div class="max-w-4xl mx-auto text-center">
        <div class="inline-flex items-center justify-center w-20 h-20 bg-white/20 backdrop-blur rounded-2xl mb-8">
          <Lock class="w-10 h-10 text-white" />
        </div>
        <h2 class="text-5xl font-bold text-white mb-6">隐私政策</h2>
        <p class="text-xl text-white/80 max-w-2xl mx-auto">
          我们如何收集、使用和保护您的个人信息
        </p>
      </div>
    </section>

    <section class="relative z-10 py-16 px-6">
      <div class="max-w-4xl mx-auto">
        <div class="bg-gradient-to-r from-purple-500/10 via-blue-500/10 to-purple-500/10 backdrop-blur-xl rounded-2xl p-8 border border-purple-500/20 mb-12">
          <div class="flex items-center gap-4">
            <div class="w-16 h-16 bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl flex items-center justify-center">
              <Shield class="w-8 h-8 text-white" />
            </div>
            <div>
              <h3 class="text-2xl font-bold text-white mb-2">您的数据属于您</h3>
              <p class="text-white/70">我们不会出售、共享或滥用您的任何数据。您的数据安全是我们最重要的责任。</p>
            </div>
          </div>
        </div>

        <div class="bg-white/5 backdrop-blur-xl rounded-2xl border border-white/10 overflow-hidden">
          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">1</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">我们收集的信息</h3>
                <p class="text-white/70 leading-relaxed">
                  我们只收集必要的信息：您的电子邮箱（用于注册、登录、找回密码和接收通知），以及使用服务时的基本日志（如登录时间、IP地址、操作记录）。我们不会读取或扫描您存储的文件内容。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">2</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">信息如何使用</h3>
                <p class="text-white/70 leading-relaxed">
                  您的信息仅用于：提供存储和分享服务、保障账号安全、验证身份、处理反馈与申诉、改进产品体验。我们不会将您的信息用于任何与提供服务无关的目的。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-green-500 to-emerald-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">3</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">信息如何保护</h3>
                <p class="text-white/70 leading-relaxed">
                  我们采取传输加密、访问控制、防火墙、入侵检测等多层安全措施保护您的信息，并定期备份数据。密码等敏感信息以不可逆方式加密存储，我们无法查看您的原始密码。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-orange-500 to-amber-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">4</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">信息共享与披露</h3>
                <p class="text-white/70 leading-relaxed">
                  我们不会向任何第三方出售、出租或共享您的个人信息和文件内容。仅在法律法规要求、司法机关依法调取，或为保护用户人身财产安全所必需的情况下，我们才会依法配合披露必要信息。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-pink-500 to-rose-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">5</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">数据保留与删除</h3>
                <p class="text-white/70 leading-relaxed">
                  我们仅在提供服务所必需的期限内保留您的信息。您可以随时在个人后台删除文件和账号数据；注销账号后，我们将按合理期限清理相关数据，法律法规另有要求的除外。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-indigo-500 to-blue-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">6</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">Cookie 与本地存储</h3>
                <p class="text-white/70 leading-relaxed">
                  我们使用必要的 Cookie 和浏览器本地存储来维持登录状态、记住您的偏好设置。这些数据仅用于提升使用体验，不会用于追踪您的浏览行为或投放广告。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-cyan-500 to-teal-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">7</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">您的权利与控制权</h3>
                <p class="text-white/70 leading-relaxed">
                  您有权访问、更正、删除自己的个人信息，有权随时停止使用服务。您可以在个人后台管理自己的资料和数据；如有其他需求，请通过「联系我们」页面与我们联系。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-emerald-500 to-green-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">8</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">未成年人保护</h3>
                <p class="text-white/70 leading-relaxed">
                  我们不面向未成年人主动收集个人信息。未成年人在使用本服务前，应在监护人指导下阅读本政策并征得监护人同意。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-slate-500 to-gray-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">9</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">政策更新</h3>
                <p class="text-white/70 leading-relaxed">
                  我们可能适时更新本隐私政策，更新后的内容将在本页面公布。重大变更我们会通过站内公告或邮件等方式提示。本政策最后更新时间为2026年8月。
                </p>
              </div>
            </div>
          </div>
        </div>

        <div class="mt-10 bg-gradient-to-r from-green-500/10 via-blue-500/10 to-green-500/10 backdrop-blur-xl rounded-2xl p-8 border border-green-500/20">
          <div class="flex items-center gap-4 mb-4">
            <div class="w-10 h-10 bg-gradient-to-br from-green-500 to-emerald-500 rounded-lg flex items-center justify-center">
              <Shield class="w-6 h-6 text-white" />
            </div>
            <h3 class="text-xl font-semibold text-white">我们的承诺</h3>
          </div>
          <ul class="text-white/70 space-y-3">
            <li class="flex items-center gap-3">
              <CheckCircle class="w-5 h-5 text-green-400 flex-shrink-0" />
              <span>不会出售您的任何个人数据</span>
            </li>
            <li class="flex items-center gap-3">
              <CheckCircle class="w-5 h-5 text-green-400 flex-shrink-0" />
              <span>不会用于广告或营销目的</span>
            </li>
            <li class="flex items-center gap-3">
              <CheckCircle class="w-5 h-5 text-green-400 flex-shrink-0" />
              <span>不会与第三方共享您的文件内容</span>
            </li>
            <li class="flex items-center gap-3">
              <CheckCircle class="w-5 h-5 text-green-400 flex-shrink-0" />
              <span>您可以随时控制和删除自己的数据</span>
            </li>
          </ul>
        </div>

        <div class="mt-10 bg-white/5 backdrop-blur-xl rounded-2xl p-8 border border-white/10">
          <h3 class="text-xl font-semibold text-white mb-4">有疑问？联系我们</h3>
          <div class="text-white/60 text-sm space-y-2">
            <p>如对本隐私政策有任何疑问，请访问「联系我们」页面或发送邮件咨询。</p>
            <p>邮箱：{{ CONTACT_EMAIL }}</p>
            <p>客服时间：工作日 8:00-22:00</p>
          </div>
          <router-link to="/contact" class="inline-flex items-center gap-2 mt-6 px-6 py-3 bg-white text-primary-600 rounded-lg hover:bg-white/90 transition-all font-medium">
            前往联系我们
          </router-link>
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
