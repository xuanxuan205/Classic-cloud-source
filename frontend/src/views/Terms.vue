<script setup lang="ts">
import { SITE_NAME, STUDIO_NAME } from '@/config/site'
import { FileText, Clock, CheckCircle } from 'lucide-vue-next'
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
          <router-link to="/terms" class="px-4 py-2 bg-white/20 text-white rounded-lg hover:bg-white/30 transition-all backdrop-blur">服务条款</router-link>
          <router-link to="/privacy" class="px-4 py-2 text-white/80 hover:text-white transition-all">隐私政策</router-link>
          <router-link to="/contact" class="px-4 py-2 text-white/80 hover:text-white transition-all">联系我们</router-link>
          <router-link to="/login" class="px-4 py-2 text-white/80 hover:text-white transition-all">登录</router-link>
          <router-link to="/register" class="px-4 py-2 bg-white text-primary-600 rounded-lg hover:bg-white/90 transition-all font-medium">注册</router-link>
        </div>
      </div>
    </nav>

    <section class="relative z-10 pt-32 pb-16 px-6">
      <div class="max-w-4xl mx-auto text-center">
        <div class="inline-flex items-center justify-center w-20 h-20 bg-white/20 backdrop-blur rounded-2xl mb-8">
          <FileText class="w-10 h-10 text-white" />
        </div>
        <h2 class="text-5xl font-bold text-white mb-6">服务条款</h2>
        <p class="text-xl text-white/80 max-w-2xl mx-auto">
          请仔细阅读，本条款明确您使用{{ SITE_NAME }}服务的规则与双方责任
        </p>
      </div>
    </section>

    <section class="relative z-10 py-16 px-6">
      <div class="max-w-4xl mx-auto">
        <div class="bg-gradient-to-r from-green-500/10 via-blue-500/10 to-green-500/10 backdrop-blur-xl rounded-2xl p-8 border border-green-500/20 mb-12">
          <div class="flex items-center gap-4">
            <div class="w-16 h-16 bg-gradient-to-br from-green-500 to-emerald-500 rounded-xl flex items-center justify-center">
              <CheckCircle class="w-8 h-8 text-white" />
            </div>
            <div>
              <h3 class="text-2xl font-bold text-white mb-2">免费使用，无需会员</h3>
              <p class="text-white/70">我们的服务对所有人免费开放，新用户赠送300MB存储空间，没有会员制度，没有付费项目，普通人都能轻松使用。</p>
            </div>
          </div>
        </div>

        <div class="bg-white/5 backdrop-blur-xl rounded-2xl border border-white/10 overflow-hidden">
          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">1</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">服务概述</h3>
                <p class="text-white/70 leading-relaxed">
                  {{ SITE_NAME }}提供免费的云端存储、文件分享和数据备份服务。注册账号并使用即表示您已阅读、理解并同意本条款的全部内容。若您不同意本条款的任何内容，请停止注册和使用本服务。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-green-500 to-emerald-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">2</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">账号注册与安全</h3>
                <p class="text-white/70 leading-relaxed">
                  您需要提供有效的电子邮箱完成注册，并妥善保管账号密码。您对账号下的所有操作承担责任，请勿将账号出借、转让或共享给他人。如发现账号异常登录或被盗，请立即联系官方邮箱处理。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">3</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">免费服务与存储空间</h3>
                <p class="text-white/70 leading-relaxed">
                  本服务免费使用，不收取任何费用，也没有会员制度。新用户注册即赠送300MB存储空间，所有用户享受相同的功能和体验。若因运营需要调整存储空间政策，我们将提前公告通知。
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
                <h3 class="text-xl font-semibold text-white mb-3">用户责任与禁止行为</h3>
                <p class="text-white/70 leading-relaxed">
                  您承诺不利用本服务从事任何违法违规活动，包括但不限于：存储或传播违法内容；侵犯他人知识产权或隐私；上传病毒、木马等恶意程序；对服务进行攻击、扫描、爬取或干扰；冒用他人身份注册；绕过安全防护或探测系统漏洞。违反上述规定的，我们有权暂停或终止相关账号。
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
                <h3 class="text-xl font-semibold text-white mb-3">上传内容与版权</h3>
                <p class="text-white/70 leading-relaxed">
                  您上传的文件内容归您所有，我们不会查看或使用您的文件内容。您需保证上传的内容合法，并拥有相应的权利或授权。因您上传的内容引发的纠纷或损失，由您自行承担。
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
                <h3 class="text-xl font-semibold text-white mb-3">数据安全与备份</h3>
                <p class="text-white/70 leading-relaxed">
                  我们采用安全防护措施保护您的数据，并定期执行数据库与文件备份。尽管如此，任何存储服务都无法保证绝对不丢失数据，建议您对重要数据自行留存备份。因不可抗力、网络故障、硬件故障等原因造成的数据损失，我们将在能力范围内尽力协助恢复，但不承担赔偿责任。
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
                <h3 class="text-xl font-semibold text-white mb-3">服务变更、中断与终止</h3>
                <p class="text-white/70 leading-relaxed">
                  我们会持续改进服务，并可能新增、调整或下线部分功能。因系统维护、升级、网络故障或不可抗力等原因，服务可能出现中断。如您违反本条款或相关法律法规，我们有权在不事先通知的情况下暂停或终止您的账号。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8 border-b border-white/5">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-slate-500 to-gray-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">8</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">免责声明</h3>
                <p class="text-white/70 leading-relaxed">
                  本服务按"现状"提供，我们不对服务的可用性、准确性、可靠性作任何明示或暗示的保证。在法律允许的范围内，我们对因使用或无法使用本服务而产生的直接或间接损失不承担责任。
                </p>
              </div>
            </div>
          </div>

          <div class="p-8">
            <div class="flex items-start gap-4">
              <div class="w-10 h-10 bg-gradient-to-br from-emerald-500 to-green-500 rounded-lg flex items-center justify-center flex-shrink-0">
                <span class="text-white font-bold">9</span>
              </div>
              <div>
                <h3 class="text-xl font-semibold text-white mb-3">条款变更</h3>
                <p class="text-white/70 leading-relaxed">
                  我们可能适时更新本条款，更新后的条款将在本页面公布。继续使用本服务即视为接受更新后的条款。如您不同意变更，可以停止使用本服务。如您对本条款有任何疑问，请通过「联系我们」页面与我们沟通。
                </p>
              </div>
            </div>
          </div>
        </div>

        <div class="mt-10 bg-white/5 backdrop-blur-xl rounded-2xl p-8 border border-white/10">
          <div class="flex items-start gap-4">
            <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center flex-shrink-0">
              <Clock class="w-6 h-6 text-white" />
            </div>
            <div>
              <h3 class="text-xl font-semibold text-white mb-3">条款生效时间</h3>
              <p class="text-white/70">本条款自发布之日起生效，最后更新时间：2026年8月</p>
            </div>
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
