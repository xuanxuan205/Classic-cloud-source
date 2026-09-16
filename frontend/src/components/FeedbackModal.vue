<script setup lang="ts">
import { R_FEEDBACK } from '@/utils/routeCodes'

import { ref, watch } from 'vue'
import { request } from '@/utils/axios'
import { X, MessageSquare, Send, CheckCircle2, Lightbulb } from 'lucide-vue-next'

const props = defineProps({ modelValue: { type: Boolean, default: false } })
const emit = defineEmits(['update:modelValue'])

const contact = ref('')
const content = ref('')
const submitting = ref(false)
const message = ref('')
const success = ref(false)
const selectedTopic = ref('')

const topics = [
  { label: '上传失败', template: '【上传失败】我在上传文件时遇到问题：' },
  { label: '下载缓慢', template: '【下载缓慢】下载速度很慢，具体情况是：' },
  { label: '登录问题', template: '【登录问题】我无法正常登录，具体现象是：' },
  { label: '文件丢失', template: '【文件丢失】我的文件不见了，具体情况是：' },
  { label: '分享异常', template: '【分享异常】分享链接使用时出现问题：' },
  { label: '功能建议', template: '【功能建议】我希望增加以下功能：' },
  { label: '安全相关', template: '【安全相关】我遇到的安全问题或建议：' },
  { label: '其他问题', template: '【其他问题】' }
]

function close() { emit('update:modelValue', false) }

watch(() => props.modelValue, (v) => {
  if (v) {
    message.value = ''
    success.value = false
    selectedTopic.value = ''
  }
})

function pickTopic(t: { label: string; template: string }) {
  selectedTopic.value = t.label
  const prefix = t.template
  if (!content.value.trim()) {
    content.value = prefix
  } else if (!content.value.includes(prefix)) {
    content.value = prefix + '\n' + content.value
  }
}

async function submit() {
  if (content.value.trim().length < 5) {
    message.value = '请至少输入 5 个字。'
    return
  }
  submitting.value = true
  message.value = ''
  try {
    const res = await request<any>({ url: R_FEEDBACK, method: 'POST', data: { contact: contact.value, content: content.value } })
    if (res && res.success) {
      success.value = true
      message.value = '反馈已提交，官方会通过邮箱收到您的意见，感谢支持！'
      content.value = ''
      contact.value = ''
      selectedTopic.value = ''
    } else {
      message.value = (res && res.message) || '提交失败，请稍后再试。'
    }
  } catch {
    message.value = '网络异常，请稍后再试。'
  }
  submitting.value = false
}
</script>

<template>
  <div v-if="modelValue" class="fixed inset-0 z-[100] flex items-center justify-center p-4">
    <div class="absolute inset-0 bg-black/70 backdrop-blur-sm" @click="close"></div>
    <div class="relative w-full max-w-xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl max-h-[88vh] flex flex-col overflow-hidden">
      <div class="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
            <MessageSquare class="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <h2 class="text-lg font-semibold text-white">意见反馈</h2>
            <p class="text-xs text-slate-500">您的意见将直接发送到官方管理员邮箱</p>
          </div>
        </div>
        <button @click="close" class="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-all">
          <X class="w-5 h-5" />
        </button>
      </div>

      <div class="flex-1 overflow-y-auto px-6 py-5 space-y-4">
        <div>
          <label class="flex items-center gap-1.5 text-sm font-medium text-slate-300 mb-2">
            <Lightbulb class="w-4 h-4 text-amber-400" />常见问题（点击自动填入）
          </label>
          <div class="flex flex-wrap gap-2">
            <button v-for="t in topics" :key="t.label" type="button" @click="pickTopic(t)"
              :class="['px-3 py-1.5 rounded-lg text-xs border transition-colors', selectedTopic === t.label ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300' : 'bg-slate-800/60 border-slate-700/50 text-slate-400 hover:text-white hover:border-slate-600']">
              {{ t.label }}
            </button>
          </div>
        </div>

        <div>
          <label class="block text-sm font-medium text-slate-300 mb-2">联系方式（邮箱/电话，选填）</label>
          <input v-model="contact" maxlength="64" placeholder="方便我们回复您"
            class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700/50 rounded-xl text-white placeholder-slate-500 focus:ring-2 focus:ring-emerald-500/50 outline-none text-sm" />
        </div>

        <div>
          <label class="block text-sm font-medium text-slate-300 mb-2">反馈内容</label>
          <textarea v-model="content" maxlength="1000" rows="6" placeholder="请描述您遇到的问题或建议（至少 5 个字）"
            class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700/50 rounded-xl text-white placeholder-slate-500 focus:ring-2 focus:ring-emerald-500/50 outline-none text-sm resize-y min-h-32"></textarea>
          <p class="text-right text-xs text-slate-600 mt-1">{{ content.length }}/1000</p>
        </div>

        <div v-if="message" :class="['text-sm rounded-lg px-3 py-2 flex items-start gap-2', success ? 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/20' : 'text-amber-400 bg-amber-500/10 border border-amber-500/20']">
          <CheckCircle2 v-if="success" class="w-4 h-4 shrink-0 mt-0.5" />
          <span>{{ message }}</span>
        </div>

        <button :disabled="submitting" @click="submit"
          class="w-full flex items-center justify-center gap-2 px-4 py-3 bg-gradient-to-r from-emerald-500 to-teal-600 text-white text-sm font-semibold rounded-xl hover:opacity-90 disabled:opacity-50 transition-all">
          <Send class="w-4 h-4" />
          {{ submitting ? '提交中…' : '提交反馈' }}
        </button>
      </div>
    </div>
  </div>
</template>
