<script setup lang="ts">
// IronWall v1.45: 全站统一反馈层（站内 toast + 确认弹窗），替代浏览器原生 alert/confirm
import { toast, confirmState, resolveConfirm } from '@/composables/useGlobalFeedback'
import { CheckCircle, XCircle, Info, AlertTriangle } from 'lucide-vue-next'
</script>

<template>
  <Teleport to="body">
    <!-- Toast -->
    <Transition name="feedback-toast">
      <div v-if="toast.show"
        :class="['fixed top-6 left-1/2 -translate-x-1/2 z-[200] px-5 py-3 rounded-xl shadow-2xl text-sm font-medium flex items-center gap-2.5 min-w-[240px] max-w-[90vw] justify-center backdrop-blur-md',
          toast.type === 'success' ? 'bg-emerald-500/95 text-white' : '',
          toast.type === 'error' ? 'bg-red-500/95 text-white' : '',
          toast.type === 'info' ? 'bg-indigo-500/95 text-white' : '']">
        <CheckCircle v-if="toast.type === 'success'" class="w-5 h-5 shrink-0" />
        <XCircle v-else-if="toast.type === 'error'" class="w-5 h-5 shrink-0" />
        <Info v-else class="w-5 h-5 shrink-0" />
        <span class="break-all">{{ toast.message }}</span>
      </div>
    </Transition>

    <!-- Confirm Dialog -->
    <Transition name="feedback-modal">
      <div v-if="confirmState.show"
        class="fixed inset-0 z-[200] flex items-center justify-center bg-black/60 p-4"
        @click.self="resolveConfirm(false)">
        <div class="bg-slate-800 rounded-2xl w-full max-w-md border border-slate-700/50 shadow-2xl p-6">
          <div class="flex items-start gap-4">
            <div :class="confirmState.danger ? 'bg-red-500/15' : 'bg-indigo-500/15'"
              class="w-11 h-11 rounded-full flex items-center justify-center shrink-0">
              <AlertTriangle :class="confirmState.danger ? 'text-red-400' : 'text-indigo-400'" class="w-6 h-6" />
            </div>
            <div class="flex-1 min-w-0">
              <h3 class="text-white font-bold text-base">{{ confirmState.title }}</h3>
              <p class="text-slate-400 text-sm mt-1.5 leading-relaxed whitespace-pre-wrap break-words">{{ confirmState.message }}</p>
            </div>
          </div>
          <div class="flex gap-3 mt-6">
            <button @click="resolveConfirm(false)"
              class="flex-1 px-4 py-2.5 bg-slate-700/50 text-slate-300 rounded-lg hover:bg-slate-700 transition-all text-sm">取消</button>
            <button @click="resolveConfirm(true)"
              :class="confirmState.danger ? 'bg-red-600 hover:bg-red-500' : 'bg-indigo-600 hover:bg-indigo-700'"
              class="flex-1 px-4 py-2.5 text-white rounded-lg transition-all text-sm font-medium">{{ confirmState.confirmText }}</button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.feedback-toast-enter-active,
.feedback-toast-leave-active {
  transition: all 0.25s ease;
}
.feedback-toast-enter-from,
.feedback-toast-leave-to {
  opacity: 0;
  transform: translate(-50%, -12px);
}
.feedback-modal-enter-active,
.feedback-modal-leave-active {
  transition: opacity 0.2s ease;
}
.feedback-modal-enter-from,
.feedback-modal-leave-to {
  opacity: 0;
}
</style>