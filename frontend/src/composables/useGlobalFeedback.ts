// IronWall v1.45: 全站统一反馈层——替代浏览器原生 alert/confirm
import { reactive } from 'vue'

export type FeedbackToastType = 'success' | 'error' | 'info'

export interface ToastState {
  show: boolean
  message: string
  type: FeedbackToastType
}

export interface ConfirmState {
  show: boolean
  title: string
  message: string
  confirmText: string
  danger: boolean
  resolve: ((value: boolean) => void) | null
}

export const toast = reactive<ToastState>({ show: false, message: '', type: 'info' })

export const confirmState = reactive<ConfirmState>({
  show: false,
  title: '确认操作',
  message: '',
  confirmText: '确认',
  danger: true,
  resolve: null
})

let toastTimer: ReturnType<typeof setTimeout> | null = null

export function showToast(message: string, type: FeedbackToastType = 'info'): void {
  if (toastTimer) clearTimeout(toastTimer)
  toast.show = true
  toast.message = message
  toast.type = type
  toastTimer = setTimeout(() => { toast.show = false }, 3000)
}

export function confirmDialog(
  message: string,
  options?: { title?: string; confirmText?: string; danger?: boolean }
): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    // 已有未决确认时兜底关闭，避免旧 Promise 永远悬挂
    if (confirmState.show && confirmState.resolve) {
      confirmState.resolve(false)
    }
    confirmState.title = options?.title ?? '确认操作'
    confirmState.message = message
    confirmState.confirmText = options?.confirmText ?? '确认'
    confirmState.danger = options?.danger ?? true
    confirmState.resolve = resolve
    confirmState.show = true
  })
}

export function resolveConfirm(result: boolean): void {
  confirmState.show = false
  confirmState.resolve?.(result)
  confirmState.resolve = null
}