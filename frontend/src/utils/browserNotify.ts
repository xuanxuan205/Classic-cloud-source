/**
 * IronWall v1.47.10: 浏览器通知落地工具。
 *
 * 旧实现里“浏览器通知”开关只是改了个布尔值：既不申请 Notification 权限，
 * 权限被拒也照常显示开启，全站没有任何一处真正推送过消息。
 * 这里统一收口权限申请、本地镜像与推送入口。
 */

const ENABLED_KEY = 'jdy_browser_notify_enabled'

export function browserNotifySupported(): boolean {
  return typeof window !== 'undefined' && 'Notification' in window
}

export function browserNotifyPermission(): NotificationPermission | 'unsupported' {
  return browserNotifySupported() ? Notification.permission : 'unsupported'
}

/** 本地镜像，供列表页/仪表盘在未拉取设置时判断是否推送 */
export function setBrowserNotifyEnabledLocal(enabled: boolean): void {
  try {
    localStorage.setItem(ENABLED_KEY, enabled ? '1' : '0')
  } catch {
    // 隐私模式下 localStorage 不可用，忽略即可
  }
}

export function isBrowserNotifyEnabledLocal(): boolean {
  try {
    return localStorage.getItem(ENABLED_KEY) === '1'
  } catch {
    return false
  }
}

/**
 * 开启浏览器通知：必要时申请权限。
 * @returns 是否真正可用（不支持或用户拒绝返回 false）
 */
export async function enableBrowserNotify(): Promise<boolean> {
  if (!browserNotifySupported()) return false
  if (Notification.permission === 'granted') return true
  if (Notification.permission === 'denied') return false
  try {
    const result = await Notification.requestPermission()
    return result === 'granted'
  } catch {
    return false
  }
}

/** 按偏好推送一条浏览器通知；未开启、未授权或不支持时静默跳过 */
export function showBrowserNotify(title: string, body?: string): void {
  if (!isBrowserNotifyEnabledLocal()) return
  if (!browserNotifySupported() || Notification.permission !== 'granted') return
  try {
    const notice = new Notification(title, { body: body || '', icon: '/favicon.ico' })
    setTimeout(() => {
      try {
        notice.close()
      } catch {
        // 关闭失败无需处理
      }
    }, 8000)
  } catch {
    // 部分浏览器要求 ServiceWorker 才允许构造，失败时静默降级
  }
}
