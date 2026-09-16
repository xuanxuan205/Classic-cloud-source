/**
 * IronWall v1.19.0: 全局封禁守卫。
 *
 * 问题背景：SPA 静态页面由 nginx 直接返回，登录页/首页加载时没有任何 API 请求，
 * 仅靠 axios 拦截器跳转专属警示页——被封禁的 IP 依然能浏览其他页面且看不到专属页。
 *
 * 方案：页面加载即探测一次 /api/blocked-page/status，之后每 10 秒轮询；
 * 后端对"已封禁且匿名"的来源返回 403 + X-IronWall-Blocked 头，前端立即整页跳转
 * /api/blocked-page 专属警示页。登录态用户按 语义不受影响。
 */
let started = false
let timer: number | undefined

export function isOnBlockedPage(): boolean {
  return window.location.pathname === '/api/blocked-page'
}

export async function checkBlocked(): Promise<boolean> {
  try {
    const resp = await fetch('/api/blocked-page/status', {
      method: 'GET',
      cache: 'no-store',
      headers: { Accept: 'application/json' },
    })
    if (resp.headers.get('x-ironwall-blocked') === 'true') {
      return true
    }
    try {
      const data = await resp.json()
      if (data && data.blocked === true) {
        return true
      }
    } catch {
      // 非 JSON 响应按未封禁处理
    }
    return false
  } catch {
    return false
  }
}

export function startBlockedGuard(intervalMs = 10000): void {
  if (started || typeof window === 'undefined') return
  started = true

  const tick = async () => {
    if (isOnBlockedPage()) return
    if (await checkBlocked()) {
      window.location.replace('/api/blocked-page')
    }
  }

  void tick()
  timer = window.setInterval(() => {
    void tick()
  }, intervalMs)
}

export function stopBlockedGuard(): void {
  if (timer !== undefined) {
    window.clearInterval(timer)
    timer = undefined
  }
  started = false
}