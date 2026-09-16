import axios, { type AxiosInstance, type AxiosRequestConfig, type AxiosResponse } from 'axios'
import { useAuthStore } from '@/stores/auth'
import { getDeviceFingerprint } from './deviceFingerprint'
import {
  completeCrawlerChallenge,
  warmUpCrawlerChallenge,
  forceRebootstrap,
  resolveCanonical,
  sha256Text,
  signRequest
} from './apiCrypto'
import { R_AUTH_LOGIN } from './routeCodes'

export { warmUpCrawlerChallenge }

const API_BASE = '/api'

const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
})

// Convert camelCase keys to snake_case for backend Jackson SNAKE_CASE compatibility
function toSnakeCase(obj: any): any {
  if (obj === null || obj === undefined) return obj
  if (Array.isArray(obj)) return obj.map(toSnakeCase)
  if (obj instanceof FormData || obj instanceof URLSearchParams) return obj
  if (typeof obj === 'object' && obj.constructor === Object) {
    const result: Record<string, any> = {}
    for (const key of Object.keys(obj)) {
      const snakeKey = key.replace(/([A-Z])/g, '_$1').toLowerCase()
      result[snakeKey] = toSnakeCase(obj[key])
    }
    return result
  }
  return obj
}

function getCookie(name: string): string | null {
  try {
    const match = document.cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'))
    return match ? decodeURIComponent(match[1]) : null
  } catch {
    return null
  }
}

let fpSigWarmUp: Promise<void> | null = null

// IronWall v1.29.0: 指纹绑定签名预热——改用签名客户端请求，加密层下同样生效
export async function warmUpFingerprintSignature(): Promise<void> {
  if (!fpSigWarmUp) {
    fpSigWarmUp = (async () => {
      if (typeof window === 'undefined') return
      if ((window as any).__iw_sig_tried) return
      ;(window as any).__iw_sig_tried = true
      const did = getCookie('iw_did')
      if (!did || getCookie('iw_fp_sig')) return
      try {
        const fp = await getDeviceFingerprint()
        const body = JSON.stringify({ username: null, password: null })
        const bodyHash = await sha256Text(body)
        const canonical = await resolveCanonical(R_AUTH_LOGIN.slice(1))
        if (!canonical) return
        const signed = await signRequest('POST', canonical, R_AUTH_LOGIN.slice(1), '', bodyHash)
        await fetch('/api/' + signed.url, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-IronWall-FP': fp,
            'X-Requested-With': 'XMLHttpRequest',
            ...signed.headers
          },
          body
        })
      } catch {
        // 预热失败不影响业务请求，指纹仍可通过后续正常请求完成绑定
      }
    })()
  }
  return fpSigWarmUp
}

apiClient.interceptors.request.use(async (config) => {
  // Auto-convert camelCase request body to snake_case for SNAKE_CASE backend
  if (config.data && typeof config.data === 'object' && !(config.data instanceof FormData)) {
    try { config.data = toSnakeCase(config.data) } catch {}
  }
  // IronWall v1.28.16: 携带设备指纹，攻击触发封禁时同步锁定指纹（换代理IP无效）
  try {
    const fp = await getDeviceFingerprint()
    config.headers = config.headers || {}
    if (!config.headers['X-IronWall-FP']) {
      config.headers['X-IronWall-FP'] = fp
    }
    // IronWall v1.29.0: 首个 API 请求前确保指纹绑定签名已建立（登录接口自身仅预热一次，避免死循环）
    if (!config.headers['X-IronWall-Skip-Sig-Warmup']) {
      await warmUpFingerprintSignature()
    }
  } catch {
    // 指纹不可用不影响业务请求
  }

  // IronWall v1.40.0: 接口加密层——逻辑路径 -> 会话前缀路径 + HMAC 签名
  try {
    const anyCfg = config as any
    if (anyCfg._origUrl === undefined) {
      anyCfg._origUrl = config.url
    }
    if (typeof config.url === 'string' && config.url.startsWith('/') && !config.url.startsWith('/api/s/')) {
      let path = config.url
      let query = ''
      const qIdx = path.indexOf('?')
      if (qIdx >= 0) {
        query = path.slice(qIdx)
        path = path.slice(0, qIdx)
      }
      if (config.params && typeof config.params === 'object') {
        const params = new URLSearchParams()
        Object.entries(config.params as Record<string, unknown>).forEach(([k, v]) => {
          if (v === null || v === undefined) return
          params.append(k, String(v))
        })
        const qs = params.toString()
        if (qs) query = query ? `${query}&${qs}` : `?${qs}`
        config.params = undefined
      }
      const method = (config.method || 'get').toUpperCase()
      let bodyHash: string | undefined
      const data = config.data
      if (data && typeof data === 'object'
          && !(data instanceof FormData) && !(data instanceof URLSearchParams) && !(data instanceof Blob)) {
        try {
          const raw = JSON.stringify(data)
          if (raw.length <= 1024 * 1024) bodyHash = await sha256Text(raw)
        } catch { /* 不可序列化则跳过体哈希 */ }
      }
      const wirePath = path.replace(/^\//, '')
      const canonical = (await resolveCanonical(wirePath)) ?? ('/api/' + wirePath)
      const signed = await signRequest(method, canonical, wirePath, query, bodyHash)
      config.url = signed.url + query
      config.headers = config.headers || {}
      Object.assign(config.headers, signed.headers)
    }
  } catch {
    // 加密层不可用（例如隐私模式无 crypto.subtle）时保持原路径，由服务端策略兜底
  }

  const authStore = useAuthStore()
  if (authStore.token) {
    config.headers = config.headers || {}
    config.headers['Authorization'] = `Bearer ${authStore.token}`
  }
  return config
})

apiClient.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error) => {
    // IronWall v1.40.0: 签名被拒（会话过期/密钥轮换）——自动重新握手并重试一次
    if (error.response?.status === 403 && error.response?.headers?.['x-ironwall-sign-required']) {
      const ok = await forceRebootstrap()
      if (ok && error.config) {
        const cfg = error.config as AxiosRequestConfig & { _sigRetried?: boolean; _origUrl?: string }
        if (!cfg._sigRetried) {
          cfg._sigRetried = true
          cfg.url = cfg._origUrl || cfg.url
          return apiClient(cfg)
        }
      }
      return Promise.reject(error)
    }

    // IronWall v1.20: 爬虫挑战——完成浏览器验证后自动重试原请求一次
    if (error.response?.status === 429 && error.response?.headers?.['x-ironwall-challenge']) {
      const ok = await completeCrawlerChallenge()
      if (ok && error.config) {
        const cfg = error.config as AxiosRequestConfig & { _retried?: boolean; _origUrl?: string }
        if (!cfg._retried) {
          cfg._retried = true
          cfg.url = cfg._origUrl || cfg.url
          return apiClient(cfg)
        }
      }
      return Promise.reject(error)
    }

    // IronWall v1.17.4: IP 被封禁后所有接口返回封禁标识，整页跳转到专属警示页
    if (error.response?.headers?.['x-ironwall-blocked']) {
      window.location.replace('/api/blocked-page')
      return Promise.reject(error)
    }
    if (error.response?.status === 401) {
      // Don't redirect if already on login page - let the login form handle the error
      const currentPath = window.location.pathname
      if (currentPath !== '/login' && currentPath !== '/register' && currentPath !== '/forgot-password') {
        const authStore = useAuthStore()
        authStore.logout()
        window.location.href = '/login'
      }
    }
    // Return error body as ApiResponse for non-401 errors so callers can handle gracefully
    if (error.response?.data) {
      return Promise.resolve(error.response)
    }
    return Promise.reject(error)
  }
)

export interface ApiResponse<T = any> {
  success: boolean
  message: string
  code?: number
  data?: T
  timestamp?: number
}

export async function request<T = any>(config: AxiosRequestConfig): Promise<ApiResponse<T>> {
  const response = await apiClient(config)
  return response.data
}

export default apiClient
