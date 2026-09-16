import { R_AUTH_2FA_LOGIN, R_AUTH_CHANGE_PASSWORD, R_AUTH_CHECK_EMAIL, R_AUTH_DELETE_ACCOUNT, R_AUTH_DEVICES, R_AUTH_DEVICES_ID, R_AUTH_LOGIN, R_AUTH_LOGIN_HISTORY, R_AUTH_LOGOUT, R_AUTH_NOTIFICATION_SETTINGS, R_AUTH_REGISTER, R_AUTH_RESET_PASSWORD, R_AUTH_SEND_CODE, R_AUTH_UPDATE_EMAIL, R_AUTH_UPDATE_USERNAME, R_AUTH_UPLOAD_AVATAR, R_AUTH_USER_INFO, R_AUTH_VERIFY_CODE, R_AUTH_VERIFY_EMAIL } from '@/utils/routeCodes'
import { computeFileSha256, signedFetch } from '@/utils/apiCrypto'
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { request } from '@/utils/axios'
import type { User, NotificationSettings, DeviceInfo } from '@/types'

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string>('')
  const user = ref<User | null>(null)
  const expiresAt = ref<string>('')

  const isLoggedIn = computed(() => !!token.value && !!user.value)

  async function login(username: string, password: string, rememberMe: boolean = false) {
    const response = await request<{
      token: string
      user: User
      expires_at: string
    }>({
      url: R_AUTH_LOGIN,
      method: 'POST',
      data: { username, password, remember_me: rememberMe }
    })

    // IronWall v1.28.0: 两步验证中间态——密码正确但需动态码时暂存中间令牌，不写会话
    // 先记录记住我选择，动态码通过后按同一选择写入对应存储
    if (rememberMe) {
      localStorage.setItem('jdy_remember', 'true')
    } else {
      localStorage.removeItem('jdy_remember')
    }
    if (response.success && (response.data as any)?.two_factor_required) {
      return response
    }

    if (response.success) {
      token.value = response.data!.token
      user.value = response.data!.user
      expiresAt.value = response.data!.expires_at
      const storage = rememberMe ? localStorage : sessionStorage
      storage.setItem('jdy_token', response.data!.token)
      storage.setItem('jdy_user', JSON.stringify(response.data!.user))
      storage.setItem('jdy_expires_at', response.data!.expires_at)
      if (rememberMe) {
        localStorage.setItem('jdy_remember', 'true')
        sessionStorage.removeItem('jdy_token')
      } else {
        localStorage.removeItem('jdy_remember')
      }
    }
    return response
  }

  // IronWall v1.28.0: 两步验证登录第二步——中间令牌 + 动态码换正式会话
  async function completeTwoFactorLogin(twoFactorToken: string, code: string) {
    const response = await request<{
      token: string
      user: User
      expires_at: string
    }>({
      url: R_AUTH_2FA_LOGIN,
      method: 'POST',
      data: { token: twoFactorToken, code }
    })

    if (response.success) {
      token.value = response.data!.token
      user.value = response.data!.user
      expiresAt.value = response.data!.expires_at
      const remember = localStorage.getItem('jdy_remember') === 'true'
      const storage = remember ? localStorage : sessionStorage
      storage.setItem('jdy_token', response.data!.token)
      storage.setItem('jdy_user', JSON.stringify(response.data!.user))
      storage.setItem('jdy_expires_at', response.data!.expires_at)
      if (remember) {
        sessionStorage.removeItem('jdy_token')
        sessionStorage.removeItem('jdy_user')
        sessionStorage.removeItem('jdy_expires_at')
      }
    }
    return response
  }

  async function register(username: string, email: string, password: string, code: string) {
    const response = await request<{ token: string; user: User; expires_at: string }>({
      url: R_AUTH_REGISTER,
      method: 'POST',
      data: { username, email, password, code }
    })

    if (response.success) {
      token.value = response.data!.token
      user.value = response.data!.user
      expiresAt.value = response.data!.expires_at
      sessionStorage.setItem('jdy_token', response.data!.token)
      sessionStorage.setItem('jdy_user', JSON.stringify(response.data!.user))
      sessionStorage.setItem('jdy_expires_at', response.data!.expires_at)
      localStorage.removeItem('jdy_remember')
    }
    return response
  }

  async function checkEmail(email: string) {
    // IronWall v1.20: 后端仅做格式校验、不返回存在性，前端弱提示即可
    const res = await request<{ checked: boolean; format_ok: boolean }>({
      url: R_AUTH_CHECK_EMAIL,
      method: 'GET',
      params: { email }
    })
    return res.success ? (res.data?.format_ok ?? false) : false
  }

  async function sendEmailCode(email: string) {
    return await request({ url: R_AUTH_SEND_CODE, method: 'POST', data: { email } })
  }

  async function verifyCode(email: string, code: string) {
    return await request({ url: R_AUTH_VERIFY_CODE, method: 'POST', data: { email, code } })
  }

  async function resetPassword(email: string, code: string, newPassword: string) {
    return await request({ url: R_AUTH_RESET_PASSWORD, method: 'POST', data: { email, code, new_password: newPassword } })
  }

  async function getUserInfo() {
    const response = await request<User>({ url: R_AUTH_USER_INFO, method: 'GET' })
    if (response.success) {
      user.value = (response.data as any).user || response.data || null
      // Persist updated user to storage
      const u = JSON.stringify(user.value)
      sessionStorage.setItem('jdy_user', u)
      if (localStorage.getItem('jdy_user')) { localStorage.setItem('jdy_user', u) }
    }
    return response
  }

  async function changePassword(oldPassword: string, newPassword: string) {
    const response = await request({ url: R_AUTH_CHANGE_PASSWORD, method: 'POST', data: { old_password: oldPassword, new_password: newPassword } })
    return response.success
  }

  async function getLoginHistory() {
    const response = await request<{ id: number; time: string; ip: string; device: string; status: string }[]>({ url: R_AUTH_LOGIN_HISTORY, method: 'GET' })
    return response.success ? response.data || [] : []
  }

  async function updateUsername(username: string, password: string) {
    return await request({
      url: R_AUTH_UPDATE_USERNAME,
      method: "POST",
      data: { username, password }
    })
  }

  async function updateEmail(email: string, code: string) {
    const response = await request({ url: R_AUTH_UPDATE_EMAIL, method: 'POST', data: { email, code } })
    if (response.success) {
      if (user.value) { user.value.email = email }
      // Persist to storage
      const ju = JSON.stringify(user.value)
      sessionStorage.setItem('jdy_user', ju)
      if (localStorage.getItem('jdy_user')) { localStorage.setItem('jdy_user', ju) }
    }
    return response
  }

  async function uploadAvatar(file: File) {
    const formData = new FormData()
    formData.append('avatar', file)
    const t = sessionStorage.getItem('jdy_token') || ''
    // IronWall v1.45.0: 头像上传绑定全文件 SHA-256（HMAC + 服务端原始字节复核）
    let fileHash: string | undefined
    try {
      if (window.crypto?.subtle) fileHash = await computeFileSha256(file)
    } catch { /* 无法计算时降级为无完整性绑定（头像路径维持旧语义，不影响业务） */ }
    const headers: Record<string, string> = { 'Authorization': 'Bearer ' + t }
    if (fileHash) headers['X-Api-File-Hash'] = fileHash
    const response = await signedFetch('POST', R_AUTH_UPLOAD_AVATAR.slice(1), {
      headers,
      body: formData
    }, fileHash)
    const result = await response.json()
    if (result.success && user.value) {
      user.value.avatar = result.data?.avatarUrl
      // Persist updated avatar to storage immediately
      const ju = JSON.stringify(user.value)
      sessionStorage.setItem('jdy_user', ju)
      if (localStorage.getItem('jdy_user')) { localStorage.setItem('jdy_user', ju) }
    }
    return result
  }

  async function deleteAccount(password: string) {
    const response = await request({ url: R_AUTH_DELETE_ACCOUNT, method: 'POST', data: { password } })
    if (response.success) { await logout() }
    return response
  }

  async function sendVerificationEmail() {
    return await request({ url: R_AUTH_VERIFY_EMAIL, method: 'POST' })
  }

  async function getNotificationSettings() {
    const response = await request<NotificationSettings>({ url: R_AUTH_NOTIFICATION_SETTINGS, method: 'GET' })
    return response
  }

  async function updateNotificationSettings(settings: Partial<NotificationSettings>) {
    // IronWall v1.47.10: 字段已是后端 snake_case 契约，直接透传（axios 拦截器对下划线键幂等）
    return await request({ url: R_AUTH_NOTIFICATION_SETTINGS, method: 'PUT', data: settings })
  }

  async function getDevices() {
    const response = await request<DeviceInfo[]>({ url: R_AUTH_DEVICES, method: 'GET' })
    return response.success ? (response.data || []) : []
  }

  async function revokeDevice(deviceId: number) {
    return await request({ url: `${R_AUTH_DEVICES_ID}/${deviceId}`, method: 'DELETE' })
  }

  function loadFromStorage() {
    // Check localStorage first for remember-me tokens
    const fromLocal = localStorage.getItem('jdy_remember') === 'true'
    const storage = fromLocal ? localStorage : sessionStorage
    const storedToken = storage.getItem('jdy_token')
    const storedUser = storage.getItem('jdy_user')
    const storedExpiresAt = storage.getItem('jdy_expires_at')
    if (storedToken && storedUser && storedExpiresAt) {
      const expires = new Date(storedExpiresAt)
      if (expires > new Date()) {
        token.value = storedToken
        user.value = JSON.parse(storedUser)
        expiresAt.value = storedExpiresAt
        // Also copy to sessionStorage for this session
        if (fromLocal) {
          sessionStorage.setItem('jdy_token', storedToken)
          sessionStorage.setItem('jdy_user', storedUser)
          sessionStorage.setItem('jdy_expires_at', storedExpiresAt)
        }
      } else { logout() }
    }
  }

  let loggingOut = false

  async function logout() {
    // IronWall v1.43.0: 服务端吊销——递增 token_version 使所有旧 JWT 立即失效；
    // 无论远端结果如何，本地会话一律清理（登出永不阻塞、永不失败）。
    if (!loggingOut) {
      loggingOut = true
      try {
        await request({ url: R_AUTH_LOGOUT, method: 'POST' })
      } catch { /* 网络异常或令牌已过期时忽略，本地照常登出 */ }
      finally {
        loggingOut = false
      }
    }
    token.value = ''
    user.value = null
    expiresAt.value = ''
    sessionStorage.removeItem('jdy_token')
    sessionStorage.removeItem('jdy_user')
    sessionStorage.removeItem('jdy_expires_at')
    localStorage.removeItem('jdy_token')
    localStorage.removeItem('jdy_user')
    localStorage.removeItem('jdy_expires_at')
    localStorage.removeItem('jdy_remember')
  }

  return {
    token,
    user,
    expiresAt,
    isLoggedIn,
    login,
    completeTwoFactorLogin,
    register,
    checkEmail,
    sendEmailCode,
    verifyCode,
    resetPassword,
    getUserInfo,
    changePassword,
    getLoginHistory,
    updateUsername,
    updateEmail,
    uploadAvatar,
    deleteAccount,
    sendVerificationEmail,
    getNotificationSettings,
    updateNotificationSettings,
    getDevices,
    revokeDevice,
    loadFromStorage,
    logout
  }
})
