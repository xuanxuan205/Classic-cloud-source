import { R_SHARES_CREATE, R_SHARES_ID, R_SHARES_LIST } from '@/utils/routeCodes'
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { request } from '@/utils/axios'
import type { Share, ShareInfo } from '@/types'

export const useSharesStore = defineStore('shares', () => {
  const shares = ref<Share[]>([])
  const currentShare = ref<ShareInfo | null>(null)
  const isLoading = ref(false)

  async function getShares(page: number = 0, size: number = 20) {
    isLoading.value = true
    try {
      const response = await request<{
        content: Share[]
        totalElements: number
        totalPages: number
        number: number
        size: number
      }>({
        url: R_SHARES_LIST,
        method: 'GET',
        params: { page, size }
      })
      if (response.success) { shares.value = response.data?.content || [] }
      return response
    } finally { isLoading.value = false }
  }

  async function createShare(id: number, options: { days?: number; password?: string; description?: string; downloadLimit?: number; shareType?: number; contact?: string; sharerName?: string }) {
    const shareType = options.shareType || 1
    const data: Record<string, any> = {
      shareType,
      days: options.days || 0,
      password: options.password || '',
      description: options.description || '',
      // IronWall v1.8: 后端为 SNAKE_CASE，显式发送 download_limit（axios 拦截器对下划线键幂等）
      download_limit: options.downloadLimit || 0,
      contact: options.contact || '',
      sharerName: options.sharerName || ''
    }
    if (shareType === 2) { data.folderId = id } else { data.fileId = id }
    return await request({ url: R_SHARES_CREATE, method: 'POST', data })
  }

  async function deleteShare(shareId: number) {
    return await request({ url: `${R_SHARES_ID}/${shareId}`, method: 'DELETE' })
  }

  async function getShareInfo(shareCode: string, pwHash?: string, pwToken?: string) {
    isLoading.value = true
    try {
      const params: Record<string, string> = {}
      if (pwHash && pwToken) { params.pw_hash = pwHash; params.pw_token = pwToken }

      const response = await request<ShareInfo>({ url: `${R_SHARES_ID}/${shareCode}`, method: 'GET', params })
      if (response.success) { currentShare.value = response.data || null }
      return response
    } finally { isLoading.value = false }
  }

  async function downloadSharedFile(shareCode: string, pwHash?: string, pwToken?: string) {
    const params = new URLSearchParams()
    if (pwHash && pwToken) { params.append('pw_hash', pwHash); params.append('pw_token', pwToken) }
    const url = `/api/shares/download/${shareCode}${params.toString() ? "?" + params.toString() : ""}`
    const response = await fetch(url)
    if (!response.ok) {
      // IronWall v1.8: 429/400 时透出后端业务提示（密码尝试过多/下载次数已达上限），不再笼统提示"下载失败"
      let message = '下载失败'
      try {
        const body = await response.json()
        if (body && typeof body.message === 'string' && body.message) { message = body.message }
      } catch { /* 非 JSON 响应保持默认提示 */ }
      return { success: false, message }
    }
    const blob = await response.blob()
    const contentDisposition = response.headers.get('Content-Disposition') || ''
    const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/)
    const filename = filenameMatch ? decodeURIComponent(filenameMatch[1]) : `share_${shareCode}`
    const urlObj = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = urlObj
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    window.URL.revokeObjectURL(urlObj)
    return { success: true, message: '下载成功' }
  }

  return { shares, currentShare, isLoading, getShares, createShare, deleteShare, getShareInfo, downloadSharedFile }
})
