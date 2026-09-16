import { R_FILES_DOWNLOAD_ID, R_FILES_FOLDER, R_FILES_FOLDER_ID, R_FILES_FOLDER_LIST, R_FILES_ID, R_FILES_ID_PERMANENT, R_FILES_ID_RESTORE, R_FILES_LIST, R_FILES_RECYCLE, R_FILES_STORAGE, R_FILES_UPLOAD, R_FILES_UPLOAD_CHUNK, R_FILES_UPLOAD_CHECK, R_FILES_UPLOAD_MERGE } from '@/utils/routeCodes'
import { computeFileSha256, forceRebootstrap, resolveCanonical, signedFetch, signRequest } from '@/utils/apiCrypto'
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { request } from '@/utils/axios'
import { useAuthStore } from './auth'
import { useSiteStore } from './site'
import type { File as FileType, StorageStats, UploadResult } from '@/types'

// IronWall v1.41.0: 裸接口 XHR 签名发送（multipart 不参与体哈希）
interface SignedXhrResult { status: number; body: string }

// IronWall v1.45.0: multipart 完整性绑定（文件级/分片级哈希头 + 纳入 HMAC）
interface IntegrityBinding { header: string; hash: string }

// IronWall v1.47.2: extension preflight - whitelist + multi-extension smuggling guard (admin bypass, server stays authoritative)
const DANGEROUS_EXT_SEGMENTS = new Set([
  'html', 'htm', 'xhtml', 'mhtml', 'js', 'mjs', 'cjs', 'wasm',
  'exe', 'dll', 'com', 'scr', 'pif', 'bat', 'cmd', 'ps1', 'sh',
  'vbs', 'vbe', 'jse', 'wsf', 'wsh', 'hta', 'msi', 'jar', 'class',
  'php', 'jsp', 'asp', 'aspx', 'pl', 'py', 'cgi', 'shtml', 'swf'
])
const MSG_NO_EXTENSION = '文件缺少扩展名，无法上传'
const MSG_SNEAKY_PREFIX = '检测到可疑的多重扩展名（.'
const MSG_SNEAKY_SUFFIX = '），已拦截上传'
const MSG_UNSUPPORTED_PREFIX = '不支持的文件类型：.'
const MSG_UNSUPPORTED_MID = '，允许上传：'
function checkUploadExtension(name: string, isAdmin: boolean, whitelist: string[]): string | null {
  if (isAdmin) return null
  const segments = (name || '').trim().toLowerCase().split('.').filter((s) => s.length > 0)
  if (segments.length < 2) return MSG_NO_EXTENSION
  const effective = segments[segments.length - 1]
  const sneaky = segments.slice(0, -1).find((s) => DANGEROUS_EXT_SEGMENTS.has(s))
  if (sneaky) return MSG_SNEAKY_PREFIX + sneaky + MSG_SNEAKY_SUFFIX
  if (!whitelist.includes(effective)) {
    const brief = whitelist.length > 12 ? whitelist.slice(0, 12).join(', ') + ' ...' : whitelist.join(', ')
    return MSG_UNSUPPORTED_PREFIX + effective + MSG_UNSUPPORTED_MID + brief
  }
  return null
}

async function signedXhr(method: string, wirePath: string, token: string, formData: FormData, onProgress?: (e: ProgressEvent) => void, integrity?: IntegrityBinding): Promise<SignedXhrResult> {
  const prepare = async (): Promise<{ url: string; headers: Record<string, string> } | null> => {
    try {
      const canonical = (await resolveCanonical(wirePath)) ?? '/api/' + wirePath
      const signed = await signRequest(method, canonical, wirePath, '', integrity?.hash)
      if (integrity) signed.headers[integrity.header] = integrity.hash
      return { url: '/api/' + signed.url, headers: signed.headers }
    } catch {
      return null
    }
  }
  const send = (p: { url: string; headers: Record<string, string> } | null): Promise<SignedXhrResult> => {
    return new Promise((resolve) => {
      const xhr = new XMLHttpRequest()
      xhr.open(method, p ? p.url : '/api/' + wirePath)
      if (token) xhr.setRequestHeader('Authorization', 'Bearer ' + token)
      if (p) {
        xhr.setRequestHeader('X-Api-Ts', p.headers['X-Api-Ts'])
        xhr.setRequestHeader('X-Api-Nonce', p.headers['X-Api-Nonce'])
        xhr.setRequestHeader('X-Api-Sig', p.headers['X-Api-Sig'])
        if (p.headers['X-Api-File-Hash']) xhr.setRequestHeader('X-Api-File-Hash', p.headers['X-Api-File-Hash'])
        if (p.headers['X-Api-Chunk-Hash']) xhr.setRequestHeader('X-Api-Chunk-Hash', p.headers['X-Api-Chunk-Hash'])
      }
      if (onProgress && xhr.upload) xhr.upload.onprogress = onProgress
      xhr.onload = () => resolve({ status: xhr.status, body: xhr.responseText })
      xhr.onerror = () => resolve({ status: 0, body: '' })
      xhr.send(formData)
    })
  }
  const prepared = await prepare()
  let result = await send(prepared)
  if (result.status === 403 && prepared) {
    const ok = await forceRebootstrap()
    if (ok) {
      const second = await prepare()
      if (second) result = await send(second)
    }
  }
  return result
}

export const useFilesStore = defineStore('files', () => {
  const files = ref<FileType[]>([])
  const folders = ref<any[]>([])
  const currentFolderId = ref(0)
  const stats = ref<StorageStats | null>(null)
  const isLoading = ref(false)

  async function getFiles(folderId: number = 0, page: number = 0, size: number = 20) {
    isLoading.value = true
    try {
      const response = await request<{
        content: FileType[]
        totalElements: number
        totalPages: number
        number: number
        size: number
      }>({
        url: R_FILES_LIST,
        method: 'GET',
        params: {
          folderId: folderId || 0,
          page,
          size
        }
      })

      console.log('[Files] getFiles response:', response)

      if (response.success) {
        const newFiles = response.data?.content || []
        console.log('[Files] getFiles got', newFiles.length, 'files, local has', files.value.length)
        files.value = newFiles
        currentFolderId.value = folderId
      } else {
        console.warn('[Files] getFiles failed:', response.message)
      }

      return response
    } catch (e: any) {
      console.error('[Files] getFiles error:', e)
      return { success: false, message: e?.message || 'get files failed' }
    } finally {
      isLoading.value = false
    }
  }

  async function getStorageStats() {
    try {
      const response = await request<StorageStats>({
        url: R_FILES_STORAGE,
        method: 'GET'
      })

      if (response.success) {
        stats.value = response.data || null
      }

      return response
    } catch {
      return { success: false, message: 'failed to get storage stats' }
    }
  }

  async function deleteFile(fileId: number) {
    return await request({
      url: `${R_FILES_ID}/${fileId}`,
      method: 'DELETE'
    })
  }

  async function uploadFile(file: File, folderId: number = 0, onProgress?: (pct: number) => void): Promise<{ success: boolean; message: string; data?: UploadResult }> {
    // IronWall v1.46.0: 阈值一律以服务端 /api/site/info 下发为准（拉取失败走与服务端同源的默认值兜底）
    const siteStore = useSiteStore()
    await siteStore.loadInfo()
    const policy = siteStore.uploadPolicy()
    const CHUNK_SIZE = policy.chunkSizeBytes
    const DIRECT_MAX = policy.directMaxBytes
    const isAdmin = useAuthStore().user?.role === 'admin'
    const MAX_FILE_SIZE = isAdmin ? policy.adminMaxFileBytes : policy.maxFileBytes
    // IronWall v1.47.2: client-side extension preflight before any upload path
    const extBlocked = checkUploadExtension(file.name, isAdmin, policy.extWhitelist)
    if (extBlocked) return { success: false, message: extBlocked }

    const sha256Hex = async (buf: ArrayBuffer): Promise<string> => {
      const digest = await crypto.subtle.digest('SHA-256', buf)
      return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
    }

    const postChunk = async (hash: string, index: number, total: number, blob: Blob): Promise<{ success: boolean; message: string }> => {
      const token = sessionStorage.getItem('jdy_token') || localStorage.getItem('jdy_token') || ''
      const formData = new FormData()
      formData.append('file', blob, 'chunk-' + index)
      formData.append('hash', hash)
      formData.append('index', String(index))
      formData.append('total', String(total))
      // IronWall v1.45.0: 每片分片计算 SHA-256 并纳入签名（服务端明文层复核）
      const chunkHash = await sha256Hex(await blob.arrayBuffer())
      const result = await signedXhr('POST', R_FILES_UPLOAD_CHUNK.slice(1), token, formData, undefined, { header: 'X-Api-Chunk-Hash', hash: chunkHash })
      try { return JSON.parse(result.body) } catch { return { success: false, message: 'Invalid response' } }
    }

    const legacyUpload = async (): Promise<{ success: boolean; message: string; data?: UploadResult }> => {
      const formData = new FormData()
      formData.append('file', file)
      if (folderId > 0) formData.append('folderId', String(folderId))
      const token = sessionStorage.getItem('jdy_token') || ''
      // IronWall v1.46.0: 非安全上下文直传必须落在服务端直传上限内（管理员豁免），超限引导换现代浏览器走分片
      if (!isAdmin && file.size > DIRECT_MAX) {
        return { success: false, message: `当前浏览器不支持完整性校验，且文件超过直传上限 ${Math.floor(DIRECT_MAX / 1024 / 1024)}MB，请使用最新版 Chrome/Edge 或 HTTPS 访问后重试` }
      }
      // IronWall v1.45.0: 全文件 SHA-256 强制绑定（缺失不再静默降级）
      if (!window.crypto?.subtle) {
        return { success: false, message: '当前环境不支持完整性校验，请使用 HTTPS 访问后重试' }
      }
      let fileHash: string
      try {
        fileHash = await computeFileSha256(file)
      } catch {
        return { success: false, message: '文件完整性哈希计算失败，请重试' }
      }
      const result = await signedXhr('POST', R_FILES_UPLOAD.slice(1), token, formData, (e) => {
        if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100))
      }, { header: 'X-Api-File-Hash', hash: fileHash })
      if (result.status === 0) return { success: false, message: 'Network error' }
      try { return JSON.parse(result.body) } catch { return { success: false, message: 'Invalid response' } }
    }

    try {
      if (file.size <= 0) return { success: false, message: '文件内容为空，无法上传' }
      if (file.size > MAX_FILE_SIZE) {
        const limitText = isAdmin
          ? Math.round(MAX_FILE_SIZE / 1024 / 1024 / 1024) + 'GB'
          : Math.round(MAX_FILE_SIZE / 1024 / 1024) + 'MB'
        return { success: false, message: isAdmin ? `单文件超过 ${limitText}，请拆分后上传` : `单文件最大支持 ${limitText}，请压缩或拆分后上传` }
      }

      // 非安全上下文（无 Web Crypto）回退旧版单次上传（其内部强制全文件哈希，缺失即报错）
      if (!window.crypto?.subtle) {
        return await legacyUpload()
      }

      // 1) 计算文件 SHA-256 指纹（用于秒传与断点续传定位）
      if (onProgress) onProgress(1)
      const hash = await sha256Hex(await file.arrayBuffer())

      // 2) 询问服务器：是否已存在相同文件（秒传），否则返回已上传的分片序号（续传）
      const check = await request<{ exists: boolean; file_id?: number; uploaded_chunks?: number[]; chunk_size_bytes?: number | string }>({
        url: R_FILES_UPLOAD_CHECK,
        method: 'POST',
        data: { filename: file.name, size: file.size, hash }
      })
      if (!check.success) {
        if (check.code === 4002) return { success: false, message: '该类型文件暂不支持上传（当前支持文档/图片/音视频/压缩包四类）' }
        return { success: false, message: check.message || '上传校验失败，请重试' }
      }

      const uploaded = new Set<number>(check.data?.uploaded_chunks || [])
      // 服务端下发的分片大小优先（check 响应 chunk_size_bytes），缺省回退 site/info 策略值
      const serverChunk = (() => {
        const n = Number(check.data?.chunk_size_bytes)
        return Number.isFinite(n) && n > 0 ? n : CHUNK_SIZE
      })()
      const total = Math.max(1, Math.ceil(file.size / serverChunk))

      // 3) 秒传：服务器已有相同物理文件，直接登记，无需传输
      if (check.data?.exists) {
        const merged = await request<UploadResult>({
          url: R_FILES_UPLOAD_MERGE,
          method: 'POST',
          data: { filename: file.name, size: file.size, hash, total: 0, folderId: folderId > 0 ? folderId : 0, mimeType: file.type || '' }
        })
        if (merged.success && onProgress) onProgress(100)
        return merged
      }

      // 4) 分片上传（跳过服务器已有分片 → 断点续传）
      for (let i = 0; i < total; i++) {
        if (uploaded.has(i)) {
          const doneBytes = Math.min(file.size, (i + 1) * serverChunk)
          if (onProgress) onProgress(Math.round((doneBytes / file.size) * 100))
          continue
        }
        const start = i * serverChunk
        const end = Math.min(file.size, start + serverChunk)
        const res = await postChunk(hash, i, total, file.slice(start, end))
        if (!res.success) {
          return { success: false, message: res.message || `第 ${i + 1}/${total} 分片上传失败，已保留进度，可稍后重新上传继续` }
        }
        const doneBytes = Math.min(file.size, (i + 1) * serverChunk)
        if (onProgress) onProgress(Math.round((doneBytes / file.size) * 100))
      }

      // 5) 合并分片，服务端复算 SHA-256 校验后落库
      const merged = await request<UploadResult>({
        url: R_FILES_UPLOAD_MERGE,
        method: 'POST',
        data: { filename: file.name, size: file.size, hash, total, folderId: folderId > 0 ? folderId : 0, mimeType: file.type || '' }
      })
      if (merged.success && onProgress) onProgress(100)
      return merged
    } catch (error: any) {
      console.error('[Files] uploadFile error:', error)
      return { success: false, message: error?.message || '上传失败，请重试' }
    }
  }
async function downloadFile(fileId: number) {
    const token = sessionStorage.getItem('jdy_token') || ''
    const response = await signedFetch('GET', `${R_FILES_DOWNLOAD_ID.slice(1)}/${fileId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    })

    if (!response.ok) {
      return { success: false, message: 'download failed' }
    }

    const blob = await response.blob()
    const contentDisposition = response.headers.get('Content-Disposition') || ''
    const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/)
    const filename = filenameMatch ? decodeURIComponent(filenameMatch[1]) : `file_${fileId}`

    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    window.URL.revokeObjectURL(url)

    return { success: true, message: 'download success' }
  }

  async function createFolder(folderName: string, parentId: number = 0) {
    const response = await request<{ id: number; name: string }>({
      url: R_FILES_FOLDER,
      method: 'POST',
      params: {
        name: folderName,
        parentId: parentId > 0 ? parentId : undefined
      }
    })

    if (response.success) {
      await getFolders(parentId)
    }

    return response
  }

  async function getFolders(parentId: number = 0) {
    try {
      const response = await request<{ id: number; name: string; parent_id: number; created_at: string }[]>({
        url: R_FILES_FOLDER_LIST,
        method: 'GET',
        params: {
          parentId: parentId > 0 ? parentId : undefined
        }
      })

      if (response.success) {
        folders.value = response.data || []
      }

      return response
    } catch {
      return { success: false, message: 'failed to get folders' }
    }
  }

  async function deleteFolder(folderId: number) {
    return await request({
      url: `${R_FILES_FOLDER_ID}/${folderId}`,
      method: 'DELETE'
    })
  }


  async function getDeletedFiles(page: number = 0, size: number = 50) {
    try {
      return await request<{ content: any[]; totalElements: number }>({
        url: R_FILES_RECYCLE,
        method: 'GET',
        params: { page, size }
      })
    } catch (e: any) {
      console.error('[Files] getDeletedFiles error:', e)
      return { success: false, message: e?.message || 'failed', data: undefined }
    }
  }

  async function restoreFile(fileId: number) {
    try {
      return await request({ url: `${R_FILES_ID_RESTORE}/${fileId}`, method: 'POST' })
    } catch (e: any) {
      console.error('[Files] restoreFile error:', e)
      return { success: false, message: e?.message || 'failed' }
    }
  }

  async function permanentDeleteFile(fileId: number) {
    try {
      return await request({ url: `${R_FILES_ID_PERMANENT}/${fileId}`, method: 'DELETE' })
    } catch (e: any) {
      console.error('[Files] permanentDeleteFile error:', e)
      return { success: false, message: e?.message || 'failed' }
    }
  }

  return {
    files,
    folders,
    currentFolderId,
    stats,
    isLoading,
    getFiles,
    getStorageStats,
    deleteFile,
    uploadFile,
    downloadFile,
    createFolder,
    getFolders,
    deleteFolder,
    getDeletedFiles,
    restoreFile,
    permanentDeleteFile
  }
})
