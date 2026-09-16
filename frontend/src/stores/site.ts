import { defineStore } from 'pinia'
import { ref } from 'vue'
import { request } from '@/utils/axios'
import { R_SITE_INFO } from '@/utils/routeCodes'

/** IronWall v1.46.0: 上传策略服务端下发——前端以 /api/site/info 为单一权威，消除前后端阈值漂移。 */
interface SiteInfo {
  site_name?: string
  site_description?: string
  disabled_notice?: string
  upload_direct_max_bytes?: string | number
  upload_chunk_size_bytes?: string | number
  upload_max_file_bytes?: string | number
  upload_admin_max_file_bytes?: string | number
  upload_policy_version?: string
  upload_ext_whitelist?: string
}

export interface UploadPolicyView {
  directMaxBytes: number
  chunkSizeBytes: number
  maxFileBytes: number
  adminMaxFileBytes: number
  policyVersion: string
  extWhitelist: string[]
}

/** 与后端 security/UploadPolicy 同源的默认值：拉取失败时兜底，绝不放大任何上限。 */
// IronWall v1.47.2: server-downloaded whitelist fallback (same source as backend UploadPolicy)
const DEFAULT_EXT_WHITELIST = [
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'md', 'csv',
  'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg',
  'mp3', 'wav', 'flac', 'mp4', 'mov', 'mkv', 'avi',
  'zip', '7z', 'rar'
]

const DEFAULT_POLICY: UploadPolicyView = {
  directMaxBytes: 10 * 1024 * 1024,
  chunkSizeBytes: 10 * 1024 * 1024,
  maxFileBytes: 850 * 1024 * 1024,
  adminMaxFileBytes: 20 * 1024 * 1024 * 1024,
  policyVersion: 'fallback',
  extWhitelist: [...DEFAULT_EXT_WHITELIST]
}

function parseExtWhitelist(raw: unknown): string[] {
  if (typeof raw === 'string' && raw.trim()) {
    const items = raw.split(/[,,\uFF0C\s]+/).map((s) => s.trim().toLowerCase()).filter(Boolean)
    if (items.length > 0) return items
  }
  return [...DEFAULT_EXT_WHITELIST]
}

function toPositiveNumber(value: unknown, fallback: number): number {
  const n = Number(value)
  return Number.isFinite(n) && n > 0 ? n : fallback
}

export const useSiteStore = defineStore('site', () => {
  const info = ref<SiteInfo | null>(null)
  const loading = ref(false)
  let inflight: Promise<SiteInfo | null> | null = null

  async function loadInfo(force = false): Promise<SiteInfo | null> {
    if (info.value && !force) return info.value
    if (inflight) return inflight
    inflight = (async () => {
      loading.value = true
      try {
        const response = await request<SiteInfo>({ url: R_SITE_INFO, method: 'GET' })
        if (response?.success && response.data) {
          info.value = response.data
        }
      } catch {
        // 拉取失败保留 null，读取方走与服务端同源的默认值兜底
      } finally {
        loading.value = false
        inflight = null
      }
      return info.value
    })()
    return inflight
  }

  function uploadPolicy(): UploadPolicyView {
    const data = info.value
    return {
      directMaxBytes: toPositiveNumber(data?.upload_direct_max_bytes, DEFAULT_POLICY.directMaxBytes),
      chunkSizeBytes: toPositiveNumber(data?.upload_chunk_size_bytes, DEFAULT_POLICY.chunkSizeBytes),
      maxFileBytes: toPositiveNumber(data?.upload_max_file_bytes, DEFAULT_POLICY.maxFileBytes),
      adminMaxFileBytes: toPositiveNumber(data?.upload_admin_max_file_bytes, DEFAULT_POLICY.adminMaxFileBytes),
      policyVersion: typeof data?.upload_policy_version === 'string' && data.upload_policy_version
        ? data.upload_policy_version
        : DEFAULT_POLICY.policyVersion,
      extWhitelist: parseExtWhitelist(data?.upload_ext_whitelist)
    }
  }

  return { info, loading, loadInfo, uploadPolicy }
})