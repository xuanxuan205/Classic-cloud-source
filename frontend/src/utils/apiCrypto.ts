// IronWall v1.40.0: API 加密层客户端
//
// 设计目标：前端包里不出现任何真实接口路径。
// 1) 页面加载后完成爬虫 JS 挑战（iw_ok 签名 cookie）；
// 2) 携带设备指纹调用 /api/bootstrap 领取「会话密钥 + AES-GCM 加密路由地图」；
// 3) 此后每个请求走会话前缀路径 /api/s/<sid>/<真实路径>，并携带 HMAC-SHA256 签名
// （method|path[?query]|ts|nonce[|bodyHash]），服务端校验 + nonce 防重放；
// 4) 签名被拒（403 + X-IronWall-Sign-Required）时自动重新握手并重试一次。
//
// 诚实边界：浏览器端代码可被逆向，本层是「抬高逆向成本 + 服务端强制准入」的组合；
// 真正的安全边界在服务端 ApiCryptoFilter 的签名校验，不在前端混淆本身。
import { getDeviceFingerprint } from './deviceFingerprint'

const STORAGE_KEY = 'iw_api_crypto_v1'

export interface CryptoState {
  sid: string
  keyHex: string
  expiresAt: number
  routeMap: Record<string, string>
  // IronWall v1.42.0: 无盐旧码 -> 当期码翻译表（路由码轮换后请求自动换新码）
  codeMap?: Record<string, string>
}

let state: CryptoState | null = null
let bootstrapping: Promise<CryptoState | null> | null = null
let challengeInFlight: Promise<boolean> | null = null

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(hex.length / 2))
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64)
  const bytes = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

function randomHex(length: number): string {
  const bytes = new Uint8Array(length / 2)
  crypto.getRandomValues(bytes)
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function hmacSha256Hex(keyHex: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', hexToBytes(keyHex), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function aesGcmDecrypt(keyHex: string, payload: string): Promise<string> {
  const dot = payload.indexOf('.')
  if (dot <= 0) throw new Error('bad route map payload')
  const key = await crypto.subtle.importKey('raw', hexToBytes(keyHex), { name: 'AES-GCM' }, false, ['decrypt'])
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(payload.substring(0, dot)) },
    key,
    b64ToBytes(payload.substring(dot + 1))
  )
  return new TextDecoder().decode(plain)
}

async function solvePow(nonce: string, difficulty: number): Promise<string> {
  const prefix = '0'.repeat(difficulty)
  for (let i = 0; i < 2000000; i++) {
    const solution = String(i)
    const hex = await sha256Hex(nonce + '|' + solution)
    if (hex.startsWith(prefix)) return solution
  }
  throw new Error('pow timeout')
}

export async function completeCrawlerChallenge(): Promise<boolean> {
  if (challengeInFlight) return challengeInFlight
  challengeInFlight = (async () => {
    try {
      const resp = await fetch('/api/crawler-challenge', { method: 'GET', cache: 'no-store', credentials: 'same-origin' })
      if (!resp.ok) return false
      const data = await resp.json().catch(() => null)
      const nonce: string | undefined = data?.nonce
      const difficulty = Number(data?.difficulty || 0)
      if (!nonce) return false
      let solution = ''
      if (difficulty > 0 && crypto?.subtle) {
        try {
          solution = await solvePow(nonce, difficulty)
        } catch {
          return false
        }
      }
      const verify = await fetch(`/api/crawler-verify?n=${encodeURIComponent(nonce)}&s=${encodeURIComponent(solution)}`, { method: 'GET', cache: 'no-store', credentials: 'same-origin' })
      return verify.ok
    } catch {
      return false
    } finally {
      setTimeout(() => { challengeInFlight = null }, 3000)
    }
  })()
  return challengeInFlight
}

export async function warmUpCrawlerChallenge(): Promise<void> {
  void completeCrawlerChallenge()
}

function loadPersisted(): CryptoState | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as CryptoState
    if (!parsed || !parsed.sid || !parsed.keyHex || parsed.expiresAt < Date.now() + 60_000) return null
    // IronWall v1.42.0: 旧会话（v1.41.0 无翻译表）失效重握手，确保拿到当期码
    if (!parsed.codeMap || Object.keys(parsed.codeMap).length === 0) return null
    return parsed
  } catch {
    return null
  }
}

function persist(value: CryptoState): void {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(value))
  } catch {
    // 隐私模式等不可写场景：仅内存态
  }
}

async function doBootstrap(): Promise<CryptoState | null> {
  const challengeOk = await completeCrawlerChallenge()
  if (!challengeOk) return null
  let fp = ''
  try {
    fp = await getDeviceFingerprint()
  } catch {
    return null
  }
  let resp: Response
  try {
    resp = await fetch('/api/bootstrap', {
      method: 'POST',
      cache: 'no-store',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-IronWall-FP': fp,
        'X-Requested-With': 'XMLHttpRequest'
      }
    })
  } catch {
    return null
  }
  if (!resp.ok) return null
  const body = await resp.json().catch(() => null)
  const d = body?.data
  if (!d?.session_id || !d?.key || !d?.route_map || !d?.code_map) return null
  try {
    const routeJson = await aesGcmDecrypt(d.key, d.route_map)
    const routeMap = JSON.parse(routeJson) as Record<string, string>
    const codeJson = await aesGcmDecrypt(d.key, d.code_map)
    const codeMap = JSON.parse(codeJson) as Record<string, string>
    const next: CryptoState = { sid: d.session_id, keyHex: d.key, expiresAt: Number(d.expires_at || 0), routeMap, codeMap }
    persist(next)
    return next
  } catch {
    return null
  }
}

export async function ensureCryptoState(force = false): Promise<CryptoState | null> {
  if (!force && state) return state
  if (!force) {
    const persisted = loadPersisted()
    if (persisted) {
      state = persisted
      return state
    }
  }
  if (bootstrapping) return bootstrapping
  bootstrapping = doBootstrap()
    .then((next) => {
      if (next) state = next
      return next
    })
    .finally(() => { bootstrapping = null })
  return bootstrapping
}

export async function forceRebootstrap(): Promise<boolean> {
  state = null
  try { sessionStorage.removeItem(STORAGE_KEY) } catch { /* ignore */ }
  const next = await ensureCryptoState(true)
  return next != null
}

export interface SignedRequest {
  url: string
  headers: Record<string, string>
}

/**
 * IronWall v1.43.0: 文件部分完整性哈希（与后端 FileIntegrityHash 算法一致）。
 * sha256(首 64KiB 字节 + "|" + 文件大小(十进制) + "|" + 尾 64KiB 字节)，
 * 首/尾切片与后端 File.slice 语义相同：小文件首尾重叠，大文件只读首尾两段。
 */
/**
 * IronWall v1.45.0: 全文件 SHA-256（消除首尾 64KB 部分哈希的中间篡改盲区）。
 * 大文件一次性读入内存计算；与后端 hashFile 算法一致（纯文件字节流），
 * 供直传/头像上传作为 X-Api-File-Hash 并参与 HMAC 绑定。
 */
export async function computeFileSha256(file: Blob): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer())
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

export async function computeFileIntegrityHash(file: Blob): Promise<string> {
  const CHUNK = 64 * 1024
  const size = file.size
  const first = new Uint8Array(await file.slice(0, Math.min(CHUNK, size)).arrayBuffer())
  const lastStart = Math.max(0, size - CHUNK)
  const last = new Uint8Array(await file.slice(lastStart, size).arrayBuffer())
  const sizeBytes = new TextEncoder().encode(String(size))
  const joined = new Uint8Array(first.byteLength + 1 + sizeBytes.byteLength + 1 + last.byteLength)
  let off = 0
  joined.set(first, off); off += first.byteLength
  joined[off++] = 0x7c
  joined.set(sizeBytes, off); off += sizeBytes.byteLength
  joined[off++] = 0x7c
  joined.set(last, off)
  const digest = await crypto.subtle.digest('SHA-256', joined)
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

export async function signRequest(method: string, canonicalPath: string, wirePath: string, query: string, bodyHash?: string): Promise<SignedRequest> {
  const current = await ensureCryptoState()
  if (!current) throw new Error('api-crypto-unavailable')
  const ts = String(Date.now())
  const nonce = randomHex(16)
  const pathWithQuery = canonicalPath + (query || '')
  const sigInput = `${method}|${pathWithQuery}|${ts}|${nonce}${bodyHash ? '|' + bodyHash : ''}`
  const sig = await hmacSha256Hex(current.keyHex, sigInput)
  // IronWall v1.42.0: 无盐旧码翻译为当期码（HMAC 仍基于 canonicalPath 不变）。
  // 路由码轮换后旧码失效，翻译保证新请求始终携带当期码。
  let finalWirePath = wirePath
  if (current.codeMap && wirePath) {
    const slash = wirePath.indexOf('/')
    const first = slash >= 0 ? wirePath.substring(0, slash) : wirePath
    const mapped = current.codeMap[first]
    if (mapped) {
      finalWirePath = slash >= 0 ? mapped + wirePath.substring(slash) : mapped
    }
  }
  // IronWall v1.41.0: 线上路径使用 wirePath（路由码或旧逻辑路径），HMAC 使用还原后的 canonicalPath。
  // axios baseURL='/api' 会拼成 /api/s/<sid>/<wirePath>；直接 fetch 需自行加 '/api/' 前缀。
  return {
    url: `s/${current.sid}/${finalWirePath}`,
    headers: { 'X-Api-Ts': ts, 'X-Api-Nonce': nonce, 'X-Api-Sig': sig }
  }
}

export async function resolveRoute(logical: string): Promise<string> {
  const current = await ensureCryptoState()
  if (current?.routeMap[logical]) return current.routeMap[logical]
  return '/api/' + logical
}

/**
 * IronWall v1.41.0: 由线上路径还原真实路径（HMAC 校验用）。
 * wirePath 首段为路由码：取加密路由地图模板按 {n} 回填动态段；占位符与动态段数量不符返回 null。
 * 非路由码（旧客户端/未知码）返回 null，调用方按旧语义 /api/<wirePath> 兜底。
 */
export async function resolveCanonical(wirePath: string): Promise<string | null> {
  const current = await ensureCryptoState()
  if (!current || !wirePath) return null
  const segments = wirePath.split('/')
  const template = current.routeMap[segments[0]]
  if (!template) return null
  const extra = segments.slice(1)
  let max = -1
  template.replace(/\{(\d+)\}/g, (_m, n) => {
    max = Math.max(max, Number(n))
    return ''
  })
  if (max + 1 !== extra.length) return null
  return template.replace(/\{(\d+)\}/g, (_m, n) => extra[Number(n)])
}

/**
 * IronWall v1.41.0: 签名 fetch（multipart/二进制下载等不走 axios 的裸接口用）。
 * 403 且带签名要求头时自动重握手并重试一次。
 */
export async function signedFetch(method: string, wirePath: string, init: RequestInit = {}, bodyHash?: string): Promise<Response> {
  const prepare = async (): Promise<{ url: string; headers: Record<string, string> } | null> => {
    try {
      const canonical = (await resolveCanonical(wirePath)) ?? '/api/' + wirePath
      const signed = await signRequest(method, canonical, wirePath, '', bodyHash)
      return { url: '/api/' + signed.url, headers: signed.headers }
    } catch {
      return null
    }
  }
  const prepared = await prepare()
  const doFetch = (p: { url: string; headers: Record<string, string> } | null) => {
    const headers: Record<string, string> = { ...(init.headers as Record<string, string> | undefined) }
    if (p) Object.assign(headers, p.headers)
    return fetch(p ? p.url : '/api/' + wirePath, { ...init, method, headers })
  }
  let resp = await doFetch(prepared)
  if (resp.status === 403 && prepared && resp.headers.get('x-ironwall-sign-required')) {
    const ok = await forceRebootstrap()
    if (ok) {
      const second = await prepare()
      if (second) resp = await doFetch(second)
    }
  }
  return resp
}

export function sha256Text(text: string): Promise<string> {
  return sha256Hex(text)
}
