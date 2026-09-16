// IronWall v1.28.16: 浏览器设备指纹
// 由 Canvas / WebGL / 屏幕 / 时区 / UA 等匿名硬件信号经 SHA-256 合成，
// 仅作设备身份标识（不含任何个人信息、不追踪跨站行为）。
// 攻击触发 IP 封禁时后端会同步锁定该指纹：更换代理 IP 依旧被拦截；
// 正常用户、以及 4G/5G 共用出口 IP 的其他设备完全不受影响。

import { SITE_SHORT_NAME } from '@/config/site'

let cached: string | null = null

function canvasNoise(): string {
  try {
    const canvas = document.createElement('canvas')
    canvas.width = 240
    canvas.height = 60
    const ctx = canvas.getContext('2d')
    if (!ctx) return ''
    ctx.textBaseline = 'top'
    ctx.font = '14px "Arial"'
    ctx.fillStyle = '#f60'
    ctx.fillRect(100, 2, 60, 20)
    ctx.fillStyle = '#069'
    ctx.fillText(`IronWall-FP ${SITE_SHORT_NAME}`, 2, 17)
    ctx.fillStyle = 'rgba(102,204,0,0.7)'
    ctx.fillText('安全引擎', 4, 33)
    return canvas.toDataURL()
  } catch {
    return ''
  }
}

function webglNoise(): string {
  try {
    const canvas = document.createElement('canvas')
    const gl = canvas.getContext('webgl') as WebGLRenderingContext | null
    if (!gl) return ''
    const ext = gl.getExtension('WEBGL_debug_renderer_info')
    const vendor = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR)
    const renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER)
    return String(vendor) + '|' + String(renderer)
  } catch {
    return ''
  }
}

function rawSignals(): string {
  const nav = navigator as any
  return [
    nav.userAgent || '',
    nav.language || '',
    (nav.languages || []).join(','),
    nav.platform || '',
    nav.hardwareConcurrency ?? '',
    nav.deviceMemory ?? '',
    String(nav.maxTouchPoints ?? ''),
    screen.width + 'x' + screen.height + 'x' + (screen.colorDepth ?? '') + 'x' + (window.devicePixelRatio ?? ''),
    String(new Date().getTimezoneOffset()),
    (Intl.DateTimeFormat().resolvedOptions().timeZone) || '',
    canvasNoise(),
    webglNoise(),
  ].join('||')
}

function fallbackHash(raw: string): string {
  // 非安全上下文（crypto.subtle 不可用）时的 FNV-1a 回退，补齐 64 位 hex 格式
  let h = 2166136261
  for (let i = 0; i < raw.length; i++) {
    h ^= raw.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return ((h >>> 0).toString(16).padStart(8, '0') + (raw.length >>> 0).toString(16).padStart(8, '0'))
    .padEnd(64, '0')
    .slice(0, 64)
}

export async function getDeviceFingerprint(): Promise<string> {
  if (cached) return cached
  const raw = rawSignals()
  try {
    if (window.crypto?.subtle) {
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw))
      cached = Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
    } else {
      cached = fallbackHash(raw)
    }
  } catch {
    cached = fallbackHash(raw)
  }
  // 镜像到 Cookie：覆盖页面加载 / 表单提交等非 XHR 请求，供服务端读取
  try {
    const secure = window.location.protocol === 'https:' ? '; Secure' : ''
    document.cookie = `iw_fp=${cached}; Max-Age=31536000; Path=/; SameSite=Lax${secure}`
  } catch {
    // Cookie 不可写时仅使用请求头
  }
  return cached
}
