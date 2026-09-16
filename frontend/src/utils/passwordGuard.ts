/**
 * 密码护航安全引擎 - 前端
 * 挑战-应答机制：阻止明文密码在网络上传输
 * 每次请求都不同，抓包无法还原原始密码
 *
 * IronWall v1.28.9 双哈希协议：
 * inner = SHA256("jdy-share:" + shareCode + ":" + password)
 * pw_hash = SHA256(一次性令牌 + inner)
 * 服务端只保存 inner（加盐哈希），不保存明文密码。
 *
 * IronWall v1.46.1: 挑战令牌请求改走签名加密管线（signedFetch + 路由码），
 * 修复 加密层上线后原生 fetch 被 403 拦截导致的「安全引擎初始化失败」。
 */

import { signedFetch } from './apiCrypto'
import { R_SHARES_CHALLENGE_ID } from './routeCodes'

/** 与后端 PasswordGuardService.SHARE_PW_SALT 保持一致 */
const SHARE_PW_SALT = 'jdy-share:'

/**
 * SHA256 哈希（浏览器原生 Web Crypto API）
 */
async function sha256(message: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(message)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * 密码护航：获取挑战令牌并生成安全哈希
 * @param shareCode 分享码
 * @param password 明文密码（仅在内存中存在）
 * @returns { pw_hash, pw_token } 发送给后端的安全凭证
 */
export async function guardPassword(shareCode: string, password: string): Promise<{
  pw_hash: string
  pw_token: string
}> {
  // 1. 从后端获取一次性挑战令牌
  const wirePath = R_SHARES_CHALLENGE_ID.slice(1) + '/' + shareCode
  const response = await signedFetch('GET', wirePath, { headers: { Accept: 'application/json' } })
  if (!response.ok) {
    const err = await response.json().catch(() => ({ message: '获取安全令牌失败' }))
    throw new Error(err.message || '获取安全令牌失败')
  }
  const data = await response.json()
  if (!data.success || !data.data?.token) {
    throw new Error('安全令牌生成失败')
  }

  const token = data.data.token

  // 2. 双哈希：先算加盐哈希，再与一次性令牌组合（密码仅在浏览器内存中，不通过网络传输）
  const inner = await sha256(SHARE_PW_SALT + shareCode + ':' + password)
  const pwHash = await sha256(token + inner)

  return { pw_hash: pwHash, pw_token: token }
}

/**
 * 普通 SHA256（用于其他需要哈希的场景）
 */
export async function sha256Hash(input: string): Promise<string> {
  return sha256(input)
}
