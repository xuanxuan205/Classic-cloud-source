/**
 * 站点身份配置（IronWall v1.48.0）
 *
 * 站点身份信息全部通过环境变量提供。请复制 .env.example 为 .env，
 * 填好下列字段后再构建：
 *
 * VITE_SITE_NAME 站点全称，例如「我的网盘」
 * VITE_SITE_SHORT_NAME 站点简称，用于标题与指纹盐
 * VITE_STUDIO_NAME 出品方署名，例如「你的工作室」；留空则页脚不显示署名
 * VITE_SITE_DOMAIN 你的域名，不含协议
 * VITE_SITE_URL 站点完整地址，留空则由域名推导
 * VITE_CONTACT_EMAIL 对外联系邮箱
 * VITE_CONTACT_QQ_URL 官方 QQ 加好友链接
 * VITE_RECOMMEND_URL 首页推荐卡片链接，留空则整块不显示
 * VITE_RECOMMEND_TITLE 推荐卡片标题
 * VITE_RECOMMEND_DESC 推荐卡片描述
 *
 * 未填写时回退到中性默认值，站点仍可正常构建与运行。
 */

const env = import.meta.env

function text(value: unknown, fallback: string): string {
  const v = typeof value === 'string' ? value.trim() : ''
  return v || fallback
}

/** 站点全称 */
export const SITE_NAME = text(env.VITE_SITE_NAME, '经典云网盘')

/** 站点简称 */
export const SITE_SHORT_NAME = text(env.VITE_SITE_SHORT_NAME, '经典云')

/** 出品方署名；留空则相关页面的署名区块整块隐藏 */
export const STUDIO_NAME = text(env.VITE_STUDIO_NAME, '')

/** 站点域名（不含协议） */
export const SITE_DOMAIN = text(env.VITE_SITE_DOMAIN, '')

/** 站点完整地址 */
export const SITE_URL = text(
  env.VITE_SITE_URL,
  SITE_DOMAIN ? `https://${SITE_DOMAIN}`: ''
)

/** 对外联系邮箱；未配置时显示中性占位，提醒部署者替换 */
export const CONTACT_EMAIL = text(env.VITE_CONTACT_EMAIL, 'support@example.com')

/** 官方 QQ 加好友链接；留空则隐藏 QQ 入口 */
export const CONTACT_QQ_URL = text(env.VITE_CONTACT_QQ_URL, '')

/** 首页友情推荐卡片；链接留空则整块不渲染 */
export const RECOMMEND_URL = text(env.VITE_RECOMMEND_URL, '')
export const RECOMMEND_TITLE = text(env.VITE_RECOMMEND_TITLE, '想搭一个属于自己的网站？')
export const RECOMMEND_DESC = text(
  env.VITE_RECOMMEND_DESC,
  '这里可以放你自己的推荐内容：配置 VITE_RECOMMEND_* 即可。'
)

/** 推荐卡片是否显示 */
export const RECOMMEND_ENABLED = RECOMMEND_URL !== ''

/** 邮箱 mailto 链接 */
export const CONTACT_MAILTO = `mailto:${CONTACT_EMAIL}`
