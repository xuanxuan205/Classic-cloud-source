/// <reference types="vite/client" />

/**
 * 站点身份相关环境变量（IronWall v1.48.0）
 * 均为可选：未填写时 src/config/site.ts 会回退到中性默认值。
 */
interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string
  readonly VITE_SITE_NAME?: string
  readonly VITE_SITE_SHORT_NAME?: string
  readonly VITE_SITE_DOMAIN?: string
  readonly VITE_SITE_URL?: string
  readonly VITE_CONTACT_EMAIL?: string
  readonly VITE_CONTACT_QQ_URL?: string
  readonly VITE_RECOMMEND_URL?: string
  readonly VITE_RECOMMEND_TITLE?: string
  readonly VITE_RECOMMEND_DESC?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
