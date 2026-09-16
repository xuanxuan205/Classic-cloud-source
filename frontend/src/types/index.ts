export interface User {
  id: number
  username: string
  email: string
  role: string
  is_official?: boolean
  user_status?: string
  verification_status?: string
  storage_used?: number
  storage_limit?: number
  upload_limit?: number
  created_at?: string
  avatar?: string
  user_code?: string
  verification_badge?: string
}

export interface VipInfo {
  status: string
  type: string
  expires_at: string
}

export interface File {
  id: number
  filename: string
  original_name: string
  file_size: number
  file_type: string
  mime_type: string
  file_hash: string
  folder_id: number
  is_shared: number
  download_count: number
  created_at: string
  status: number
}

export interface Folder {
  id: number
  user_id: number
  name: string
  parent_id: number
  status: number
  created_at: string
  updated_at: string
}

export interface Share {
  id: number
  share_type: number
  file_id: number
  folder_id: number
  share_code: string
  download_limit: number
  download_count: number
  expire_time: string
  status: number
  created_at: string
  has_password?: boolean
  description?: string
  file_name?: string
  file_size?: number
}

export interface ShareInfo extends Share {
  download_sig?: string
  file_name?: string
  folder_name?: string
  file_size?: number
  share_url?: string
  contact?: string
  has_password?: boolean
  verification_badge?: string
  owner_username?: string
  owner_user_code?: string
  owner_avatar?: string
  files?: Array<{ file_id: number; file_name: string; file_size: number }>
}

export interface StorageStats {
  used: number
  limit: number
  upload_limit: number
  total_downloads?: number
  percentage?: number
}

export interface UploadResult {
  id: number
  filename: string
  original_name: string
  file_size: number
  file_type: string
  mime_type: string
  folder_id: number
  download_count: number
  created_at: string
}
export interface NotificationSettings {
  // IronWall v1.47.10: 后端全局 SNAKE_CASE，响应键名为下划线式
  email_notify: boolean
  browser_notify: boolean
  storage_alert: boolean
  share_notify: boolean
}

export interface DeviceInfo {
  id: number
  device: string
  ip: string
  lastLogin: string
}

export interface UpdateEmailRequest {
  email: string
  code: string
}

export interface DeleteAccountRequest {
  password: string
}
