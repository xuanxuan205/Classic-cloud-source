import { R_ADMIN_ANNOUNCEMENTS, R_ADMIN_ANNOUNCEMENTS_ID, R_ADMIN_DASHBOARD, R_ADMIN_DOWNLOAD_STATS, R_ADMIN_FILES, R_ADMIN_FILES_ID_STATUS, R_ADMIN_LOGS, R_ADMIN_SHARES, R_ADMIN_SHARES_ID_STATUS, R_ADMIN_USERS, R_ADMIN_USERS_ID, R_ADMIN_USERS_ID_UNVERIFY, R_ADMIN_USERS_ID_VERIFY, R_ADMIN_USERS_UNVERIFIED } from '@/utils/routeCodes'
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { request } from '@/utils/axios'

export const useAdminStore = defineStore('admin', () => {
  const stats = ref<{
    totalUsers?: number
    activeUsers?: number
    totalFiles?: number
    todayUploads?: number
    totalShares?: number
    todayShares?: number
    storageUsed?: number
    storageRemaining?: number
    storageTotal?: number
  }>({})

  const users = ref<any[]>([])
  const files = ref<any[]>([])
  const shares = ref<any[]>([])
  const logs = ref<any[]>([])
  const announcements = ref<any[]>([])
  const unverifiedUsers = ref<any[]>([])

  async function getDashboardStats() {
    try {
      const response = await request<typeof stats.value>({ url: R_ADMIN_DASHBOARD, method: 'GET' })
      if (response.success) { stats.value = response.data || {} }
      return response
    } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function getUsers(page: number = 0, size: number = 20, keyword: string = '') {
    try {
      const params: Record<string, any> = { page, size }
      if (keyword) params.keyword = keyword
      const response = await request<{ content: any[]; totalElements: number }>({ url: R_ADMIN_USERS, method: 'GET', params })
      if (response.success) { users.value = response.data?.content || [] }
      return response
    } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function getUnverifiedUsers() {
    try {
      const response = await request<any[]>({ url: R_ADMIN_USERS_UNVERIFIED, method: 'GET' })
      if (response.success) { unverifiedUsers.value = response.data || [] }
      return response
    } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function verifyUser(userId: number, badge?: string) {
    try { return await request({ url: `${R_ADMIN_USERS_ID_VERIFY}/${userId}`, method: 'POST', data: { badge: badge || '已认证' } }) } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function unverifyUser(userId: number) {
    try { return await request({ url: `${R_ADMIN_USERS_ID_UNVERIFY}/${userId}`, method: 'POST' }) } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

async function updateUser(userId: number, updates: Record<string, any>) {
    // IronWall v1.9: 显式转 snake_case，双命名契约不依赖 axios 拦截器
    const data: Record<string, any> = {}
    for (const key of Object.keys(updates)) {
      data[key.replace(/([A-Z])/g, '_$1').toLowerCase()] = updates[key]
    }
    try { return await request({ url: `${R_ADMIN_USERS_ID}/${userId}`, method: 'PUT', data }) } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function banUser(userId: number) {
    try { return await request({ url: `${R_ADMIN_USERS_ID}/${userId}`, method: 'PUT', data: { user_status: 'banned' } }) } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function unbanUser(userId: number) {
    try { return await request({ url: `${R_ADMIN_USERS_ID}/${userId}`, method: 'PUT', data: { user_status: 'active' } }) } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function deleteUser(userId: number) {
    try { return await request({ url: `${R_ADMIN_USERS_ID}/${userId}`, method: 'DELETE' }) } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function getFiles(page: number = 0, size: number = 20, keyword: string = '') {
    try {
      const params: Record<string, any> = { page, size }
      if (keyword) params.keyword = keyword
      const response = await request<{ content: any[]; totalElements: number }>({ url: R_ADMIN_FILES, method: 'GET', params })
      if (response.success) { files.value = response.data?.content || [] }
      return response
    } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function updateFileStatus(fileId: number, status: number) {
    try { return await request({ url: `${R_ADMIN_FILES_ID_STATUS}/${fileId}`, method: 'PUT', data: { status } }) } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function getShares(page: number = 0, size: number = 20, keyword: string = '') {
    try {
      const params: Record<string, any> = { page, size }
      if (keyword) params.keyword = keyword
      const response = await request<{ content: any[]; totalElements: number }>({ url: R_ADMIN_SHARES, method: 'GET', params })
      if (response.success) { shares.value = response.data?.content || [] }
      return response
    } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function updateShareStatus(shareId: number, status: number) {
    try { return await request({ url: `${R_ADMIN_SHARES_ID_STATUS}/${shareId}`, method: 'PUT', data: { status } }) } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function getAnnouncements(page: number = 0, size: number = 20) {
    try {
      const response = await request<{ content: any[]; totalElements: number }>({ url: R_ADMIN_ANNOUNCEMENTS, method: 'GET', params: { page, size } })
      if (response.success) { announcements.value = response.data?.content || [] }
      return response
    } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function createAnnouncement(title: string, content: string, status: string, publishAt?: string) {
    try {
      const data: Record<string, any> = { title, content, status }
      if (publishAt) data.publish_at = publishAt
      return await request({ url: R_ADMIN_ANNOUNCEMENTS, method: 'POST', data })
    } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function updateAnnouncement(id: number, title: string, content: string, status: string, publishAt?: string) {
    try {
      const data: Record<string, any> = { title, content, status }
      if (publishAt) data.publish_at = publishAt
      return await request({ url: `${R_ADMIN_ANNOUNCEMENTS_ID}/${id}`, method: 'PUT', data })
    } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function deleteAnnouncement(id: number) {
    try { return await request({ url: `${R_ADMIN_ANNOUNCEMENTS_ID}/${id}`, method: 'DELETE' }) } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function getLogs(action?: string, userId?: number, keyword?: string, page: number = 0, size: number = 50) {
    try {
      const response = await request<{ content: any[]; totalElements: number; totalPages: number }>({ url: R_ADMIN_LOGS, method: 'GET', params: { action, userId, keyword, page, size } })
      if (response.success) { logs.value = response.data?.content || [] }
      return response
    } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  async function getDownloadStats() {
    try { return await request({ url: R_ADMIN_DOWNLOAD_STATS, method: 'GET' }) } catch (e: any) { return { success: false, message: e?.message || 'error' } }
  }

  return {
    stats, users, files, shares, logs, announcements, unverifiedUsers,
    getDashboardStats, getUsers, getUnverifiedUsers, verifyUser, unverifyUser,
    updateUser, banUser, unbanUser, deleteUser, getFiles, updateFileStatus, getShares, updateShareStatus,
    getAnnouncements, createAnnouncement, updateAnnouncement, deleteAnnouncement,
    getLogs, getDownloadStats
  }
})
