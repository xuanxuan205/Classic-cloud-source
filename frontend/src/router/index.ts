import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  history: createWebHistory(),
  scrollBehavior(to, _from, savedPosition) {
    if (savedPosition) return savedPosition
    if (to.hash) return { el: to.hash, behavior: 'smooth' }
    return { top: 0 }
  },
  routes: [
    {
      path: '/',
      name: 'Home',
      component: () => import('@/views/Home.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/login',
      name: 'Login',
      component: () => import('@/views/auth/Login.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/register',
      name: 'Register',
      component: () => import('@/views/auth/Register.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/forgot-password',
      name: 'ForgotPassword',
      component: () => import('@/views/auth/ForgotPassword.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/dashboard',
      name: 'Dashboard',
      component: () => import('@/views/Dashboard.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/files',
      name: 'Files',
      component: () => import('@/views/files/Files.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/shares',
      name: 'Shares',
      component: () => import('@/views/shares/Shares.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/recycle',
      name: 'RecycleBin',
      component: () => import('@/views/files/RecycleBin.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/profile',
      name: 'Profile',
      component: () => import('@/views/user/Profile.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/admin',
      name: 'AdminDashboard',
      component: () => import('@/views/admin/AdminDashboard.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/admin/users',
      name: 'AdminUsers',
      component: () => import('@/views/admin/AdminUsers.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/admin/announcements',
      name: 'AdminAnnouncements',
      component: () => import('@/views/admin/AdminAnnouncements.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/admin/smtp',
      name: 'AdminSMTP',
      component: () => import('@/views/admin/AdminSMTP.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/admin/verification',
      name: 'AdminVerification',
      component: () => import('@/views/admin/AdminVerification.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/admin/files',
      name: 'AdminFiles',
      component: () => import('@/views/admin/AdminFiles.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/admin/shares',
      name: 'AdminShares',
      component: () => import('@/views/admin/AdminShares.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/admin/upload-limit',
      name: 'AdminUploadLimit',
      component: () => import('@/views/admin/AdminUploadLimit.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/admin/download-stats',
      name: 'AdminDownloadStats',
      component: () => import('@/views/admin/AdminDownloadStats.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/admin/settings',
      name: 'AdminSettings',
      component: () => import('@/views/admin/AdminSettings.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },{
      path: '/admin/logs',
      name: 'AdminLogs',
      component: () => import('@/views/admin/AdminLogs.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/admin/security',
      name: 'AdminSecurity',
      component: () => import('@/views/admin/AdminSecurity.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/admin/appeals',
      name: 'AdminAppeals',
      component: () => import('@/views/admin/AdminAppeals.vue'),
      meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
      path: '/share/:code',
      name: 'SharePublic',
      component: () => import('@/views/shares/SharePublic.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/help',
      name: 'HelpCenter',
      component: () => import('@/views/HelpCenter.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/about',
      name: 'About',
      component: () => import('@/views/About.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/contact',
      name: 'Contact',
      component: () => import('@/views/Contact.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/terms',
      name: 'Terms',
      component: () => import('@/views/Terms.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/privacy',
      name: 'Privacy',
      component: () => import('@/views/Privacy.vue'),
      meta: { requiresAuth: false }
    },
    {
      path: '/system',
      name: 'System',
      component: () => import('@/views/SystemInfo.vue'),
      meta: { requiresAuth: false }
    }
  ]
})

router.beforeEach(async (to, _from, next) => {
  const authStore = useAuthStore()
  
  if (to.meta.requiresAuth && !authStore.isLoggedIn) {
    next({ name: 'Login', query: { redirect: to.fullPath } })
  } else if (to.meta.requiresAdmin && !(authStore.user?.role === 'admin' || authStore.user?.is_official)) {
    next({ name: 'Dashboard' })
  } else if (to.name === 'Login' && authStore.isLoggedIn) {
    next({ name: 'Dashboard' })
  } else {
    next()
  }
})

export default router
