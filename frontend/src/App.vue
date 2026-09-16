<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { startBlockedGuard, stopBlockedGuard } from '@/utils/blockedGuard'
import GlobalFeedback from '@/components/GlobalFeedback.vue'

const authStore = useAuthStore()

onMounted(() => {
  authStore.loadFromStorage()
  // IronWall v1.18.2: IP 封禁全局守卫——封禁后立即整页跳转专属警示页
  startBlockedGuard()
})

onUnmounted(() => {
  stopBlockedGuard()
})
</script>

<template>
  <router-view />
  <GlobalFeedback />
</template>
