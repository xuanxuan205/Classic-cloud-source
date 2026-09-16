<script setup lang="ts">
import { SITE_NAME } from '@/config/site'
import AnimatedCloud from './AnimatedCloud.vue'
</script>

<template>
  <div class="min-h-screen relative overflow-hidden flex items-center justify-center p-4">
    <div class="fixed inset-0 z-0">
      <img 
        src="/app-screenshot2.jpg" 
        alt="背景" 
        class="w-full h-full object-cover"
      />
      <div class="absolute inset-0 bg-gradient-to-b from-black/40 via-black/30 to-black/50"></div>
    </div>

    <div class="fixed inset-0 z-0 pointer-events-none">
      <div class="absolute top-20 left-10 w-32 h-32 bg-white/5 rounded-full blur-3xl animate-pulse"></div>
      <div class="absolute top-40 right-20 w-48 h-48 bg-purple-500/10 rounded-full blur-3xl animate-pulse" style="animation-delay: 1s;"></div>
      <div class="absolute bottom-40 left-1/4 w-40 h-40 bg-pink-500/10 rounded-full blur-3xl animate-pulse" style="animation-delay: 2s;"></div>
    </div>

    <div class="relative z-10 bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20 w-full max-w-md p-10 shadow-2xl">
      <div class="text-center mb-10">
        <div class="inline-flex items-center justify-center mb-4">
          <AnimatedCloud size="large" />
        </div>
        <h1 class="text-3xl font-bold text-white mb-2">{{ SITE_NAME }}</h1>
        <p class="text-white/60">Classic Cloud</p>
      </div>

      <slot />
    </div>
  </div>
</template>
