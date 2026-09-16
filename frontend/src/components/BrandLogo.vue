<script setup lang="ts">
import { SITE_NAME } from '@/config/site'
defineProps<{
  size?: number
  withText?: boolean
  showSubtitle?: boolean
}>()
</script>

<template>
  <div class="brand-logo">
    <svg
      :width="size || 40"
      :height="size || 40"
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      :aria-label="SITE_NAME"
    >
      <defs>
        <linearGradient id="classicCloudGradient" x1="8" y1="6" x2="56" y2="58" gradientUnits="userSpaceOnUse">
          <stop stop-color="#60A5FA" />
          <stop offset="0.55" stop-color="#06B6D4" />
          <stop offset="1" stop-color="#8B5CF6" />
        </linearGradient>
      </defs>
      <path
        d="M16.2 33.5C10 33.5 5 28.7 5 22.8 5 17.3 9.2 12.8 14.6 12.1 16.4 6.9 21.4 3 27.4 3c6.7 0 12.2 4.8 13.1 11.1 5.5.5 9.8 5 9.8 10.4 0 5.8-4.7 10.5-10.6 10.5H16.2z"
        fill="url(#classicCloudGradient)"
      />
      <path
        d="M32 17.5l11.6 5.8v10.2c0 7.7-5 13-11.6 15-6.6-2-11.6-7.3-11.6-15V23.3L32 17.5z"
        fill="rgba(255,255,255,0.97)"
        stroke="rgba(255,255,255,0.9)"
        stroke-width="1.2"
      />
      <path
        d="M26.5 33.6l3.8 3.9 7.8-8.4"
        stroke="#2563EB"
        stroke-width="3.2"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
    </svg>

    <div v-if="withText" class="brand-text">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="brand-name">{{ SITE_NAME }}</span>
        <span class="brand-en">CLASSIC CLOUD</span>
      </div>
      <p v-if="showSubtitle" class="brand-sub">安心存储，每一份珍贵</p>
    </div>
  </div>
</template>

<style scoped>
.brand-logo {
  display: inline-flex;
  align-items: center;
  gap: 10px;
}

.brand-name {
  font-weight: 700;
  font-size: 18px;
  color: #fff;
  letter-spacing: 0.02em;
}

.brand-en {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.18em;
  color: rgba(255, 255, 255, 0.5);
  border: 1px solid rgba(255, 255, 255, 0.2);
  padding: 2px 6px;
  border-radius: 999px;
  white-space: nowrap;
}

.brand-sub {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.55);
  margin-top: 2px;
}
</style>
