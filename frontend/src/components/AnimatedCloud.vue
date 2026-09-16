<script setup lang="ts">
defineProps<{
  size?: 'small' | 'medium' | 'large'
}>()
</script>

<template>
  <div class="cloud-container" :class="`cloud-${size || 'medium'}`">
    <div class="cloud">
      <div class="cloud-part cloud-part-1"></div>
      <div class="cloud-part cloud-part-2"></div>
      <div class="cloud-part cloud-part-3"></div>
      <div class="cloud-part cloud-part-4"></div>
      <div class="cloud-part cloud-part-5"></div>
      <div class="cloud-shine"></div>
    </div>
    <div class="cloud-shadow"></div>
  </div>
</template>

<style scoped>
.cloud-container {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.cloud-small {
  width: 40px;
  height: 40px;
}

.cloud-medium {
  width: 96px;
  height: 96px;
}

.cloud-large {
  width: 150px;
  height: 150px;
}

.cloud {
  position: relative;
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  animation: cloudFloat 6s ease-in-out infinite;
}

.cloud-part {
  position: absolute;
  border-radius: 50%;
  background: linear-gradient(135deg, rgba(255,255,255,0.9) 0%, rgba(220,230,255,0.8) 50%, rgba(180,200,255,0.7) 100%);
  filter: blur(1px);
  animation: cloudPulse 4s ease-in-out infinite;
}

.cloud-small .cloud-part {
  filter: blur(0.5px);
}

.cloud-large .cloud-part {
  filter: blur(2px);
}

.cloud-part-1 {
  width: 55%;
  height: 55%;
  top: 30%;
  left: 15%;
  animation-delay: 0s;
}

.cloud-part-2 {
  width: 45%;
  height: 45%;
  top: 15%;
  left: 35%;
  animation-delay: 0.5s;
}

.cloud-part-3 {
  width: 40%;
  height: 40%;
  top: 20%;
  left: 55%;
  animation-delay: 1s;
}

.cloud-part-4 {
  width: 35%;
  height: 35%;
  top: 40%;
  left: 50%;
  animation-delay: 1.5s;
}

.cloud-part-5 {
  width: 50%;
  height: 50%;
  top: 35%;
  left: 5%;
  animation-delay: 2s;
}

.cloud-small .cloud-part-1 { width: 55%; height: 55%; }
.cloud-small .cloud-part-2 { width: 45%; height: 45%; }
.cloud-small .cloud-part-3 { width: 40%; height: 40%; }
.cloud-small .cloud-part-4 { width: 35%; height: 35%; }
.cloud-small .cloud-part-5 { width: 50%; height: 50%; }

.cloud-large .cloud-part-1 { width: 55%; height: 55%; }
.cloud-large .cloud-part-2 { width: 45%; height: 45%; }
.cloud-large .cloud-part-3 { width: 40%; height: 40%; }
.cloud-large .cloud-part-4 { width: 35%; height: 35%; }
.cloud-large .cloud-part-5 { width: 50%; height: 50%; }

.cloud-shine {
  position: absolute;
  width: 30%;
  height: 25%;
  top: 25%;
  left: 25%;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(255,255,255,0.9) 0%, transparent 70%);
  animation: shineGlow 3s ease-in-out infinite;
}

.cloud-shadow {
  position: absolute;
  width: 60%;
  height: 10%;
  bottom: -5%;
  border-radius: 50%;
  background: rgba(0,0,0,0.1);
  filter: blur(4px);
  animation: shadowMove 6s ease-in-out infinite;
}

@keyframes cloudFloat {
  0%, 100% {
    transform: translateY(0) rotate(0deg);
  }
  25% {
    transform: translateY(-5px) rotate(1deg);
  }
  50% {
    transform: translateY(0) rotate(0deg);
  }
  75% {
    transform: translateY(-3px) rotate(-1deg);
  }
}

@keyframes cloudPulse {
  0%, 100% {
    transform: scale(1);
    opacity: 0.9;
  }
  50% {
    transform: scale(1.05);
    opacity: 1;
  }
}

@keyframes shineGlow {
  0%, 100% {
    opacity: 0.6;
    transform: scale(1);
  }
  50% {
    opacity: 1;
    transform: scale(1.1);
  }
}

@keyframes shadowMove {
  0%, 100% {
    transform: translateY(0) scaleX(1);
    opacity: 0.3;
  }
  50% {
    transform: translateY(2px) scaleX(0.95);
    opacity: 0.2;
  }
}
</style>
