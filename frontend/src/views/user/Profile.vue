<script setup lang="ts">
import { R_AUTH_2FA_STATUS, R_AUTH_2FA_SETUP, R_AUTH_2FA_CONFIRM, R_AUTH_2FA_DISABLE } from '@/utils/routeCodes'

import { ref, onMounted, computed } from "vue"
import { useRouter } from "vue-router"
import { useAuthStore } from "@/stores/auth"
import { useFilesStore } from "@/stores/files"
import { request } from "@/utils/axios"
import { browserNotifySupported, browserNotifyPermission, enableBrowserNotify, setBrowserNotifyEnabledLocal } from "@/utils/browserNotify"
import QRCode from "qrcode"
import Layout from "@/components/Layout.vue"
import { showToast, confirmDialog } from "@/composables/useGlobalFeedback"
import { User, Mail, Shield, Cloud, Camera, Eye, EyeOff, Lock, X, Upload, AlertTriangle, Monitor, Loader2, Smartphone, Bell, Laptop, Tablet, HardDrive, Key, Trash2, Check, Clock, Globe, Zap, Wifi, CheckCircle, Copy, ShieldCheck, Fingerprint } from "lucide-vue-next"

const router = useRouter()
const authStore = useAuthStore()
const filesStore = useFilesStore()



const storageUsed = computed(() => filesStore.stats?.used ?? (authStore.user as any)?.storage_used ?? 0)
const storageLimit = computed(() => filesStore.stats?.limit ?? (authStore.user as any)?.storage_limit ?? 314572800)
const storagePercent = computed(() => storageLimit.value > 0 ? Math.min((storageUsed.value / storageLimit.value) * 100, 100) : 0)
const isAdmin = computed(() => authStore.user?.role === 'admin')
const storageFree = computed(() => Math.max(storageLimit.value - storageUsed.value, 0))

// Display UID - use stored user_code from backend (fixed after registration)
const displayUid = computed(() => {
  return authStore.user?.user_code || String(authStore.user?.id || 10000).padStart(5, '0')
})

// Avatar cache-busting key
const avatarKey = ref(0)
const avatarUrl = computed(() => {
  const base = authStore.user?.avatar
  if (!base) return ''
  const sep = base.includes('?') ? '&' : '?'
  return base + sep + '_t=' + avatarKey.value
})

// Copy full user ID
const copiedUid = ref(false)
async function copyUid() {
  const uid = displayUid.value
  try {
    await navigator.clipboard.writeText(uid)
    copiedUid.value = true
    setTimeout(() => { copiedUid.value = false }, 1500)
    showToast("用户 ID 已复制", "success")
  } catch {
    showToast("复制失败，请手动复制", "error")
  }
}

// ============ Change Email ============
const showEmailModal = ref(false)
const newEmail = ref("")
const emailCode = ref("")
const emailSending = ref(false)
const emailCountdown = ref(0)
const emailSaving = ref(false)
let emailTimer: any = null

function startCountdown() { emailCountdown.value=60; emailSending.value=true; emailTimer=setInterval(()=>{ emailCountdown.value--; if(emailCountdown.value<=0){clearInterval(emailTimer); emailSending.value=false} },1000) }

async function sendEmailCode() {
  if(!newEmail.value) return showToast("请输入新邮箱", "error")
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail.value)) return showToast("请输入有效邮箱", "error")
  emailSending.value=true
  try { const r=await authStore.sendEmailCode(newEmail.value); if(r.success) { startCountdown(); showToast("验证码已发送", "success") } else { showToast(r.message||"发送失败", "error"); emailSending.value=false } }
  catch(e:any){ showToast("发送失败", "error"); emailSending.value=false }
}

async function saveEmail() {
  if(!newEmail.value||!emailCode.value) return showToast("请填写完整", "error")
  emailSaving.value=true
  try { const r=await authStore.updateEmail(newEmail.value,emailCode.value); if(r.success){ showToast("邮箱修改成功", "success"); showEmailModal.value=false; newEmail.value=""; emailCode.value=""; clearInterval(emailTimer); emailSending.value=false; await authStore.getUserInfo() } else showToast(r.message||"修改失败", "error") }
  catch(e:any){ showToast("修改失败", "error") }
  emailSaving.value=false
}

// ============ Change Avatar ============
const showAvatarModal = ref(false)
const avatarFile = ref<File|null>(null)
const avatarPreview = ref("")
const avatarUploading = ref(false)

function pickAvatar(e:Event){ const t=(e.target as HTMLInputElement).files?.[0]; if(!t) return; if(!t.type.startsWith("image/")) return showToast("请选择图片", "error"); if(t.size>5*1024*1024) return showToast("图片不超过5MB", "error"); avatarFile.value=t; const r=new FileReader(); r.onload=e=>avatarPreview.value=e.target?.result as string; r.readAsDataURL(t) }

async function uploadAvatar(){ if(!avatarFile.value) return; avatarUploading.value=true; try { const r=await authStore.uploadAvatar(avatarFile.value); if(r.success){ showToast("头像已更新", "success"); showAvatarModal.value=false; avatarFile.value=null; avatarPreview.value=""; avatarKey.value++; await authStore.getUserInfo(); avatarKey.value++ } else showToast(r.message||"上传失败", "error") } catch(e:any){ showToast("上传失败", "error") }; avatarUploading.value=false }

// ============ Change Password ============
const showPasswordModal = ref(false)
const oldPwd = ref(""); const newPwd = ref(""); const confirmPwd = ref("")
const showOld = ref(false); const showNew = ref(false); const showConfirm = ref(false)
const pwdSaving = ref(false)

const pwdStrength = computed(()=>{ const p=newPwd.value; if(!p) return {l:0,label:"",color:"",pct:0}; let s=0; if(p.length>=8)s++; if(p.length>=12)s++; if(/[a-z]/.test(p))s++; if(/[A-Z]/.test(p))s++; if(/[0-9]/.test(p))s++; if(/[^a-zA-Z0-9]/.test(p))s++; if(s<=2) return {l:1,label:"弱",color:"bg-red-500",pct:25}; if(s<=4) return {l:2,label:"中",color:"bg-yellow-500",pct:60}; return {l:3,label:"强",color:"bg-green-500",pct:100} })

async function changePassword(){ if(!oldPwd.value||!newPwd.value||!confirmPwd.value) return showToast("请填写完整", "error"); if(newPwd.value!==confirmPwd.value) return showToast("两次密码不一致", "error"); if(pwdStrength.value.l<2) return showToast("密码强度不够", "error"); pwdSaving.value=true; try { const ok=await authStore.changePassword(oldPwd.value,newPwd.value); if(ok){ showToast("密码已修改，请重新登录", "success"); setTimeout(()=>{ showPasswordModal.value=false; oldPwd.value=""; newPwd.value=""; confirmPwd.value=""; authStore.logout(); router.push("/login") }, 1000) } else showToast("旧密码错误", "error") } catch(e:any){ showToast("修改失败", "error") }; pwdSaving.value=false }

// ============ Delete Account ============
const showDeleteModal = ref(false)
const deleteText = ref(""); const deletePwd = ref(""); const deleteLoading = ref(false)

async function deleteAccount(){ if(deleteText.value!=="确认注销") return showToast('请输入"确认注销"', 'error'); if(!deletePwd.value) return showToast("请输入密码", "error"); deleteLoading.value=true; try { const r=await authStore.deleteAccount(deletePwd.value); if(r.success){ showToast("账号已注销", "success"); router.push("/login") } else showToast(r.message||"注销失败", "error") } catch(e:any){ showToast("注销失败", "error") }; deleteLoading.value=false }

// ============ Devices ============
const showDeviceModal = ref(false)
const devices = ref<any[]>([])
const deviceLoading = ref(false)

function deviceType(ua:string):string{ if(!ua) return "desktop"; const l=ua.toLowerCase(); if(/iphone|ipad|ipod/.test(l)) return "apple"; if(/android/.test(l)) return "android"; if(/mobile/.test(l)) return "phone"; if(/tablet/.test(l)) return "tablet"; return "desktop" }
function deviceIcon(t:string){ switch(t){ case "apple": case "android": case "phone": return Smartphone; case "tablet": return Tablet; default: return Monitor } }
function shortDevice(d:string):string{ if(!d) return "未知"; const m:string[]=[]; if(d.includes("Edg")) m.push("Edge"); else if(d.includes("Chrome")) m.push("Chrome"); else if(d.includes("Firefox")) m.push("Firefox"); else if(d.includes("Safari")) m.push("Safari"); if(d.includes("Windows")) m.push("Win"); else if(d.includes("Mac")) m.push("Mac"); else if(d.includes("Linux")) m.push("Linux"); else if(d.includes("Android")) m.push("Android"); else if(d.includes("iPhone")||d.includes("iPad")) m.push("iOS"); return m.length>0?m.join(" · "):d.substring(0,50) }

async function loadDevices(){ deviceLoading.value=true; try { const d=await authStore.getDevices(); devices.value=(d||[]).map((x:any)=>({...x,deviceType:deviceType(x.device||"")})) } catch(e:any){}; deviceLoading.value=false }
async function revokeDevice(id:number){ if(!await confirmDialog("撤销此设备？")) return; try { await authStore.revokeDevice(id); devices.value=devices.value.filter(d=>d.id!==id); showToast("设备已撤销", "success") } catch(e:any){ showToast("撤销失败", "error") } }

// ============ Two-Factor Auth (IronWall v1.28.0) ============
const twoFaEnabled = ref(false)
const twoFaBoundAt = ref("")
const showTwoFaModal = ref(false)
const twoFaSetupMode = ref(false)
const twoFaSecret = ref("")
const twoFaOtpAuthUri = ref("")
const twoFaQrDataUrl = ref("")
const twoFaCode = ref("")
const twoFaBusy = ref(false)
const twoFaDisableMode = ref(false)
const twoFaDisablePwd = ref("")
const twoFaDisableCode = ref("")

async function loadTwoFa(){ try { const r = await request<{enabled:boolean;bound_at:string;has_pending:boolean}>({url: R_AUTH_2FA_STATUS, method:"GET"}); if (r.success && r.data) { twoFaEnabled.value = !!r.data.enabled; twoFaBoundAt.value = r.data.bound_at || "" } } catch(e:any){} }
async function openTwoFaModal(){ twoFaSetupMode.value=false; twoFaDisableMode.value=false; twoFaCode.value=""; twoFaDisablePwd.value=""; twoFaDisableCode.value=""; twoFaBusy.value=false; await loadTwoFa(); showTwoFaModal.value=true }
async function startTwoFaSetup(){ twoFaBusy.value=true; try { const r = await request<{secret:string;otpauth_uri:string}>({url: R_AUTH_2FA_SETUP, method:"POST"}); if (r.success && r.data) { twoFaSecret.value=r.data.secret; twoFaOtpAuthUri.value=r.data.otpauth_uri; twoFaSetupMode.value=true; try { twoFaQrDataUrl.value=await QRCode.toDataURL(r.data.otpauth_uri,{width:180,margin:1}) } catch(e:any){} } else showToast(r.message||"生成失败", "error") } catch(e:any){ showToast("生成失败", "error") }; twoFaBusy.value=false }
async function confirmTwoFa(){ const code=twoFaCode.value.trim(); if(!/^\d{6}$/.test(code)) return showToast("请输入 6 位动态验证码", "error"); twoFaBusy.value=true; try { const r=await request({url: R_AUTH_2FA_CONFIRM, method:"POST", data:{code}}); if(r.success){ showToast("两步验证已开启", "success"); await loadTwoFa(); twoFaSetupMode.value=false; twoFaSecret.value=""; twoFaOtpAuthUri.value=""; twoFaQrDataUrl.value="" } else showToast(r.message||"验证码错误", "error") } catch(e:any){ showToast("验证失败", "error") }; twoFaBusy.value=false }
async function disableTwoFa(){ if(!twoFaDisablePwd.value) return showToast("请输入登录密码", "error"); if(!/^\d{6}$/.test(twoFaDisableCode.value.trim())) return showToast("请输入验证器 App 中的 6 位动态验证码", "error"); twoFaBusy.value=true; try { const r=await request({url: R_AUTH_2FA_DISABLE, method:"POST", data:{password:twoFaDisablePwd.value, code:twoFaDisableCode.value.trim()}}); if(r.success){ showToast("两步验证已关闭", "success"); twoFaEnabled.value=false; twoFaDisableMode.value=false; twoFaDisablePwd.value=""; twoFaDisableCode.value="" } else showToast(r.message||"密码或动态验证码错误", "error") } catch(e:any){ showToast("关闭失败", "error") }; twoFaBusy.value=false }
function copyTwoFaSecret(){ navigator.clipboard && navigator.clipboard.writeText(twoFaSecret.value).catch(()=>{}); showToast("密钥已复制", "success") }
// ============ Notifications ============
// IronWall v1.47.10: 与后端 SNAKE_CASE 响应键名保持一致，修复开关读了永远变默认值的 bug
const notify = ref({ email_notify:true, browser_notify:true, storage_alert:true, share_notify:false })
const notifySaving = ref(false)

async function loadNotify(){
  try {
    const r = await authStore.getNotificationSettings()
    if (r.success && r.data) {
      notify.value = {
        email_notify: r.data.email_notify ?? true,
        browser_notify: r.data.browser_notify ?? true,
        storage_alert: r.data.storage_alert ?? true,
        share_notify: r.data.share_notify ?? false
      }
      setBrowserNotifyEnabledLocal(notify.value.browser_notify && browserNotifyPermission() === 'granted')
    }
  } catch { /* 读取失败保持默认显示，用户仍可重新保存 */ }
}

// IronWall v1.47.10: 开启浏览器通知必须真正拿到权限，拿不到就保持关闭
async function toggleBrowserNotify(){
  if (notify.value.browser_notify) {
    notify.value.browser_notify = false
    setBrowserNotifyEnabledLocal(false)
    return
  }
  if (!browserNotifySupported()) {
    showToast("当前浏览器不支持通知", "error")
    return
  }
  const granted = await enableBrowserNotify()
  if (!granted) {
    notify.value.browser_notify = false
    setBrowserNotifyEnabledLocal(false)
    showToast("浏览器通知权限未授权，请在浏览器设置中允许后重试", "error")
    return
  }
  notify.value.browser_notify = true
  setBrowserNotifyEnabledLocal(true)
}

async function saveNotify(){
  notifySaving.value = true
  try {
    const r = await authStore.updateNotificationSettings(notify.value)
    // IronWall v1.47.10: 拦截器会把失败响应解析返回，必须判 success，否则失败也提示“已保存”
    if (r && r.success) {
      setBrowserNotifyEnabledLocal(notify.value.browser_notify && browserNotifyPermission() === 'granted')
      showToast("已保存", "success")
    } else {
      showToast((r && r.message) || "保存失败", "error")
    }
  } catch (e:any) {
    showToast("保存失败", "error")
  }
  notifySaving.value = false
}

function fmtSize(b:number):string{ if(!b) return "0 B"; const k=1024,s=["B","KB","MB","GB","TB"]; const i=Math.floor(Math.log(b)/Math.log(k)); return parseFloat((b/Math.pow(k,i)).toFixed(2))+" "+s[i] }
function fmtDate(s:string):string{ if(!s) return ""; return new Date(s).toLocaleString("zh-CN") }

onMounted(async ()=>{
  try { await filesStore.getStorageStats() } catch{}
  loadNotify()
})
</script>

<template>
<Layout>

<div class="p-3 sm:p-4 md:p-6 xl:p-8 w-full space-y-4 sm:space-y-5 xl:space-y-6">

  <!-- ====== HERO ====== -->
  <div class="relative overflow-hidden rounded-2xl xl:rounded-3xl bg-gradient-to-br from-indigo-600 via-purple-600 to-pink-500 p-5 sm:p-6 md:p-8 xl:p-10">
    <div class="absolute top-0 right-0 w-48 sm:w-64 xl:w-80 h-48 sm:h-64 xl:h-80 bg-white/5 rounded-full -translate-y-1/2 translate-x-1/4"></div>
    <div class="absolute bottom-0 left-1/2 w-72 sm:w-96 xl:w-[32rem] h-72 sm:h-96 xl:h-[32rem] bg-white/5 rounded-full translate-y-1/2"></div>
    <div class="absolute inset-0 opacity-[0.06]" style="background-image:linear-gradient(#fff 1px,transparent 1px),linear-gradient(90deg,#fff 1px,transparent 1px);background-size:28px 28px;"></div>
    <div class="relative flex flex-col md:flex-row md:items-center gap-4 sm:gap-6 xl:gap-8">
      <div class="flex items-center gap-4 sm:gap-6 xl:gap-8 min-w-0 flex-1">
        <div class="relative group cursor-pointer shrink-0" @click="showAvatarModal=true">
          <div class="w-16 h-16 sm:w-20 sm:h-20 xl:w-24 xl:h-24 2xl:w-28 2xl:h-28 rounded-2xl xl:rounded-3xl bg-white/20 backdrop-blur flex items-center justify-center overflow-hidden ring-2 ring-white/30">
            <img v-if="avatarUrl" :src="avatarUrl" class="w-full h-full object-cover" />
            <User v-else class="w-7 h-7 sm:w-9 sm:h-9 xl:w-11 xl:h-11 text-white/70" />
          </div>
          <div class="absolute -bottom-1 -right-1 w-6 h-6 sm:w-7 sm:h-7 xl:w-8 xl:h-8 bg-white rounded-full flex items-center justify-center shadow-lg">
            <Camera class="w-3 h-3 sm:w-3.5 sm:h-3.5 xl:w-4 xl:h-4 text-indigo-600" />
          </div>
        </div>
        <div class="text-white min-w-0">
          <div class="flex items-center gap-2 flex-wrap">
            <h1 class="text-lg sm:text-xl md:text-2xl xl:text-3xl 2xl:text-4xl font-bold truncate">{{ authStore.user?.username }}</h1>
            <span v-if="authStore.user?.role==='admin'" class="px-2 py-0.5 bg-red-500/30 text-red-100 rounded-full text-xs xl:text-sm font-medium ring-1 ring-white/20">官方管理员</span>
            <span v-else class="px-2 py-0.5 bg-emerald-400/25 text-emerald-100 rounded-full text-xs xl:text-sm font-medium ring-1 ring-white/20">尊享用户</span>
          </div>
          <p class="text-white/70 text-xs sm:text-sm xl:text-base mt-0.5 truncate flex items-center gap-1.5"><Mail class="w-3.5 h-3.5 xl:w-4 xl:h-4 shrink-0" />{{ authStore.user?.email }}</p>
          <div class="flex items-center gap-3 sm:gap-4 mt-1.5 sm:mt-2 text-white/60 text-xs xl:text-sm flex-wrap">
            <span class="flex items-center gap-1"><ShieldCheck class="w-3.5 h-3.5 xl:w-4 xl:h-4" />{{ (authStore.user?.role==='admin' || authStore.user?.verification_status==='verified')?'已认证':'未认证' }}</span>
            <span class="flex items-center gap-1">ID: <b class="text-white/90 font-mono">{{ displayUid }}</b></span>
            <span class="hidden sm:inline">注册于 {{ fmtDate(authStore.user?.created_at||"") }}</span>
          </div>
        </div>
      </div>
      <div class="flex md:flex-col gap-2 shrink-0">
        <button @click="showAvatarModal=true" class="px-3.5 py-2 bg-white/15 hover:bg-white/25 backdrop-blur rounded-xl text-white text-xs xl:text-sm font-medium transition-colors flex items-center justify-center gap-1.5 ring-1 ring-white/20"><Camera class="w-3.5 h-3.5 xl:w-4 xl:h-4" />更换头像</button>
        <button @click="showPasswordModal=true" class="px-3.5 py-2 bg-white/15 hover:bg-white/25 backdrop-blur rounded-xl text-white text-xs xl:text-sm font-medium transition-colors flex items-center justify-center gap-1.5 ring-1 ring-white/20"><Key class="w-3.5 h-3.5 xl:w-4 xl:h-4" />修改密码</button>
      </div>
    </div>
  </div>

  <!-- ====== STATS ROW ====== -->
  <div class="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-3 xl:gap-4">
    <div class="group bg-slate-800/50 rounded-xl border border-slate-700/30 p-3 sm:p-4 xl:p-5 hover:border-amber-500/40 hover:bg-slate-800/70 transition-all">
      <div class="w-8 h-8 sm:w-9 sm:h-9 xl:w-10 xl:h-10 rounded-lg bg-amber-500/10 flex items-center justify-center mb-2 sm:mb-3 group-hover:scale-110 transition-transform">
        <Zap class="w-4 h-4 sm:w-5 sm:h-5 xl:w-6 xl:h-6 text-amber-400" />
      </div>
      <p class="text-lg sm:text-xl xl:text-2xl font-bold text-white">{{ fmtSize(storageUsed) }}</p>
      <p class="text-slate-500 text-xs xl:text-sm">已用存储</p>
    </div>
    <div class="group bg-slate-800/50 rounded-xl border border-slate-700/30 p-3 sm:p-4 xl:p-5 hover:border-blue-500/40 hover:bg-slate-800/70 transition-all">
      <div class="w-8 h-8 sm:w-9 sm:h-9 xl:w-10 xl:h-10 rounded-lg bg-blue-500/10 flex items-center justify-center mb-2 sm:mb-3 group-hover:scale-110 transition-transform">
        <HardDrive class="w-4 h-4 sm:w-5 sm:h-5 xl:w-6 xl:h-6 text-blue-400" />
      </div>
      <p class="text-lg sm:text-xl xl:text-2xl font-bold text-white">{{ isAdmin ? "无限" : fmtSize(storageLimit) }}</p>
      <p class="text-slate-500 text-xs xl:text-sm">总空间</p>
    </div>
    <div class="group bg-slate-800/50 rounded-xl border border-slate-700/30 p-3 sm:p-4 xl:p-5 hover:border-green-500/40 hover:bg-slate-800/70 transition-all">
      <div class="w-8 h-8 sm:w-9 sm:h-9 xl:w-10 xl:h-10 rounded-lg bg-green-500/10 flex items-center justify-center mb-2 sm:mb-3 group-hover:scale-110 transition-transform">
        <Globe class="w-4 h-4 sm:w-5 sm:h-5 xl:w-6 xl:h-6 text-green-400" />
      </div>
      <p class="text-lg sm:text-xl xl:text-2xl font-bold text-white">{{ isAdmin ? "—" : (storagePercent.toFixed(1) + "%") }}</p>
      <p class="text-slate-500 text-xs xl:text-sm">使用率</p>
    </div>
    <div class="group bg-slate-800/50 rounded-xl border border-slate-700/30 p-3 sm:p-4 xl:p-5 hover:border-purple-500/40 hover:bg-slate-800/70 transition-all">
      <div class="w-8 h-8 sm:w-9 sm:h-9 xl:w-10 xl:h-10 rounded-lg bg-purple-500/10 flex items-center justify-center mb-2 sm:mb-3 group-hover:scale-110 transition-transform">
        <ShieldCheck class="w-4 h-4 sm:w-5 sm:h-5 xl:w-6 xl:h-6 text-purple-400" />
      </div>
      <p class="text-lg sm:text-xl xl:text-2xl font-bold text-white">{{ (authStore.user?.role==='admin' || authStore.user?.verification_status==='verified')?'已认证':'未认证' }}</p>
      <p class="text-slate-500 text-xs xl:text-sm">认证状态</p>
    </div>
  </div>

  <!-- ====== MAIN GRID ====== -->
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-5 xl:gap-6">

    <!-- ====== LEFT COLUMN ====== -->
    <div class="lg:col-span-2 space-y-4 sm:space-y-5 xl:space-y-6">

      <!-- PERSONAL INFO -->
      <section class="bg-slate-800/40 rounded-2xl xl:rounded-3xl border border-slate-700/30 overflow-hidden">
        <div class="px-4 sm:px-6 xl:px-8 py-3 sm:py-4 border-b border-slate-700/30 flex items-center gap-2">
          <User class="w-4 h-4 sm:w-5 sm:h-5 text-indigo-400" />
          <h2 class="text-white font-semibold text-sm sm:text-base xl:text-lg">个人信息</h2>
        </div>
        <div class="p-4 sm:p-6 xl:p-8 grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
          <div>
            <label class="text-slate-500 text-xs xl:text-sm mb-1 block">用户名</label>
            <input :value="authStore.user?.username" disabled class="w-full bg-slate-700/30 border border-slate-600/30 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 text-white/60 text-sm xl:text-base cursor-not-allowed" />
          </div>
          <div>
            <label class="text-slate-500 text-xs xl:text-sm mb-1 block">邮箱地址</label>
            <div class="flex gap-2">
              <input :value="authStore.user?.email" disabled class="flex-1 bg-slate-700/30 border border-slate-600/30 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 text-white/60 text-sm xl:text-base cursor-not-allowed" />
              <button @click="showEmailModal=true" class="px-3 sm:px-4 py-2 sm:py-2.5 bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-400 rounded-lg text-xs sm:text-sm transition-colors flex items-center gap-1 shrink-0">
                <Mail class="w-3.5 h-3.5 sm:w-4 sm:h-4" />修改
              </button>
            </div>
          </div>
          <div>
            <label class="text-slate-500 text-xs xl:text-sm mb-1 block">用户 ID</label>
            <div class="flex gap-2">
              <input :value="displayUid" disabled class="flex-1 bg-slate-700/30 border border-slate-600/30 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 text-white/60 text-sm xl:text-base cursor-not-allowed font-mono" />
              <button @click="copyUid" class="px-3 sm:px-4 py-2 sm:py-2.5 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-400 rounded-lg text-xs sm:text-sm transition-colors flex items-center gap-1 shrink-0">
                <Check v-if="copiedUid" class="w-3.5 h-3.5 sm:w-4 sm:h-4" /><Copy v-else class="w-3.5 h-3.5 sm:w-4 sm:h-4" />{{ copiedUid?'已复制':'复制' }}
              </button>
            </div>
          </div>
          <div>
            <label class="text-slate-500 text-xs xl:text-sm mb-1 block">注册时间</label>
            <input :value="fmtDate(authStore.user?.created_at||'')" disabled class="w-full bg-slate-700/30 border border-slate-600/30 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 text-white/60 text-sm xl:text-base cursor-not-allowed" />
          </div>
          <div>
            <label class="text-slate-500 text-xs xl:text-sm mb-1 block">账号角色</label>
            <input :value="authStore.user?.role==='admin'?'官方管理员':'普通用户'" disabled class="w-full bg-slate-700/30 border border-slate-600/30 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 text-white/60 text-sm xl:text-base cursor-not-allowed" />
          </div>
          <div>
            <label class="text-slate-500 text-xs xl:text-sm mb-1 block">认证状态</label>
            <div class="flex items-center gap-2 bg-slate-700/30 border border-slate-600/30 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5">
              <span class="w-2 h-2 rounded-full shrink-0" :class="authStore.user?.verification_status==='verified'?'bg-green-500':'bg-slate-500'"></span>
              <span class="text-white/60 text-sm xl:text-base">{{ (authStore.user?.role==='admin' || authStore.user?.verification_status==='verified')?'已认证':'未认证' }}</span>
            </div>
          </div>
        </div>
      </section>

      <!-- STORAGE -->
      <section class="bg-slate-800/40 rounded-2xl xl:rounded-3xl border border-slate-700/30 overflow-hidden">
        <div class="px-4 sm:px-6 xl:px-8 py-3 sm:py-4 border-b border-slate-700/30 flex items-center gap-2">
          <HardDrive class="w-4 h-4 sm:w-5 sm:h-5 text-blue-400" />
          <h2 class="text-white font-semibold text-sm sm:text-base xl:text-lg">存储空间</h2>
        </div>
        <div class="p-4 sm:p-6 xl:p-8">
          <div class="flex justify-between text-sm xl:text-base mb-1.5">
            <span class="text-slate-400">已使用 {{ storagePercent.toFixed(1) }}%</span>
            <span class="text-white">{{ fmtSize(storageUsed) }} / {{ fmtSize(storageLimit) }}</span>
          </div>
          <div class="h-2 sm:h-2.5 xl:h-3 bg-slate-700 rounded-full overflow-hidden">
            <div :class="['h-full rounded-full transition-all duration-500', storagePercent>90?'bg-red-500':storagePercent>70?'bg-yellow-500':'bg-gradient-to-r from-indigo-500 to-purple-500']" :style="{ width: storagePercent+'%' }"></div>
          </div>
          <div class="flex justify-between mt-2 text-xs xl:text-sm text-slate-500">
            <span>剩余空间 {{ fmtSize(storageFree) }}</span>
            <span v-if="storagePercent>=90" class="text-red-400 flex items-center gap-1"><AlertTriangle class="w-3.5 h-3.5" />空间即将耗尽</span>
            <span v-else class="text-green-400 flex items-center gap-1"><CheckCircle class="w-3.5 h-3.5" />状态正常</span>
          </div>
        </div>
      </section>

      <!-- LOGIN HISTORY -->
      <section class="bg-slate-800/40 rounded-2xl xl:rounded-3xl border border-slate-700/30 overflow-hidden">
        <div class="px-4 sm:px-6 xl:px-8 py-3 sm:py-4 border-b border-slate-700/30 flex items-center gap-2">
          <Clock class="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" />
          <h2 class="text-white font-semibold text-sm sm:text-base xl:text-lg">最近登录记录</h2>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-xs sm:text-sm xl:text-base">
            <thead>
              <tr class="border-b border-slate-700/30">
                <th class="text-left py-2 sm:py-3 px-4 sm:px-6 text-slate-500 font-medium">登录时间</th>
                <th class="text-left py-2 sm:py-3 px-4 sm:px-6 text-slate-500 font-medium">IP地址</th>
                <th class="text-left py-2 sm:py-3 px-4 sm:px-6 text-slate-500 font-medium hidden sm:table-cell">设备信息</th>
                <th class="text-center py-2 sm:py-3 px-4 sm:px-6 text-slate-500 font-medium">状态</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(d, i) in (devices.length ? devices : [])" :key="i" class="border-b border-slate-700/20 hover:bg-slate-700/20 transition-colors">
                <td class="py-2 sm:py-3 px-4 sm:px-6 text-slate-300 font-mono text-xs">{{ fmtDate(d.last_login || d.lastLogin) }}</td>
                <td class="py-2 sm:py-3 px-4 sm:px-6 text-slate-400">{{ d.ip }}</td>
                <td class="py-2 sm:py-3 px-4 sm:px-6 text-slate-400 hidden sm:table-cell">{{ shortDevice(d.device || d.user_agent || '') }}</td>
                <td class="py-2 sm:py-3 px-4 sm:px-6 text-center"><span class="px-1.5 py-0.5 bg-green-500/10 text-green-400 rounded text-xs">成功</span></td>
              </tr>
              <tr v-if="devices.length===0">
                <td colspan="4" class="py-8 sm:py-10 text-center text-slate-600 text-xs sm:text-sm">暂无登录记录</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- ====== RIGHT COLUMN ====== -->
    <div class="space-y-4 sm:space-y-5 xl:space-y-6">

      <!-- SECURITY CENTER -->
      <section class="bg-slate-800/40 rounded-2xl xl:rounded-3xl border border-slate-700/30 overflow-hidden">
        <div class="px-4 sm:px-6 xl:px-8 py-3 sm:py-4 border-b border-slate-700/30 flex items-center gap-2">
          <Fingerprint class="w-4 h-4 sm:w-5 sm:h-5 text-amber-400" />
          <h2 class="text-white font-semibold text-sm sm:text-base xl:text-lg">安全中心</h2>
        </div>
        <div class="p-4 sm:p-6 xl:p-8 space-y-2.5">
          <button @click="showPasswordModal=true" class="w-full flex items-center gap-3 bg-slate-700/30 hover:bg-slate-700/50 rounded-xl p-3 sm:p-4 transition-colors">
            <div class="w-9 h-9 sm:w-10 sm:h-10 rounded-lg bg-amber-500/10 flex items-center justify-center shrink-0"><Key class="w-4 h-4 sm:w-5 sm:h-5 text-amber-400" /></div>
            <div class="flex-1 text-left min-w-0">
              <p class="text-white text-xs sm:text-sm font-medium">修改密码</p>
              <p class="text-slate-500 text-xs mt-0.5">定期更换密码更安全</p>
            </div>
            <span class="text-slate-600 text-lg">›</span>
          </button>
          <button @click="openTwoFaModal" class="w-full flex items-center gap-3 bg-slate-700/30 hover:bg-slate-700/50 rounded-xl p-3 sm:p-4 transition-colors">
            <div class="w-9 h-9 sm:w-10 sm:h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center shrink-0"><ShieldCheck class="w-4 h-4 sm:w-5 sm:h-5 text-emerald-400" /></div>
            <div class="flex-1 text-left min-w-0">
              <p class="text-white text-xs sm:text-sm font-medium">两步验证</p>
              <p class="text-slate-500 text-xs mt-0.5">{{ twoFaEnabled ? '已开启 · 登录需验证动态码' : '绑定验证器 App，登录更安全' }}</p>
            </div>
            <span v-if="twoFaEnabled" class="px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 text-xs font-medium">已开启</span>
            <span v-else class="text-slate-600 text-lg">›</span>
          </button><button @click="showDeviceModal=true; loadDevices()" class="w-full flex items-center gap-3 bg-slate-700/30 hover:bg-slate-700/50 rounded-xl p-3 sm:p-4 transition-colors">
            <div class="w-9 h-9 sm:w-10 sm:h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center shrink-0"><Monitor class="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" /></div>
            <div class="flex-1 text-left min-w-0">
              <p class="text-white text-xs sm:text-sm font-medium">设备管理</p>
              <p class="text-slate-500 text-xs mt-0.5">查看并撤销登录设备</p>
            </div>
            <span class="text-slate-600 text-lg">›</span>
          </button>
          <div class="pt-2.5 mt-2.5 border-t border-slate-700/30">
            <button @click="showDeleteModal=true" class="w-full flex items-center gap-3 bg-red-500/5 hover:bg-red-500/10 rounded-xl p-3 sm:p-4 transition-colors">
              <div class="w-9 h-9 sm:w-10 sm:h-10 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0"><Trash2 class="w-4 h-4 sm:w-5 sm:h-5 text-red-400" /></div>
              <div class="flex-1 text-left min-w-0">
                <p class="text-red-400 text-xs sm:text-sm font-medium">注销账户</p>
                <p class="text-slate-500 text-xs mt-0.5">永久删除所有数据，不可恢复</p>
              </div>
              <span class="text-red-400/60 text-lg">›</span>
            </button>
          </div>
        </div>
      </section>

      <!-- NOTIFICATIONS -->
      <section class="bg-slate-800/40 rounded-2xl xl:rounded-3xl border border-slate-700/30 overflow-hidden">
        <div class="px-4 sm:px-6 xl:px-8 py-3 sm:py-4 border-b border-slate-700/30 flex items-center gap-2">
          <Bell class="w-4 h-4 sm:w-5 sm:h-5 text-green-400" />
          <h2 class="text-white font-semibold text-sm sm:text-base xl:text-lg">通知设置</h2>
        </div>
        <div class="p-4 sm:p-6 xl:p-8 space-y-3 sm:space-y-4">
          <div class="flex items-center justify-between gap-3">
            <div class="min-w-0">
              <p class="text-white text-xs sm:text-sm">邮箱通知</p>
              <p class="text-slate-500 text-xs mt-0.5">通过邮件接收重要通知</p>
            </div>
            <button type="button" role="switch" :aria-checked="notify.email_notify" @click="notify.email_notify=!notify.email_notify" :class="['w-10 h-5 rounded-full transition-colors shrink-0 relative',notify.email_notify?'bg-green-500':'bg-slate-600']">
              <span :class="['absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform',notify.email_notify?'translate-x-5':'translate-x-0']"></span>
            </button>
          </div>
          <div class="flex items-center justify-between gap-3">
            <div class="min-w-0">
              <p class="text-white text-xs sm:text-sm">浏览器通知</p>
              <p class="text-slate-500 text-xs mt-0.5">允许浏览器推送系统消息</p>
            </div>
            <button type="button" role="switch" :aria-checked="notify.browser_notify" @click="toggleBrowserNotify" :class="['w-10 h-5 rounded-full transition-colors shrink-0 relative',notify.browser_notify?'bg-green-500':'bg-slate-600']">
              <span :class="['absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform',notify.browser_notify?'translate-x-5':'translate-x-0']"></span>
            </button>
          </div>
          <div class="flex items-center justify-between gap-3">
            <div class="min-w-0">
              <p class="text-white text-xs sm:text-sm">存储提醒</p>
              <p class="text-slate-500 text-xs mt-0.5">存储空间不足时提醒我</p>
            </div>
            <button type="button" role="switch" :aria-checked="notify.storage_alert" @click="notify.storage_alert=!notify.storage_alert" :class="['w-10 h-5 rounded-full transition-colors shrink-0 relative',notify.storage_alert?'bg-green-500':'bg-slate-600']">
              <span :class="['absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform',notify.storage_alert?'translate-x-5':'translate-x-0']"></span>
            </button>
          </div>
          <div class="flex items-center justify-between gap-3">
            <div class="min-w-0">
              <p class="text-white text-xs sm:text-sm">分享通知</p>
              <p class="text-slate-500 text-xs mt-0.5">分享被下载或封禁时通知我</p>
            </div>
            <button type="button" role="switch" :aria-checked="notify.share_notify" @click="notify.share_notify=!notify.share_notify" :class="['w-10 h-5 rounded-full transition-colors shrink-0 relative',notify.share_notify?'bg-green-500':'bg-slate-600']">
              <span :class="['absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform',notify.share_notify?'translate-x-5':'translate-x-0']"></span>
            </button>
          </div>
          <button @click="saveNotify" :disabled="notifySaving" class="w-full mt-2 py-2 sm:py-2.5 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-500 hover:to-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs sm:text-sm font-medium transition-colors">{{ notifySaving?'保存中...':'保存设置' }}</button>
        </div>
      </section>
    </div>
  </div>
</div>

<!-- ====== MODALS ====== -->

<!-- Email Modal -->
<Teleport to="body">
  <div v-if="showEmailModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" @click.self="showEmailModal=false">
    <div class="bg-slate-800 rounded-2xl p-5 sm:p-6 xl:p-8 w-full max-w-md xl:max-w-lg border border-slate-700/50 shadow-2xl">
      <div class="flex items-center justify-between mb-5 sm:mb-6"><h3 class="text-base sm:text-lg xl:text-xl font-bold text-white flex items-center gap-2"><Mail class="w-4 h-4 sm:w-5 sm:h-5 text-indigo-400" />修改邮箱</h3><button @click="showEmailModal=false" class="text-slate-500 hover:text-white transition-colors"><X class="w-4 h-4 sm:w-5 sm:h-5" /></button></div>
      <div class="space-y-3 sm:space-y-4">
        <div><label class="text-slate-400 text-xs xl:text-sm block mb-1.5">当前邮箱</label><input :value="authStore.user?.email" disabled class="w-full bg-slate-700/30 border border-slate-600/30 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 text-white/50 text-sm xl:text-base cursor-not-allowed" /></div>
        <div><label class="text-slate-400 text-xs xl:text-sm block mb-1.5">新邮箱</label><input v-model="newEmail" type="email" placeholder="请输入新邮箱" class="w-full bg-slate-700/50 border border-slate-600 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 xl:py-3 text-white text-sm xl:text-base placeholder-slate-500 focus:border-indigo-500 outline-none transition-colors" /></div>
        <div class="flex gap-2">
          <input v-model="emailCode" placeholder="验证码" class="flex-1 bg-slate-700/50 border border-slate-600 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 xl:py-3 text-white text-sm xl:text-base placeholder-slate-500 focus:border-indigo-500 outline-none transition-colors" />
          <button @click="sendEmailCode" :disabled="emailSending" class="px-3 sm:px-4 py-2 sm:py-2.5 xl:py-3 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-xs sm:text-sm rounded-lg shrink-0 transition-colors">{{ emailSending ? emailCountdown+'s' : '发送验证码' }}</button>
        </div>
        <button @click="saveEmail" :disabled="emailSaving" class="w-full py-2.5 sm:py-3 xl:py-3.5 bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white rounded-lg text-sm sm:text-base transition-colors">{{ emailSaving?'保存中...':'确认修改' }}</button>
      </div>
    </div>
  </div>
</Teleport>

<!-- Avatar Modal -->
<Teleport to="body">
  <div v-if="showAvatarModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" @click.self="showAvatarModal=false">
    <div class="bg-slate-800 rounded-2xl p-5 sm:p-6 xl:p-8 w-full max-w-md xl:max-w-lg border border-slate-700/50 shadow-2xl">
      <div class="flex items-center justify-between mb-5 sm:mb-6"><h3 class="text-base sm:text-lg xl:text-xl font-bold text-white flex items-center gap-2"><Camera class="w-4 h-4 sm:w-5 sm:h-5 text-purple-400" />更换头像</h3><button @click="showAvatarModal=false" class="text-slate-500 hover:text-white transition-colors"><X class="w-4 h-4 sm:w-5 sm:h-5" /></button></div>
      <div class="space-y-4">
        <div class="flex justify-center">
          <div class="w-24 h-24 sm:w-28 sm:h-28 xl:w-32 xl:h-32 rounded-2xl xl:rounded-3xl bg-slate-700/50 border-2 border-dashed border-slate-600 flex items-center justify-center overflow-hidden">
            <img v-if="avatarPreview" :src="avatarPreview" class="w-full h-full object-cover" />
            <Upload v-else class="w-8 h-8 sm:w-10 sm:h-10 xl:w-12 xl:h-12 text-slate-500" />
          </div>
        </div>
        <label class="block w-full py-2.5 sm:py-3 xl:py-3.5 bg-gradient-to-r from-slate-600 to-slate-700 hover:from-slate-500 hover:to-slate-600 text-white rounded-lg text-center cursor-pointer transition-all duration-200 text-sm sm:text-base border border-slate-500/30 hover:border-slate-400/50 shadow-lg flex items-center justify-center gap-2">
          <Upload class="w-4 h-4 sm:w-5 sm:h-5" />
          <span>选择图片</span>
          <input type="file" accept="image/*" @change="pickAvatar" class="hidden" />
        </label>
        <button @click="uploadAvatar" :disabled="!avatarFile||avatarUploading" class="w-full py-2.5 sm:py-3 xl:py-3.5 bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm sm:text-base font-medium transition-all duration-200 shadow-lg shadow-purple-500/20 hover:shadow-purple-500/40 flex items-center justify-center gap-2">
          <Loader2 v-if="avatarUploading" class="w-4 h-4 sm:w-5 sm:h-5 animate-spin" />
          <Upload v-else class="w-4 h-4 sm:w-5 sm:h-5" />
          {{ avatarUploading ? '上传中...' : '上传头像' }}
        </button>
      </div>
    </div>
  </div>
</Teleport>

    <!-- Two-Factor Auth Modal -->
    <div v-if="showTwoFaModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" @click.self="showTwoFaModal=false">
      <div class="bg-slate-800 border border-slate-700 rounded-2xl w-full max-w-md p-5 sm:p-6 relative max-h-[90vh] overflow-y-auto">
        <button @click="showTwoFaModal=false" class="absolute top-4 right-4 text-slate-500 hover:text-white transition-colors"><X class="w-4 h-4 sm:w-5 sm:h-5" /></button>
        <div class="mb-5"><h3 class="text-base sm:text-lg xl:text-xl font-bold text-white flex items-center gap-2"><ShieldCheck class="w-4 h-4 sm:w-5 sm:h-5 text-emerald-400" />两步验证</h3></div>

        <template v-if="!twoFaSetupMode">
          <div v-if="twoFaEnabled" class="space-y-4">
            <div class="flex items-center gap-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-4">
              <CheckCircle class="w-6 h-6 text-emerald-400 shrink-0" />
              <div>
                <p class="text-white text-sm font-medium">已开启两步验证</p>
                <p class="text-slate-400 text-xs mt-0.5">绑定时间：{{ twoFaBoundAt || '—' }}</p>
              </div>
            </div>
            <p class="text-slate-400 text-xs sm:text-sm leading-relaxed">每次登录输入密码后，还需要输入验证器 App 中的 6 位动态验证码，账号安全双重保障。</p>
            <template v-if="!twoFaDisableMode">
              <button @click="twoFaDisableMode=true" class="w-full py-2.5 sm:py-3 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 rounded-lg text-sm font-medium transition-colors">关闭两步验证</button>
            </template>
            <template v-else>
              <div><label class="text-slate-400 text-xs xl:text-sm block mb-1.5">登录密码</label><input v-model="twoFaDisablePwd" type="password" placeholder="输入密码以确认关闭" class="w-full bg-slate-700/50 border border-slate-600 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 xl:py-3 text-white text-sm xl:text-base placeholder-slate-500 focus:border-red-500 outline-none transition-colors" /></div>
              <div><label class="text-slate-400 text-xs xl:text-sm block mb-1.5">动态验证码</label><input v-model="twoFaDisableCode" type="text" inputmode="numeric" maxlength="6" placeholder="输入验证器 App 当前 6 位动态码" class="w-full bg-slate-700/50 border border-slate-600 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 xl:py-3 text-white text-sm xl:text-base text-center tracking-[0.4em] placeholder-slate-500 focus:border-red-500 outline-none transition-colors" /></div>
              <p class="text-slate-500 text-xs leading-relaxed">为保障账号安全，关闭两步验证需同时验证登录密码与当前动态验证码（每个动态码仅可使用一次）。</p>
              <div class="flex gap-2">
                <button @click="twoFaDisableMode=false; twoFaDisablePwd=''; twoFaDisableCode=''" class="flex-1 py-2.5 sm:py-3 bg-slate-700/50 hover:bg-slate-700 rounded-lg text-white text-sm transition-colors">取消</button>
                <button @click="disableTwoFa" :disabled="twoFaBusy" class="flex-1 py-2.5 sm:py-3 bg-red-500 hover:bg-red-600 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">{{ twoFaBusy?'关闭中...':'确认关闭' }}</button>
              </div>
            </template>
          </div>
          <div v-else class="space-y-4">
            <p class="text-slate-400 text-xs sm:text-sm leading-relaxed">绑定验证器后，登录时需要额外输入 6 位动态验证码。即使密码泄露，攻击者也无法登录你的账号。</p>
            <div class="space-y-2 bg-cyan-500/5 border border-cyan-500/15 rounded-xl p-3 sm:p-4">
              <p class="text-cyan-300 text-xs sm:text-sm font-medium">📱 验证器推荐（均免费）</p>
              <ul class="text-slate-400 text-xs sm:text-sm space-y-1 leading-relaxed list-disc list-inside">
                <li>电脑端：浏览器扩展 <span class="text-cyan-300">Authenticator: 2FA Client</span>（Edge / Chrome 商店安装）</li>
                <li>手机端：Google Authenticator / Microsoft Authenticator（苹果、安卓应用商店均免费）</li>
              </ul>
            </div>
            <div class="space-y-2 bg-amber-500/5 border border-amber-500/15 rounded-xl p-3 sm:p-4">
              <p class="text-amber-300 text-xs sm:text-sm font-medium">⚠️ 开启前请注意</p>
              <ul class="text-slate-400 text-xs sm:text-sm space-y-1 leading-relaxed list-disc list-inside">
                <li>以后在手机登录也需要动态码；出现二维码时，请用电脑扩展和手机 App 同时扫码，多设备备份。</li>
                <li>开启后每次登录都要输入动态码；若验证器丢失或卸载，将无法自行登录，需联系管理员人工处理。</li>
              </ul>
            </div>
            <button @click="startTwoFaSetup" :disabled="twoFaBusy" class="w-full py-2.5 sm:py-3 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2">{{ twoFaBusy?'生成中...':'开始绑定' }}</button>
          </div>
        </template>

        <template v-else>
          <div class="space-y-4">
            <p class="text-slate-400 text-xs sm:text-sm leading-relaxed">使用验证器扫描下方二维码：电脑端推荐浏览器扩展 <span class="text-cyan-300">Authenticator: 2FA Client</span>，手机端推荐 Google / Microsoft Authenticator（均免费）。若以后要在手机登录，请用手机 App 同时扫描同一二维码，或复制下方密钥手动添加。</p>
            <div class="flex items-center justify-center py-2">
              <img v-if="twoFaQrDataUrl" :src="twoFaQrDataUrl" alt="两步验证二维码" class="w-40 h-40 rounded-lg bg-white p-2" />
            </div>
            <div class="bg-slate-700/50 rounded-lg p-3 flex items-center justify-between gap-2">
              <code class="text-emerald-300 text-xs sm:text-sm break-all">{{ twoFaSecret }}</code>
              <button @click="copyTwoFaSecret" class="text-slate-400 hover:text-white shrink-0"><Copy class="w-4 h-4" /></button>
            </div>
            <div><label class="text-slate-400 text-xs xl:text-sm block mb-1.5">动态验证码</label><input v-model="twoFaCode" type="text" inputmode="numeric" maxlength="6" placeholder="输入 App 中的 6 位动态码" class="w-full bg-slate-700/50 border border-slate-600 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 xl:py-3 text-white text-sm xl:text-base text-center tracking-[0.4em] placeholder-slate-500 focus:border-emerald-500 outline-none transition-colors" /></div>
            <div class="flex gap-2">
              <button @click="twoFaSetupMode=false" class="flex-1 py-2.5 sm:py-3 bg-slate-700/50 hover:bg-slate-700 rounded-lg text-white text-sm transition-colors">取消</button>
              <button @click="confirmTwoFa" :disabled="twoFaBusy" class="flex-1 py-2.5 sm:py-3 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">{{ twoFaBusy?'验证中...':'确认启用' }}</button>
            </div>
          </div>
        </template>
      </div>
    </div>
<!-- Password Modal -->
<Teleport to="body">
  <div v-if="showPasswordModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" @click.self="showPasswordModal=false">
    <div class="bg-slate-800 rounded-2xl p-5 sm:p-6 xl:p-8 w-full max-w-md xl:max-w-lg border border-slate-700/50 shadow-2xl">
      <div class="flex items-center justify-between mb-5 sm:mb-6"><h3 class="text-base sm:text-lg xl:text-xl font-bold text-white flex items-center gap-2"><Key class="w-4 h-4 sm:w-5 sm:h-5 text-amber-400" />修改密码</h3><button @click="showPasswordModal=false" class="text-slate-500 hover:text-white transition-colors"><X class="w-4 h-4 sm:w-5 sm:h-5" /></button></div>
      <div class="space-y-3 sm:space-y-4">
        <div><label class="text-slate-400 text-xs xl:text-sm block mb-1.5">当前密码</label><div class="relative"><input v-model="oldPwd" :type="showOld?'text':'password'" placeholder="请输入当前密码" class="w-full bg-slate-700/50 border border-slate-600 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 xl:py-3 text-white text-sm xl:text-base placeholder-slate-500 focus:border-amber-500 outline-none transition-colors" /><button @click="showOld=!showOld" class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"><EyeOff v-if="showOld" class="w-4 h-4" /><Eye v-else class="w-4 h-4" /></button></div></div>
        <div><label class="text-slate-400 text-xs xl:text-sm block mb-1.5">新密码</label><div class="relative"><input v-model="newPwd" :type="showNew?'text':'password'" placeholder="请输入新密码（至少6位）" class="w-full bg-slate-700/50 border border-slate-600 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 xl:py-3 text-white text-sm xl:text-base placeholder-slate-500 focus:border-amber-500 outline-none transition-colors" /><button @click="showNew=!showNew" class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"><EyeOff v-if="showNew" class="w-4 h-4" /><Eye v-else class="w-4 h-4" /></button></div>
          <div v-if="newPwd" class="mt-2"><div class="h-1.5 bg-slate-700 rounded-full overflow-hidden"><div :class="['h-full rounded-full transition-all',pwdStrength.pct>60?'bg-green-500':pwdStrength.pct>30?'bg-yellow-500':'bg-red-500']" :style="{width:pwdStrength.pct+'%'}"></div></div><p class="text-xs mt-1" :class="pwdStrength.pct>60?'text-green-400':pwdStrength.pct>30?'text-yellow-400':'text-red-400'">{{ pwdStrength.label }}</p></div>
        </div>
        <div><label class="text-slate-400 text-xs xl:text-sm block mb-1.5">确认新密码</label><div class="relative"><input v-model="confirmPwd" :type="showConfirm?'text':'password'" placeholder="请再次输入新密码" class="w-full bg-slate-700/50 border border-slate-600 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 xl:py-3 text-white text-sm xl:text-base placeholder-slate-500 focus:border-amber-500 outline-none transition-colors" /><button @click="showConfirm=!showConfirm" class="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"><EyeOff v-if="showConfirm" class="w-4 h-4" /><Eye v-else class="w-4 h-4" /></button></div></div>
        <button @click="changePassword" :disabled="pwdSaving" class="w-full py-2.5 sm:py-3 xl:py-3.5 bg-amber-500 hover:bg-amber-600 disabled:opacity-50 text-white rounded-lg text-sm sm:text-base font-medium transition-colors">{{ pwdSaving?'修改中...':'修改密码' }}</button>
      </div>
    </div>
  </div>
</Teleport>

<!-- Delete Modal -->
<Teleport to="body">
  <div v-if="showDeleteModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" @click.self="showDeleteModal=false">
    <div class="bg-slate-800 rounded-2xl p-5 sm:p-6 xl:p-8 w-full max-w-md xl:max-w-lg border border-red-500/30 shadow-2xl">
      <div class="flex items-center justify-between mb-2"><h3 class="text-base sm:text-lg xl:text-xl font-bold text-red-400 flex items-center gap-2"><AlertTriangle class="w-4 h-4 sm:w-5 sm:h-5" />账户注销</h3><button @click="showDeleteModal=false" class="text-slate-500 hover:text-white transition-colors"><X class="w-4 h-4 sm:w-5 sm:h-5" /></button></div>
      <div class="bg-red-500/5 border border-red-500/10 rounded-lg p-3 mb-3 sm:mb-4">
        <p class="text-slate-400 text-xs sm:text-sm leading-relaxed">⚠️ 此操作无法撤销！所有文件、分享、账户数据将被永久删除。</p>
      </div>
      <div class="space-y-3 sm:space-y-4">
        <div><label class="text-slate-400 text-xs xl:text-sm block mb-1.5">请输入 <span class="text-red-400 font-bold">确认注销</span> 以确认</label><input v-model="deleteText" placeholder="确认注销" class="w-full bg-slate-700/50 border border-slate-600 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 xl:py-3 text-white text-sm xl:text-base placeholder-slate-500 focus:border-red-500 outline-none transition-colors" /></div>
        <div><label class="text-slate-400 text-xs xl:text-sm block mb-1.5">当前密码</label><input v-model="deletePwd" type="password" placeholder="请输入您的账户密码" class="w-full bg-slate-700/50 border border-slate-600 rounded-lg px-3 sm:px-4 py-2 sm:py-2.5 xl:py-3 text-white text-sm xl:text-base placeholder-slate-500 focus:border-red-500 outline-none transition-colors" /></div>
        <button @click="deleteAccount" :disabled="deleteLoading||deleteText!=='确认注销'" class="w-full py-2.5 sm:py-3 xl:py-3.5 bg-red-500 hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm sm:text-base font-medium transition-colors">{{ deleteLoading?'注销中...':'确认注销账户' }}</button>
      </div>
    </div>
  </div>
</Teleport>

<!-- Device Modal -->
<Teleport to="body">
  <div v-if="showDeviceModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" @click.self="showDeviceModal=false">
    <div class="bg-slate-800 rounded-2xl p-5 sm:p-6 xl:p-8 w-full max-w-lg xl:max-w-2xl border border-slate-700/50 shadow-2xl max-h-[85vh] flex flex-col">
      <div class="flex items-center justify-between mb-5 sm:mb-6 shrink-0"><h3 class="text-base sm:text-lg xl:text-xl font-bold text-white flex items-center gap-2"><Monitor class="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" />设备管理</h3><button @click="showDeviceModal=false" class="text-slate-500 hover:text-white transition-colors"><X class="w-4 h-4 sm:w-5 sm:h-5" /></button></div>
      <div v-if="deviceLoading" class="text-center py-8 xl:py-10 flex-1 flex items-center justify-center"><Loader2 class="w-5 h-5 sm:w-6 sm:h-6 xl:w-8 xl:h-8 animate-spin mx-auto mb-2 text-slate-400" /><p class="text-slate-500 text-xs sm:text-sm">加载中...</p></div>
      <div v-else-if="devices.length===0" class="text-center py-8 xl:py-10 flex-1 flex flex-col items-center justify-center"><Monitor class="w-8 h-8 sm:w-10 sm:h-10 xl:w-12 xl:h-12 text-slate-600 mx-auto mb-2" /><p class="text-slate-500 text-xs sm:text-sm">暂无设备记录</p></div>
      <div v-else class="space-y-2 overflow-y-auto flex-1 pr-1">
        <div v-for="d in devices" :key="d.id" class="flex items-center justify-between bg-slate-700/30 rounded-xl p-3 sm:p-4 xl:p-5 hover:bg-slate-700/50 transition-colors">
          <div class="flex items-center gap-2 sm:gap-3 xl:gap-4 min-w-0">
            <div class="w-9 h-9 sm:w-10 sm:h-10 xl:w-12 xl:h-12 rounded-xl flex items-center justify-center shrink-0" :class="d.deviceType==='desktop'?'bg-blue-500/10 text-blue-400':d.deviceType==='apple'?'bg-slate-500/10 text-slate-400':'bg-green-500/10 text-green-400'">
              <component :is="deviceIcon(d.deviceType || (d.device ? deviceType(d.device) : 'desktop'))" class="w-4 h-4 sm:w-5 sm:h-5 xl:w-6 xl:h-6" />
            </div>
            <div class="min-w-0">
              <p class="text-white text-xs sm:text-sm xl:text-base truncate">{{ shortDevice(d.device || d.user_agent || '') }}</p>
              <p class="text-slate-500 text-xs xl:text-sm">{{ d.ip }} · {{ fmtDate(d.last_login || d.lastLogin) }}</p>
            </div>
          </div>
          <button @click="revokeDevice(d.id)" class="px-2.5 sm:px-3 py-1 sm:py-1.5 xl:py-2 bg-red-500/10 text-red-400 rounded-lg hover:bg-red-500/20 text-xs xl:text-sm shrink-0 transition-colors">移除</button>
        </div>
      </div>
    </div>
  </div>
</Teleport>
</Layout>
</template>
