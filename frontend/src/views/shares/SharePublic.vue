<script setup lang="ts">
import { SITE_NAME } from '@/config/site'
import { ref, onMounted, computed } from 'vue'
import { useRoute } from 'vue-router'
import { useSharesStore } from '@/stores/shares'
import { guardPassword } from '@/utils/passwordGuard'
import { Cloud, FileText, Download, Lock, Clock, FileImage, FileVideo, FileAudio, FileArchive, AlertCircle, Zap, Share2, Calendar, User, Shield, ShieldAlert, Hash, ArrowLeft, FolderOpen, HardDrive, MessageCircle, Globe, Eye, EyeOff, Search, Trash2, Ban } from 'lucide-vue-next'

const route = useRoute()
const sharesStore = useSharesStore()

const shareCode = ref('')
const password = ref('')
const showPassword = ref(false)
const pwError = ref('')
const pwAttempts = ref(0)
const pwLocked = ref(false)
const pwLockCountdown = ref('')
const pwLockoutLevel = ref(0)
const MAX_PW_ATTEMPTS = 5
let pwLockTimer: ReturnType<typeof setInterval> | null = null

const isLoading = ref(true)
const errorMessage = ref('')
// IronWall v1.47.0: 区分「真失效」与「瞬时故障」，瞬时错误页展示真实原因并支持重试
const errorKind = ref<'dead' | 'transient'>('dead')
const dlError = ref('')
const shareInfo = ref<any>(null)
const downloadStarted = ref<number | null>(null)

// IronWall v1.47.9: 记录 download_sig 获取时刻，闲置超 60 秒后下载前自动换新
let sigFetchedAt = 0
const timeRemaining = ref('')
let timer: ReturnType<typeof setInterval> | null = null

function handleKeyboard(e: KeyboardEvent) {
  if (e.key === 'Enter' && !isLoading.value && shareInfo.value && (shareInfo.value.file_name || shareInfo.value.folder_name)) {
    e.preventDefault()
    handleDownload()
  }
}

onMounted(async () => {
  shareCode.value = route.params.code as string
  if (!shareCode.value) {
    errorMessage.value = '无效链接'
    isLoading.value = false
    return
  }
  const up = route.query.password as string
  if (up) {
    password.value = up
    try {
      const cu = new URL(location.href)
      cu.searchParams.delete('password')
      history.replaceState(null, '', cu.pathname + cu.search + cu.hash)
    } catch {}
  } else {
    const saved = sessionStorage.getItem('share_pw_' + shareCode.value)
    if (saved) password.value = saved
  }
  await loadShareInfo(up || password.value || undefined)
  const lockData = sessionStorage.getItem('share_lock_' + shareCode.value)
  if (lockData) {
    try {
      const ld = JSON.parse(lockData)
      const remaining = ld.expiry - Date.now()
      if (remaining > 0) {
        pwLockoutLevel.value = ld.level || 0
        pwLocked.value = true
        pwAttempts.value = MAX_PW_ATTEMPTS
        const rm = Math.ceil(remaining / 60000)
        pwError.value = '密码错误次数过多，已锁定' + rm + '分钟'
        let remainingSec = Math.ceil(remaining / 1000)
        const tick = () => {
          const m = Math.floor(remainingSec / 60)
          const s = remainingSec % 60
          pwLockCountdown.value = m + '分' + s + '秒'
          remainingSec--
          if (remainingSec < 0) {
            clearLockout()
            pwAttempts.value = 0
            pwLockoutLevel.value = (ld.level || 0) + 1
            pwError.value = ''
            password.value = ''
            sessionStorage.removeItem('share_lock_' + shareCode.value)
          }
        }
        tick()
        pwLockTimer = setInterval(tick, 1000)
      } else {
        sessionStorage.removeItem('share_lock_' + shareCode.value)
      }
    } catch {
      sessionStorage.removeItem('share_lock_' + shareCode.value)
    }
  }
  document.addEventListener('keydown', handleKeyboard)
})

function getLockoutMinutes() {
  const levels = [5, 15, 30, 60, 120]
  return levels[Math.min(pwLockoutLevel.value, levels.length - 1)]
}

function startLockout() {
  pwLocked.value = true
  const mins = getLockoutMinutes()
  let sec = mins * 60
  const tick = () => {
    const m = Math.floor(sec / 60)
    const s = sec % 60
    pwLockCountdown.value = m + '分' + s + '秒'
    sec--
    if (sec < 0) {
      clearLockout()
      pwAttempts.value = 0
      pwLockoutLevel.value++
      pwError.value = ''
      password.value = ''
    }
  }
  tick()
  pwLockTimer = setInterval(tick, 1000)
  const expiry = Date.now() + mins * 60 * 1000
  sessionStorage.setItem('share_lock_' + shareCode.value, JSON.stringify({ level: pwLockoutLevel.value, expiry: expiry }))
}

function clearLockout() {
  pwLocked.value = false
  pwLockCountdown.value = ''
  if (pwLockTimer) {
    clearInterval(pwLockTimer)
    pwLockTimer = null
  }
  sessionStorage.removeItem('share_lock_' + shareCode.value)
}

// IronWall v1.47.0: 按业务码精确分类失败，message 关键词仅作兜底。
// 瞬时错误（签名拒绝/限流/网络）绝不再把用户推上「分享已失效」页。
type ShareFailureKind = 'password' | 'banned' | 'dead' | 'transient'

function classifyShareFailure(code: number | undefined, msg: string, submitted: boolean): ShareFailureKind {
  if (code === 3006 || msg.includes('封禁')) return 'banned'
  if (code === 3003 || code === 3004 || msg.includes('密码') || msg.includes('提取码')) return 'password'
  if (code === 3001 || code === 3002 || code === 2001 || code === 2005 || code === 404) return 'dead'
  if (!submitted && /不存在|已过期|已被删除|已失效/.test(msg)) return 'dead'
  return 'transient'
}

async function loadShareInfo(pwd?: string) {
  isLoading.value = true
  errorMessage.value = ''
  pwError.value = ''
  errorKind.value = 'dead'
  const submitted = !!pwd
  try {
    let pwHash = ''
    let pwToken = ''
    if (pwd) {
      try {
        const guard = await guardPassword(shareCode.value, pwd)
        pwHash = guard.pw_hash
        pwToken = guard.pw_token
      } catch (e) {
        pwError.value = '安全引擎初始化失败，请刷新重试'
        isLoading.value = false
        return
      }
    }
    const r = await sharesStore.getShareInfo(shareCode.value, pwHash, pwToken)
    if (r.success) {
      shareInfo.value = r.data
      sigFetchedAt = Date.now()
      if (r.data?.file_name || r.data?.folder_name) {
        document.title = `${SITE_NAME} - 分享`
        startTimer()
        pwAttempts.value = 0
        pwError.value = ''
        pwLockoutLevel.value = 0
        clearLockout()
        if (password.value) sessionStorage.setItem('share_pw_' + shareCode.value, password.value)
      }
    } else {
      const msg = r.message || ''
      const kind = classifyShareFailure(r.code, msg, submitted)
      if (kind === 'password') {
        pwError.value = msg || '提取码错误'
        pwAttempts.value++
        password.value = ''
        if (pwAttempts.value >= MAX_PW_ATTEMPTS) {
          const mins = getLockoutMinutes()
          pwError.value = '密码错误次数过多，已锁定' + mins + '分钟'
          startLockout()
        }
        // URL 携带密码直达失败时补拉最小信息，恢复密码门而非白屏
        if (!shareInfo.value) {
          try {
            const base = await sharesStore.getShareInfo(shareCode.value)
            if (base.success) {
              shareInfo.value = base.data
              sigFetchedAt = Date.now()
            }
          } catch { /* 补拉失败保持现状，刷新可恢复 */ }
        }
      } else if (kind === 'banned') {
        errorMessage.value = msg || '该分享已被封禁'
      } else if (kind === 'dead') {
        errorMessage.value = msg || '分享已失效'
      } else {
        // 瞬时故障：提交过密码 → 留在密码门；未提交 → 可重试错误卡
        if (submitted && shareInfo.value?.has_password) {
          pwError.value = msg || '验证失败，请稍后重试'
        } else {
          errorMessage.value = msg || (submitted ? '验证失败，请检查网络连接' : '加载失败，请检查网络连接')
          errorKind.value = 'transient'
        }
      }
    }
  } catch {
    const em = submitted ? '验证失败，请检查网络连接' : '加载失败，请检查网络连接'
    if (submitted && shareInfo.value?.has_password) {
      pwError.value = em
    } else {
      errorMessage.value = em
      errorKind.value = 'transient'
    }
  } finally {
    isLoading.value = false
  }
}

function startTimer() {
  if (timer) clearInterval(timer)
  if (!shareInfo.value?.expire_time) {
    timeRemaining.value = '永久有效'
    return
  }
  const tick = () => {
    const d = new Date(shareInfo.value.expire_time).getTime() - Date.now()
    if (d <= 0) {
      timeRemaining.value = '已过期'
      if (timer) clearInterval(timer)
      return
    }
    const day = Math.floor(d / 86400000)
    const hr = Math.floor((d % 86400000) / 3600000)
    const min = Math.floor((d % 3600000) / 60000)
    timeRemaining.value = day > 0 ? day + '天' + hr + '时' : hr > 0 ? hr + '时' + min + '分' : min + '分'
  }
  tick()
  timer = setInterval(tick, 60000)
}

const fileIcon = computed(() => {
  if (!shareInfo.value?.file_name) return { icon: FileText, tint: 'tint-doc' }
  const n = shareInfo.value.file_name.toLowerCase()
  if (/\.(jpg|jpeg|png|gif|webp|svg|bmp|ico)$/i.test(n)) return { icon: FileImage, tint: 'tint-img' }
  if (/\.(mp4|avi|mov|wmv|flv|mkv|webm)$/i.test(n)) return { icon: FileVideo, tint: 'tint-video' }
  if (/\.(mp3|wav|aac|flac|ogg|wma)$/i.test(n)) return { icon: FileAudio, tint: 'tint-audio' }
  if (/\.(zip|rar|7z|tar|gz|bz2|xz)$/i.test(n)) return { icon: FileArchive, tint: 'tint-archive' }
  return { icon: FileText, tint: 'tint-doc' }
})

const ext = computed(() => {
  if (!shareInfo.value?.file_name) return ''
  const p = shareInfo.value.file_name.split('.')
  return p.length > 1 ? p.pop()!.toUpperCase() : 'FILE'
})

function fileIconFor(f: string) {
  const n = f.toLowerCase()
  if (/\.(jpg|jpeg|png|gif|webp|svg|bmp|ico)$/i.test(n)) return FileImage
  if (/\.(mp4|avi|mov|wmv|flv|mkv|webm)$/i.test(n)) return FileVideo
  if (/\.(mp3|wav|aac|flac|ogg|wma)$/i.test(n)) return FileAudio
  if (/\.(zip|rar|7z|tar|gz|bz2|xz)$/i.test(n)) return FileArchive
  return FileText
}

function fileIconColor(f: string) {
  const n = f.toLowerCase()
  if (/\.(jpg|jpeg|png|gif|webp|svg|bmp|ico)$/i.test(n)) return 'tint-img'
  if (/\.(mp4|avi|mov|wmv|flv|mkv|webm)$/i.test(n)) return 'tint-video'
  if (/\.(mp3|wav|aac|flac|ogg|wma)$/i.test(n)) return 'tint-audio'
  if (/\.(zip|rar|7z|tar|gz|bz2|xz)$/i.test(n)) return 'tint-archive'
  return 'tint-doc'
}

async function handleDownload(fid?: number) {
  if (!shareInfo.value) return
  downloadStarted.value = fid || 0
  dlError.value = ''

    const limit = shareInfo.value.download_limit || 0
    const count = shareInfo.value.download_count || 0
    if (limit > 0 && count >= limit) {
      downloadStarted.value = null
      dlError.value = '下载次数已达上限，剩余 0 次'
      return
    }  try {
    let qs: string[] = []
    if (fid) qs.push('fileId=' + fid)
    let sig = shareInfo.value.download_sig
    if (Date.now() - sigFetchedAt > 60_000) {
      try {
        let ph = ''
        let pt = ''
        if (password.value) {
          const g = await guardPassword(shareCode.value, password.value)
          ph = g.pw_hash
          pt = g.pw_token
        }
        const fresh = await sharesStore.getShareInfo(shareCode.value, ph, pt)
        if (fresh.success && fresh.data?.download_sig) {
          sig = fresh.data.download_sig
          shareInfo.value = fresh.data
          sigFetchedAt = Date.now()
        }
      } catch {
        // 换新失败沿用旧签名，服务端明确拒绝（3007）时用户重试即可
      }
    }
    if (sig) qs.push('sig=' + encodeURIComponent(sig))
    if (password.value) {
      const g = await guardPassword(shareCode.value, password.value)
      qs.push('pw_hash=' + encodeURIComponent(g.pw_hash))
      qs.push('pw_token=' + encodeURIComponent(g.pw_token))
    }
    let u = '/api/shares/download/' + shareCode.value
    if (qs.length) u += '?' + qs.join('&')
    window.open(u, '_blank')
  } catch {
    dlError.value = '安全引擎校验失败，请重试'
  }
  setTimeout(() => { downloadStarted.value = null }, 2000)
}

function fs(b: number): string {
  if (!b) return '0 B'
  const k = 1024
  const s = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(b) / Math.log(k))
  return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + s[i]
}

function fd(s: string): string {
  if (!s) return ''
  return new Date(s).toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' }) + ' ' + new Date(s).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
}

const shareUrl = computed(() => location.href)
const encodedUrl = computed(() => encodeURIComponent(shareUrl.value))
const encodedTitle = computed(() => encodeURIComponent(shareInfo.value?.file_name || shareInfo.value?.folder_name || '分享文件'))
const qqShareUrl = computed(() => 'https://connect.qq.com/widget/shareqq/index.html?url=' + encodedUrl.value + '&title=' + encodedTitle.value + '&summary=' + encodedTitle.value + '&site=' + encodeURIComponent(SITE_NAME))
const weiboShareUrl = computed(() => 'https://service.weibo.com/share/share.php?url=' + encodedUrl.value + '&title=' + encodedTitle.value)
const isExpired = computed(() => {
  if (!shareInfo.value?.expire_time) return false
  return new Date(shareInfo.value.expire_time).getTime() < Date.now()
})
const isBanned = computed(() => errorMessage.value.includes('封禁'))
const folderTotalSize = computed(() => {
  if (!shareInfo.value?.files) return 0
  return shareInfo.value.files.reduce((s: number, f: any) => s + (f.file_size || 0), 0)
})
const downloadProgress = computed(() => {
  if (!shareInfo.value || shareInfo.value.download_limit <= 0) return 0
  return Math.min(100, ((shareInfo.value.download_count || 0) / shareInfo.value.download_limit) * 100)
})
</script>

<template>
  <div class="share-root">
    <div class="bg-orb orb-a"></div>
    <div class="bg-orb orb-b"></div>
    <div class="bg-grid"></div>

    <!-- 加载中 -->
    <div v-if="isLoading" class="stage">
      <div class="loader-box">
        <div class="loader-ring"><Cloud class="loader-cloud" /></div>
        <p class="loader-text">正在打开分享...</p>
      </div>
    </div>

    <!-- 违规封禁专属页 -->
    <div v-else-if="errorMessage && isBanned" class="stage">
      <div class="state-card banned-card">
        <div class="state-badge banned-badge"><ShieldAlert /></div>
        <h1 class="state-title banned-title">该分享已被封禁</h1>
        <p class="state-sub">该分享因涉及违规内容，已被{{ SITE_NAME }}官方封禁，无法访问</p>
        <div class="state-reasons">
          <div class="state-reason"><Ban /><span>内容涉嫌违规，违反相关法律法规</span></div>
          <div class="state-reason"><Shield /><span>为保护用户权益，官方已停止该分享传播</span></div>
          <div class="state-reason"><MessageCircle /><span>如认为存在误封，可通过官方渠道联系管理员申诉</span></div>
        </div>
        <div class="state-actions">
          <a href="/" class="btn-ghost"><ArrowLeft /><span>返回首页</span></a>
          <a href="/contact" class="btn-danger"><MessageCircle /><span>联系管理员</span></a>
        </div>
      </div>
    </div>

    <!-- 分享失效页 / 瞬时故障重试页 -->
    <div v-else-if="errorMessage" class="stage">
      <div class="state-card">
        <div class="state-badge">
          <FileText />
          <div class="badge-chip"><Search /></div>
        </div>
        <h1 class="state-title">{{ errorKind === 'transient' ? '暂时无法打开' : '你来晚了' }}</h1>
        <p class="state-sub">{{ errorMessage || '该分享链接已失效' }}</p>
        <div v-if="errorKind !== 'transient'" class="state-reasons">
          <div class="state-reason"><Trash2 /><span>文件已被分享者删除</span></div>
          <div class="state-reason"><Clock /><span>分享链接已过期</span></div>
          <div class="state-reason"><Ban /><span>下次记得早点来哇！</span></div>
        </div>
        <div class="state-actions">
          <a href="/" class="btn-ghost"><ArrowLeft /><span>返回首页</span></a>
          <button v-if="shareCode" type="button" class="btn-primary retry-btn" @click="loadShareInfo()">
            <Zap /><span>重新加载</span>
          </button>
        </div>
      </div>
    </div>

    <!-- 密码门 -->
    <div v-else-if="shareInfo && shareInfo.has_password && !shareInfo.file_name && !shareInfo.folder_name" class="stage">
      <div class="pw-card">
        <div class="pw-lock" :class="{ shake: pwError, locked: pwLocked }"><Lock /></div>
        <h1 class="pw-title">{{ pwLocked ? '已锁定' : '加密分享' }}</h1>
        <p class="pw-sub">{{ pwLocked ? '验证次数已达上限，请稍后再试' : '此文件已设置密码保护，请输入提取码查看' }}</p>

        <div v-if="pwLocked" class="pw-timer"><Clock /><span>{{ pwLockCountdown || '计算中...' }}</span></div>

        <div v-if="pwError" class="pw-error"><span class="pw-error-dot"></span>{{ pwError }}</div>

        <div v-if="pwAttempts > 0 && !pwLocked" class="pw-attempts">
          <div class="pw-dots">
            <span v-for="i in MAX_PW_ATTEMPTS" :key="i" class="pw-dot" :class="{ used: i <= pwAttempts }"></span>
          </div>
          <p>剩余 <strong>{{ MAX_PW_ATTEMPTS - pwAttempts }}</strong> 次尝试{{ pwLockoutLevel > 0 ? ' · 第' + (pwLockoutLevel + 1) + '轮锁定' : '' }}</p>
        </div>

        <div v-if="!pwLocked" class="pw-form">
          <div class="pw-input" :class="{ error: pwError }">
            <Lock class="pw-input-icon" />
            <input v-model="password" :type="showPassword ? 'text' : 'password'" placeholder="输入提取码" maxlength="20" @keyup.enter.stop="loadShareInfo(password)" @input="pwError = ''" />
            <button type="button" class="pw-eye-btn" :title="showPassword ? '隐藏密码' : '显示密码'" @click="showPassword = !showPassword">
              <EyeOff v-if="showPassword" />
              <Eye v-else />
            </button>
          </div>
          <button type="button" class="btn-primary pw-submit" :disabled="!password || pwLocked" @click="loadShareInfo(password)">
            <Zap /><span>验证提取</span>
          </button>
        </div>

        <div v-if="shareInfo?.contact" class="pw-contact"><MessageCircle /><span>联系分享者：{{ shareInfo.contact }}</span></div>
        <p v-else class="pw-hint">联系分享者获取提取码</p>
      </div>
    </div>

    <!-- 主内容 -->
    <div v-else-if="shareInfo" class="stage">
      <div class="main-wrap">
        <div class="topbar">
          <div class="brand"><Cloud class="brand-icon" /><span>{{ SITE_NAME }}</span></div>
          <div class="secure-badge"><Shield /><span>文件验证成功，可以安全下载</span></div>
        </div>

        <div class="main-card">
          <div class="card-glow-bar"></div>
          <div class="card-body">
            <!-- 文件头 -->
            <div class="file-head">
              <div class="file-tile" :class="shareInfo.share_type === 2 ? 'tile-folder' : fileIcon.tint">
                <component :is="shareInfo.share_type === 2 ? FolderOpen : fileIcon.icon" class="tile-icon" />
              </div>
              <div class="file-head-info">
                <h1 class="file-title">{{ shareInfo.file_name || shareInfo.folder_name || '未命名文件' }}</h1>
                <div class="file-tags">
                  <span class="tag">{{ ext }}</span>
                  <span v-if="shareInfo.file_size" class="tag">{{ fs(shareInfo.file_size) }}</span>
                  <span v-if="shareInfo.share_type === 2" class="tag tag-folder">文件夹 · {{ shareInfo.files?.length || 0 }} 个文件</span>
                </div>
              </div>
            </div>

            <!-- 文件说明 -->
            <div v-if="shareInfo.description" class="desc">
              <div class="desc-icon"><AlertCircle /></div>
              <div>
                <p class="desc-label">文件说明</p>
                <p class="desc-text">{{ shareInfo.description }}</p>
              </div>
            </div>

            <!-- 文件夹内容 -->
            <div v-if="shareInfo.share_type === 2 && shareInfo.files?.length" class="folder-block">
              <div class="folder-head">
                <p class="folder-title">文件夹内容（{{ shareInfo.files.length }} 个文件）</p>
              </div>
              <p v-if="dlError" class="dl-error"><AlertCircle />{{ dlError }}</p>
              <div class="folder-list">
                <div v-for="f in shareInfo.files" :key="f.id" class="folder-row">
                  <div class="row-icon" :class="fileIconColor(f.original_name)">
                    <component :is="fileIconFor(f.original_name)" />
                  </div>
                  <div class="row-info">
                    <p class="row-name">{{ f.original_name }}</p>
                    <p class="row-meta">{{ fs(f.file_size) }} · {{ (f.original_name || '').split('.').pop()?.toUpperCase() || 'FILE' }}</p>
                  </div>
                  <a href="#" class="row-dl" @click.prevent="handleDownload(f.id)"><Download />下载</a>
                </div>
              </div>
            </div>

            <!-- 统计 -->
            <div class="stats">
              <div class="stat"><Clock class="stat-icon" /><div><p class="stat-label">有效期</p><p class="stat-value" :class="{ expired: isExpired }">{{ timeRemaining }}</p></div></div>
              <div class="stat"><HardDrive class="stat-icon" /><div><p class="stat-label">文件大小</p><p class="stat-value">{{ shareInfo.share_type === 2 ? fs(folderTotalSize) : (shareInfo.file_size ? fs(shareInfo.file_size) : '-') }}</p></div></div>
              <div class="stat"><Download class="stat-icon" /><div><p class="stat-label">已下载</p><p class="stat-value">{{ shareInfo.download_count || 0 }} 次</p></div></div>
              <div class="stat"><Shield class="stat-icon" /><div><p class="stat-label">类型</p><p class="stat-value">{{ shareInfo.share_type === 2 ? '文件夹' : ext }}</p></div></div>
            </div>

            <!-- 下载 -->
            <div class="action-row">
              <button v-if="shareInfo.share_type === 1" type="button" class="btn-primary dl-btn" :disabled="downloadStarted !== null" @click="handleDownload()">
                <Download :class="{ bounce: downloadStarted !== null }" />{{ downloadStarted !== null ? '正在下载...' : '立即下载' }}
              </button>
            </div>
            <p v-if="dlError && shareInfo.share_type === 1" class="dl-error"><AlertCircle />{{ dlError }}</p>

            <!-- 分享到 -->
            <div class="share-row">
              <span class="share-label"><Share2 />分享到</span>
              <a class="share-chip" target="_blank" rel="noopener noreferrer" :href="qqShareUrl"><MessageCircle />QQ</a>
              <a class="share-chip" target="_blank" rel="noopener noreferrer" :href="weiboShareUrl"><Globe />微博</a>
            </div>

            <!-- 下载限制进度 -->
            <div v-if="shareInfo.download_limit > 0" class="limit">
              <div class="limit-head"><Download /><span>下载统计</span><span class="limit-count">{{ shareInfo.download_count || 0 }} / {{ shareInfo.download_limit }} 次</span></div>
              <div class="limit-bar"><div class="limit-fill" :style="{ width: downloadProgress + '%' }"></div></div>
              <p class="limit-hint">剩余 {{ Math.max(0, shareInfo.download_limit - (shareInfo.download_count || 0)) }} 次下载机会</p>
            </div>

            <!-- 分享者 -->
            <div class="sharer">
              <div class="avatar">
                <img v-if="shareInfo.owner_avatar" :src="shareInfo.owner_avatar" alt="分享者头像" />
                <User v-else />
              </div>
              <div class="sharer-info">
                <div class="sharer-top">
                  <span class="sharer-label">分享者</span>
                  <span class="sharer-name">{{ shareInfo.sharer_name || shareInfo.owner_username || '未知用户' }}</span>
                  <span v-if="shareInfo.verification_badge" class="verify"><Shield />{{ shareInfo.verification_badge }}</span>
                </div>
                <div class="sharer-meta">
                  <span v-if="shareInfo.owner_user_code" class="meta"><Hash />{{ shareInfo.owner_user_code }}</span>
                  <span class="meta"><Calendar />{{ shareInfo.created_at ? fd(shareInfo.created_at) : '-' }}</span>
                </div>
              </div>
            </div>

            <!-- 页脚 -->
            <div class="card-footer">
              <div class="footer-links">
                <span class="footer-brand"><Cloud />{{ SITE_NAME }}</span>
                <span class="dot">·</span>
                <span>安全文件分享</span>
                <span class="dot">·</span>
                <a href="/">返回首页</a>
              </div>
              <p class="footer-copy">通过{{ SITE_NAME }}安全分享 · 文件加密传输 · 极速稳定</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.share-root{position:relative;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:clamp(16px,3vw,48px);background:#070b18;overflow:hidden}
.bg-orb{position:fixed;border-radius:50%;filter:blur(90px);opacity:.5;pointer-events:none;z-index:0}
.orb-a{width:56vw;height:56vw;min-width:420px;min-height:420px;top:-18vw;left:-12vw;background:radial-gradient(circle,rgba(99,102,241,.5),transparent 65%)}
.orb-b{width:50vw;height:50vw;min-width:380px;min-height:380px;bottom:-16vw;right:-10vw;background:radial-gradient(circle,rgba(139,92,246,.42),transparent 65%)}
.bg-grid{position:fixed;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(148,163,184,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(148,163,184,.05) 1px,transparent 1px);background-size:44px 44px;mask-image:radial-gradient(ellipse at center,rgba(0,0,0,.85),transparent 72%);-webkit-mask-image:radial-gradient(ellipse at center,rgba(0,0,0,.85),transparent 72%)}
.stage{position:relative;z-index:1;width:100%;display:flex;justify-content:center;animation:fadeUp .45s ease}

/* 加载态 */
.loader-box{display:flex;flex-direction:column;align-items:center;gap:clamp(14px,2vw,22px);padding:clamp(24px,4vw,48px)}
.loader-ring{width:clamp(64px,9vw,104px);height:clamp(64px,9vw,104px);border-radius:50%;background:rgba(99,102,241,.08);border:1px solid rgba(129,140,248,.25);display:flex;align-items:center;justify-content:center;animation:pulse 1.6s ease infinite}
.loader-cloud{width:clamp(28px,4vw,44px);height:clamp(28px,4vw,44px);color:#a5b4fc}
.loader-text{color:#94a3b8;font-size:clamp(13px,1.5vw,17px)}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(129,140,248,.25)}50%{box-shadow:0 0 0 18px rgba(129,140,248,0)}}

/* 状态卡（封禁 / 失效） */
.state-card{position:relative;width:min(92vw,600px);text-align:center;padding:clamp(32px,5vw,64px) clamp(20px,4vw,56px);background:rgba(15,23,42,.72);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);border:1px solid rgba(148,163,184,.12);border-radius:clamp(20px,3vw,32px);box-shadow:0 24px 80px rgba(0,0,0,.5)}
.state-badge{position:relative;width:clamp(72px,10vw,104px);height:clamp(72px,10vw,104px);margin:0 auto clamp(16px,2.5vw,28px);border-radius:50%;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);display:flex;align-items:center;justify-content:center;color:rgba(248,113,113,.95)}
.state-badge>svg{width:clamp(34px,5vw,50px);height:clamp(34px,5vw,50px)}
.badge-chip{position:absolute;right:-6px;bottom:-6px;width:clamp(28px,4vw,40px);height:clamp(28px,4vw,40px);border-radius:50%;background:#ef4444;display:flex;align-items:center;justify-content:center;color:#fff;box-shadow:0 4px 14px rgba(239,68,68,.4)}
.badge-chip svg{width:60%;height:60%}
.banned-card{border-color:rgba(239,68,68,.28);box-shadow:0 24px 80px rgba(0,0,0,.5),0 0 60px rgba(239,68,68,.12)}
.state-title{color:#f1f5f9;font-size:clamp(24px,3.5vw,40px);font-weight:700;margin-bottom:clamp(6px,1vw,12px)}
.banned-title{background:linear-gradient(135deg,#fca5a5,#ef4444);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.state-sub{color:#94a3b8;font-size:clamp(13px,1.7vw,19px);margin-bottom:clamp(20px,3vw,34px)}
.state-reasons{display:flex;flex-direction:column;gap:clamp(8px,1.2vw,13px);max-width:420px;margin:0 auto clamp(22px,3vw,38px)}
.state-reason{display:flex;align-items:center;gap:10px;padding:clamp(10px,1.4vw,14px) clamp(14px,1.8vw,20px);background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:clamp(10px,1.4vw,14px);color:#94a3b8;font-size:clamp(12px,1.4vw,15px);text-align:left}
.state-reason svg{flex-shrink:0;color:rgba(248,113,113,.6);width:clamp(15px,1.8vw,19px);height:clamp(15px,1.8vw,19px)}
.banned-card .state-reason{border-color:rgba(239,68,68,.16);background:rgba(239,68,68,.05)}
.state-actions{display:flex;align-items:center;justify-content:center;gap:clamp(10px,1.6vw,16px);flex-wrap:wrap}

/* 按钮 */
.btn-ghost{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:clamp(10px,1.4vw,14px) clamp(20px,2.6vw,32px);background:rgba(99,102,241,.12);border:1px solid rgba(99,102,241,.3);border-radius:clamp(10px,1.4vw,16px);color:#a5b4fc;font-size:clamp(13px,1.5vw,16px);font-weight:600;text-decoration:none;transition:all .2s;cursor:pointer}
.btn-ghost:hover{background:rgba(99,102,241,.22);border-color:rgba(99,102,241,.5);color:#c7d2fe;transform:translateY(-1px)}
.btn-ghost svg{width:clamp(15px,1.8vw,19px);height:clamp(15px,1.8vw,19px)}
.retry-btn{padding:clamp(10px,1.4vw,14px) clamp(20px,2.6vw,32px);font-size:clamp(13px,1.5vw,16px);box-shadow:none;border-radius:clamp(10px,1.4vw,16px)}
.retry-btn svg{width:clamp(15px,1.8vw,19px);height:clamp(15px,1.8vw,19px)}
.btn-danger{display:inline-flex;align-items:center;gap:8px;padding:clamp(10px,1.4vw,14px) clamp(20px,2.6vw,32px);background:rgba(239,68,68,.14);border:1px solid rgba(239,68,68,.35);border-radius:clamp(10px,1.4vw,16px);color:#fca5a5;font-size:clamp(13px,1.5vw,16px);font-weight:600;text-decoration:none;transition:all .2s;cursor:pointer}
.btn-danger:hover{background:rgba(239,68,68,.24);border-color:rgba(239,68,68,.55);color:#fecaca;transform:translateY(-1px)}
.btn-danger svg{width:clamp(15px,1.8vw,19px);height:clamp(15px,1.8vw,19px)}
.btn-primary{display:inline-flex;align-items:center;justify-content:center;gap:clamp(8px,1.1vw,12px);padding:clamp(13px,1.8vw,18px) clamp(24px,3vw,40px);background:linear-gradient(135deg,#6366f1,#8b5cf6);border:none;border-radius:clamp(12px,1.6vw,18px);color:#fff;font-size:clamp(15px,1.8vw,20px);font-weight:700;letter-spacing:.5px;cursor:pointer;transition:all .25s;box-shadow:0 8px 28px rgba(99,102,241,.35)}
.btn-primary:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 14px 40px rgba(124,58,237,.45);background:linear-gradient(135deg,#4f46e5,#7c3aed)}
.btn-primary:active:not(:disabled){transform:translateY(0)}
.btn-primary:disabled{opacity:.45;cursor:not-allowed;transform:none;box-shadow:none}
.btn-primary svg{width:clamp(17px,2vw,23px);height:clamp(17px,2vw,23px)}
.bounce{animation:bounce 1s infinite}
@keyframes bounce{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}

/* 密码门 */
.pw-card{position:relative;width:min(92vw,460px);padding:clamp(30px,4.5vw,54px) clamp(20px,3.5vw,44px);background:rgba(15,23,42,.75);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);border:1px solid rgba(148,163,184,.14);border-radius:clamp(20px,3vw,32px);box-shadow:0 24px 80px rgba(0,0,0,.5);text-align:center;overflow:hidden;animation:fadeUp .4s ease}
.pw-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,transparent,#8b5cf6,transparent)}
.pw-lock{width:clamp(76px,10vw,104px);height:clamp(76px,10vw,104px);margin:0 auto clamp(14px,2vw,24px);border-radius:50%;background:rgba(99,102,241,.1);border:1px solid rgba(129,140,248,.35);display:flex;align-items:center;justify-content:center;color:#c4b5fd;transition:all .3s}
.pw-lock svg{width:clamp(34px,4.5vw,46px);height:clamp(34px,4.5vw,46px)}
.pw-lock.locked{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.4);color:#fca5a5}
.pw-lock.shake{animation:shake .4s ease}
@keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-7px)}40%{transform:translateX(7px)}60%{transform:translateX(-5px)}80%{transform:translateX(5px)}}
.pw-title{color:#f1f5f9;font-size:clamp(22px,3vw,32px);font-weight:700;margin-bottom:clamp(6px,.8vw,10px)}
.pw-sub{color:#94a3b8;font-size:clamp(12px,1.4vw,15px);margin-bottom:clamp(14px,2vw,22px)}
.pw-timer{display:inline-flex;align-items:center;gap:8px;margin-bottom:clamp(12px,1.6vw,18px);padding:clamp(8px,1.1vw,12px) clamp(14px,1.8vw,22px);background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.22);border-radius:999px;color:#fca5a5;font-size:clamp(14px,1.7vw,18px);font-weight:600}
.pw-timer svg{width:clamp(15px,1.7vw,19px);height:clamp(15px,1.7vw,19px)}
.pw-error{display:flex;align-items:center;gap:8px;margin-bottom:clamp(12px,1.6vw,16px);padding:clamp(10px,1.4vw,13px) clamp(13px,1.7vw,18px);background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.22);border-radius:clamp(10px,1.4vw,14px);color:#fca5a5;font-size:clamp(12px,1.4vw,15px);text-align:left;animation:fadeUp .3s ease}
.pw-error-dot{width:7px;height:7px;border-radius:50%;background:#f87171;flex-shrink:0;box-shadow:0 0 8px rgba(248,113,113,.5)}
.pw-attempts{display:flex;flex-direction:column;align-items:center;gap:clamp(6px,.9vw,10px);margin-bottom:clamp(12px,1.6vw,16px)}
.pw-dots{display:flex;gap:clamp(7px,1vw,11px)}
.pw-dot{width:clamp(8px,1.2vw,11px);height:clamp(8px,1.2vw,11px);border-radius:50%;background:rgba(71,85,105,.5);transition:all .3s}
.pw-dot.used{background:#f87171;box-shadow:0 0 8px rgba(248,113,113,.5)}
.pw-attempts p{color:#94a3b8;font-size:clamp(11px,1.3vw,14px)}
.pw-attempts strong{color:#f87171}
.pw-form{display:flex;flex-direction:column;gap:clamp(10px,1.4vw,14px)}
.pw-input{display:flex;align-items:center;background:rgba(2,6,23,.6);border:1.5px solid rgba(71,85,105,.4);border-radius:clamp(12px,1.6vw,16px);overflow:hidden;transition:all .25s}
.pw-input:focus-within{border-color:#8b5cf6;box-shadow:0 0 0 4px rgba(139,92,246,.12)}
.pw-input.error{border-color:rgba(239,68,68,.55);box-shadow:0 0 0 4px rgba(239,68,68,.08)}
.pw-input-icon{width:clamp(17px,2vw,21px);height:clamp(17px,2vw,21px);color:#64748b;margin-left:clamp(12px,1.7vw,16px);flex-shrink:0}
.pw-input input{flex:1;min-width:0;padding:clamp(14px,1.9vw,18px) clamp(8px,1.2vw,12px);background:transparent;border:none;outline:none;color:#fff;font-size:clamp(16px,2vw,21px);letter-spacing:3px;font-family:inherit}
.pw-input input::placeholder{color:#475569;letter-spacing:0;font-size:clamp(13px,1.6vw,16px)}
.pw-eye-btn{padding:clamp(8px,1.1vw,12px) clamp(10px,1.4vw,14px);background:transparent;border:none;color:#64748b;cursor:pointer;flex-shrink:0;transition:color .15s;display:flex}
.pw-eye-btn:hover{color:#a78bfa}
.pw-eye-btn svg{width:clamp(17px,2vw,21px);height:clamp(17px,2vw,21px)}
.pw-submit{width:100%}
.pw-contact{display:flex;align-items:center;justify-content:center;gap:7px;margin-top:clamp(14px,1.8vw,20px);padding:clamp(9px,1.2vw,12px);background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.18);border-radius:clamp(9px,1.2vw,13px);color:#a5b4fc;font-size:clamp(11px,1.3vw,14px)}
.pw-contact svg{width:clamp(14px,1.5vw,17px);height:clamp(14px,1.5vw,17px);flex-shrink:0;color:#818cf8}
.pw-hint{margin-top:clamp(14px,1.8vw,20px);color:#475569;font-size:clamp(11px,1.2vw,13px)}

/* 主内容 */
.main-wrap{width:min(96vw,1120px);display:flex;flex-direction:column;gap:clamp(14px,2vw,24px)}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:clamp(10px,1.6vw,18px);flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:clamp(8px,1vw,12px);color:#e2e8f0;font-size:clamp(16px,2vw,24px);font-weight:800;letter-spacing:.5px}
.brand-icon{width:clamp(24px,2.8vw,36px);height:clamp(24px,2.8vw,36px);color:#a78bfa}
.secure-badge{display:inline-flex;align-items:center;gap:clamp(4px,.7vw,8px);padding:clamp(6px,.8vw,10px) clamp(12px,1.4vw,18px);background:rgba(52,211,153,.08);border:1px solid rgba(52,211,153,.22);border-radius:999px;color:#34d399;font-size:clamp(11px,1.2vw,15px);font-weight:600;white-space:nowrap}
.secure-badge svg{width:clamp(14px,1.6vw,20px);height:clamp(14px,1.6vw,20px);flex-shrink:0}
.main-card{position:relative;background:rgba(15,23,42,.72);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border:1px solid rgba(148,163,184,.12);border-radius:clamp(18px,2.6vw,30px);overflow:hidden;box-shadow:0 28px 90px rgba(0,0,0,.55)}
.card-glow-bar{height:4px;background:linear-gradient(90deg,#6366f1,#a78bfa,#8b5cf6,#6366f1);background-size:200% 100%;animation:glow 6s linear infinite}
@keyframes glow{0%{background-position:0 0}100%{background-position:200% 0}}
.card-body{padding:clamp(22px,3vw,44px)}
.file-head{display:flex;align-items:center;gap:clamp(14px,2vw,26px);margin-bottom:clamp(16px,2.2vw,30px)}
.file-tile{width:clamp(56px,8vw,96px);height:clamp(56px,8vw,96px);border-radius:clamp(14px,1.8vw,22px);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.tile-icon{width:clamp(28px,4vw,48px);height:clamp(28px,4vw,48px)}
.tile-folder{color:#c4b5fd;background:linear-gradient(135deg,rgba(99,102,241,.18),rgba(139,92,246,.16));border:1px solid rgba(139,92,246,.3)}
.tint-doc{color:#60a5fa;background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.24)}
.tint-img{color:#fb7185;background:rgba(244,63,94,.1);border:1px solid rgba(244,63,94,.24)}
.tint-video{color:#c084fc;background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.24)}
.tint-audio{color:#34d399;background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.24)}
.tint-archive{color:#fbbf24;background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.24)}
.file-head-info{flex:1;min-width:0}
.file-title{color:#f8fafc;font-size:clamp(18px,2.6vw,32px);font-weight:700;line-height:1.3;word-break:break-word;margin-bottom:clamp(6px,.9vw,12px)}
.file-tags{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.tag{display:inline-flex;align-items:center;padding:clamp(3px,.5vw,6px) clamp(8px,1.1vw,13px);background:rgba(148,163,184,.1);border:1px solid rgba(148,163,184,.12);border-radius:8px;color:#94a3b8;font-size:clamp(11px,1.2vw,15px);font-weight:600;letter-spacing:.4px;text-transform:uppercase}
.tag-folder{background:rgba(139,92,246,.1);border-color:rgba(139,92,246,.25);color:#c4b5fd;text-transform:none}
.desc{display:flex;gap:clamp(10px,1.5vw,16px);margin-bottom:clamp(16px,2.2vw,30px);padding:clamp(13px,1.8vw,20px) clamp(14px,1.9vw,22px);background:rgba(99,102,241,.06);border:1px solid rgba(99,102,241,.16);border-radius:clamp(12px,1.6vw,18px)}
.desc-icon{width:clamp(32px,3.4vw,40px);height:clamp(32px,3.4vw,40px);border-radius:10px;background:rgba(99,102,241,.14);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.desc-icon svg{width:55%;height:55%;color:#a5b4fc}
.desc-label{color:#e2e8f0;font-weight:600;font-size:clamp(13px,1.5vw,17px);margin-bottom:clamp(3px,.5vw,7px)}
.desc-text{color:#94a3b8;font-size:clamp(12px,1.4vw,16px);line-height:1.7;word-break:break-word}
.folder-block{margin-bottom:clamp(16px,2.2vw,30px)}
.folder-head{display:flex;align-items:center;justify-content:space-between;gap:clamp(10px,1.5vw,18px);flex-wrap:wrap;margin-bottom:clamp(10px,1.3vw,16px)}
.folder-title{color:#e2e8f0;font-size:clamp(14px,1.7vw,20px);font-weight:600}
.folder-list{display:flex;flex-direction:column;gap:clamp(7px,1vw,10px);max-height:360px;overflow-y:auto;padding-right:2px}
.folder-list::-webkit-scrollbar{width:6px}
.folder-list::-webkit-scrollbar-thumb{background:rgba(148,163,184,.25);border-radius:999px}
.folder-row{display:flex;align-items:center;gap:clamp(10px,1.4vw,16px);padding:clamp(9px,1.2vw,14px) clamp(12px,1.6vw,18px);background:rgba(148,163,184,.04);border:1px solid rgba(148,163,184,.07);border-radius:clamp(10px,1.3vw,15px);transition:background .2s}
.folder-row:hover{background:rgba(148,163,184,.08)}
.row-icon{width:clamp(36px,4vw,46px);height:clamp(36px,4vw,46px);border-radius:11px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.row-icon svg{width:50%;height:50%}
.row-info{flex:1;min-width:0}
.row-name{color:#e2e8f0;font-size:clamp(13px,1.4vw,17px);font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.row-meta{color:#64748b;font-size:clamp(10px,1.1vw,13px);margin-top:3px}
.row-dl{display:inline-flex;align-items:center;gap:6px;padding:clamp(6px,.9vw,10px) clamp(11px,1.4vw,16px);background:rgba(99,102,241,.12);border:1px solid rgba(129,140,248,.3);border-radius:clamp(7px,1vw,11px);color:#a5b4fc;font-size:clamp(11px,1.2vw,14px);font-weight:600;text-decoration:none;transition:all .2s;flex-shrink:0}
.row-dl:hover{background:rgba(99,102,241,.22);border-color:rgba(129,140,248,.5);color:#c7d2fe}
.row-dl svg{width:clamp(13px,1.5vw,16px);height:clamp(13px,1.5vw,16px)}
.dl-error{display:flex;align-items:center;gap:7px;margin:clamp(8px,1.2vw,14px) 0 0;color:#fca5a5;font-size:clamp(12px,1.3vw,14px)}
.dl-error svg{width:clamp(14px,1.5vw,17px);height:clamp(14px,1.5vw,17px);flex-shrink:0}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:clamp(8px,1.2vw,14px);margin-bottom:clamp(16px,2.2vw,30px)}
.stat{display:flex;align-items:center;gap:clamp(8px,1.2vw,13px);padding:clamp(11px,1.5vw,17px) clamp(12px,1.6vw,18px);background:rgba(148,163,184,.04);border:1px solid rgba(148,163,184,.08);border-radius:clamp(11px,1.4vw,16px);min-width:0}
.stat-icon{width:clamp(17px,2vw,23px);height:clamp(17px,2vw,23px);color:#818cf8;flex-shrink:0}
.stat-label{color:#64748b;font-size:clamp(10px,1.1vw,13px);margin-bottom:3px;white-space:nowrap}
.stat-value{color:#e2e8f0;font-size:clamp(12px,1.4vw,17px);font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.stat-value.expired{color:#f87171}
.action-row{display:flex;align-items:center;gap:clamp(10px,1.5vw,16px);flex-wrap:wrap;margin-bottom:clamp(14px,1.8vw,22px)}
.dl-btn{flex:1;min-width:220px}
.share-row{display:flex;align-items:center;gap:clamp(8px,1.2vw,12px);flex-wrap:wrap;margin-bottom:clamp(16px,2.2vw,30px)}
.share-label{display:inline-flex;align-items:center;gap:7px;color:#94a3b8;font-size:clamp(12px,1.3vw,15px);font-weight:600}
.share-label svg{width:clamp(15px,1.7vw,19px);height:clamp(15px,1.7vw,19px);color:#818cf8}
.share-chip{display:inline-flex;align-items:center;gap:6px;padding:clamp(7px,1vw,10px) clamp(12px,1.5vw,16px);background:rgba(255,255,255,.04);border:1px solid rgba(148,163,184,.16);border-radius:999px;color:#cbd5e1;font-size:clamp(11px,1.2vw,14px);text-decoration:none;transition:all .2s}
.share-chip:hover{background:rgba(148,163,184,.12);color:#fff;transform:translateY(-1px)}
.share-chip svg{width:clamp(13px,1.5vw,16px);height:clamp(13px,1.5vw,16px)}
.limit{margin-bottom:clamp(16px,2.2vw,30px);padding:clamp(13px,1.7vw,19px) clamp(14px,1.8vw,20px);background:rgba(148,163,184,.04);border:1px solid rgba(148,163,184,.08);border-radius:clamp(12px,1.5vw,17px)}
.limit-head{display:flex;align-items:center;gap:8px;color:#cbd5e1;font-size:clamp(12px,1.3vw,15px);font-weight:600;margin-bottom:clamp(8px,1.1vw,12px)}
.limit-head svg{width:clamp(14px,1.6vw,18px);height:clamp(14px,1.6vw,18px);color:#818cf8}
.limit-count{margin-left:auto;color:#94a3b8;font-weight:500}
.limit-bar{height:clamp(8px,1vw,11px);background:rgba(71,85,105,.35);border-radius:999px;overflow:hidden}
.limit-fill{height:100%;background:linear-gradient(90deg,#6366f1,#a78bfa);border-radius:999px;transition:width .6s ease}
.limit-hint{color:#64748b;font-size:clamp(10px,1.1vw,13px);margin-top:clamp(6px,.9vw,10px)}
.sharer{display:flex;align-items:center;gap:clamp(11px,1.5vw,17px);margin-bottom:clamp(16px,2.2vw,30px);padding:clamp(12px,1.6vw,19px) clamp(14px,1.8vw,20px);background:rgba(99,102,241,.05);border:1px solid rgba(99,102,241,.14);border-radius:clamp(12px,1.5vw,17px)}
.avatar{width:clamp(42px,5vw,58px);height:clamp(42px,5vw,58px);border-radius:50%;background:linear-gradient(135deg,#6366f1,#8b5cf6);display:flex;align-items:center;justify-content:center;overflow:hidden;flex-shrink:0}
.avatar svg{width:50%;height:50%;color:#fff}
.avatar img{width:100%;height:100%;object-fit:cover}
.sharer-info{flex:1;min-width:0}
.sharer-top{display:flex;align-items:center;gap:clamp(6px,.9vw,10px);flex-wrap:wrap;margin-bottom:clamp(4px,.6vw,8px)}
.sharer-label{color:#64748b;font-size:clamp(11px,1.2vw,14px)}
.sharer-name{color:#f1f5f9;font-size:clamp(13px,1.5vw,17px);font-weight:700}
.verify{display:inline-flex;align-items:center;gap:4px;padding:clamp(2px,.4vw,4px) clamp(7px,1vw,10px);background:rgba(52,211,153,.1);border:1px solid rgba(52,211,153,.28);border-radius:999px;color:#34d399;font-size:clamp(10px,1.1vw,12px);font-weight:600}
.verify svg{width:clamp(11px,1.2vw,14px);height:clamp(11px,1.2vw,14px)}
.sharer-meta{display:flex;align-items:center;gap:clamp(8px,1.2vw,14px);flex-wrap:wrap}
.meta{display:inline-flex;align-items:center;gap:4px;color:#94a3b8;font-size:clamp(10px,1.2vw,13px)}
.meta svg{width:clamp(11px,1.3vw,14px);height:clamp(11px,1.3vw,14px)}
.card-footer{text-align:center;padding-top:clamp(14px,1.8vw,22px);border-top:1px solid rgba(148,163,184,.09)}
.footer-links{display:flex;align-items:center;justify-content:center;gap:clamp(8px,1vw,12px);flex-wrap:wrap;color:#94a3b8;font-size:clamp(11px,1.3vw,15px);margin-bottom:clamp(6px,.9vw,10px)}
.footer-brand{display:inline-flex;align-items:center;gap:6px;color:#c4b5fd;font-weight:700}
.footer-brand svg{width:clamp(14px,1.6vw,18px);height:clamp(14px,1.6vw,18px)}
.footer-links a{color:#a5b4fc;text-decoration:none;transition:color .2s}
.footer-links a:hover{color:#c7d2fe}
.dot{color:#475569}
.footer-copy{color:#475569;font-size:clamp(10px,1.1vw,13px)}
@keyframes fadeUp{0%{opacity:0;transform:translateY(14px)}100%{opacity:1;transform:translateY(0)}}
@media (max-width:760px){
  .stats{grid-template-columns:repeat(2,1fr)}
  .file-head{flex-direction:column;text-align:center}
  .file-tags{justify-content:center}
  .action-row{flex-direction:column}
  .dl-btn{width:100%}
  .topbar{flex-direction:column;align-items:flex-start}
}
@media (min-width:1920px){
  .main-wrap{max-width:1380px}
}
</style>
