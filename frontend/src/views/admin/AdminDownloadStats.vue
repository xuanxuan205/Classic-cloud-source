<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAdminStore } from '@/stores/admin'
import Layout from '@/components/Layout.vue'
import { BarChart3, TrendingUp, Download, Files, FileDown, Loader2, Trophy, Info } from 'lucide-vue-next'

const adminStore = useAdminStore()
const loading = ref(true)
const totalDownloads = ref(0)
const totalFiles = ref(0)
const topFiles = ref<{ id: number; name: string; count: number; size: number }[]>([])

const avgDownloads = computed(() => {
  if (!totalFiles.value) return 0
  return totalDownloads.value / totalFiles.value
})

const maxCount = computed(() => topFiles.value[0]?.count || 1)
const activeFiles = computed(() => topFiles.value.filter(f => f.count > 0).length)

function formatCount(n: number): string {
  if (n >= 10000) return (n / 10000).toFixed(1) + 'w'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'k'
  return String(n)
}

function formatSize(bytes: number): string {
  if (!bytes && bytes !== 0) return '-'
  if (bytes >= 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB'
  if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return bytes + ' B'
}

function percentOf(count: number): string {
  if (!totalDownloads.value) return '0'
  return ((count / totalDownloads.value) * 100).toFixed(1)
}

onMounted(async () => {
  loading.value = true
  try {
    const res: any = await adminStore.getDownloadStats()
    if (res.success && res.data) {
      totalDownloads.value = res.data.totalDownloads || 0
    }
    const fres: any = await adminStore.getFiles(0, 200)
    const list = fres?.data?.content || []
    totalFiles.value = fres?.data?.totalElements ?? list.length
    topFiles.value = list
      .map((f: any) => ({ id: f.id, name: f.original_name || f.filename || '未命名文件', count: f.download_count || 0, size: f.file_size || 0 }))
      .sort((a: any, b: any) => b.count - a.count)
      .slice(0, 10)
  } catch (e: any) { console.error(e) }
  loading.value = false
})
</script>

<template>
  <Layout>
    <div class="space-y-6">
      <div>
        <h1 class="text-3xl font-bold text-white flex items-center gap-3">
          <BarChart3 class="w-7 h-7 text-blue-400" />下载统计
        </h1>
        <p class="text-slate-400 mt-2">系统文件下载数据实时汇总与热门排行</p>
      </div>

      <div v-if="loading" class="text-center py-16 text-slate-400">
        <Loader2 class="w-8 h-8 animate-spin mx-auto mb-3" />
        <p class="text-sm">正在加载统计数据...</p>
      </div>

      <div v-else class="space-y-6">
        <!-- 统计卡片 -->
        <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
          <div class="bg-slate-800/60 rounded-2xl p-6 border border-slate-700/30 hover:border-blue-500/40 transition-all group">
            <div class="flex items-center justify-between mb-4">
              <div class="w-11 h-11 bg-blue-500/20 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform">
                <Download class="w-5 h-5 text-blue-400" />
              </div>
              <span class="text-xs px-2 py-1 bg-blue-500/10 text-blue-400 rounded-full">累计</span>
            </div>
            <p class="text-3xl font-bold text-white">{{ formatCount(totalDownloads) }}</p>
            <p class="text-slate-400 text-sm mt-2">总下载次数</p>
          </div>

          <div class="bg-slate-800/60 rounded-2xl p-6 border border-slate-700/30 hover:border-indigo-500/40 transition-all group">
            <div class="flex items-center justify-between mb-4">
              <div class="w-11 h-11 bg-indigo-500/20 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform">
                <Files class="w-5 h-5 text-indigo-400" />
              </div>
              <span class="text-xs px-2 py-1 bg-indigo-500/10 text-indigo-400 rounded-full">全站</span>
            </div>
            <p class="text-3xl font-bold text-white">{{ totalFiles }}</p>
            <p class="text-slate-400 text-sm mt-2">纳入统计文件数</p>
          </div>

          <div class="bg-slate-800/60 rounded-2xl p-6 border border-slate-700/30 hover:border-emerald-500/40 transition-all group">
            <div class="flex items-center justify-between mb-4">
              <div class="w-11 h-11 bg-emerald-500/20 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform">
                <TrendingUp class="w-5 h-5 text-emerald-400" />
              </div>
              <span class="text-xs px-2 py-1 bg-emerald-500/10 text-emerald-400 rounded-full">均值</span>
            </div>
            <p class="text-3xl font-bold text-white">{{ avgDownloads.toFixed(1) }}</p>
            <p class="text-slate-400 text-sm mt-2">平均每文件下载</p>
          </div>

          <div class="bg-slate-800/60 rounded-2xl p-6 border border-slate-700/30 hover:border-amber-500/40 transition-all group">
            <div class="flex items-center justify-between mb-4">
              <div class="w-11 h-11 bg-amber-500/20 rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform">
                <FileDown class="w-5 h-5 text-amber-400" />
              </div>
              <span class="text-xs px-2 py-1 bg-amber-500/10 text-amber-400 rounded-full">热度</span>
            </div>
            <p class="text-3xl font-bold text-white">{{ formatCount(maxCount) }}</p>
            <p class="text-slate-400 text-sm mt-2">最高单文件下载</p>
          </div>
        </div>

        <!-- 热门排行 -->
        <div class="bg-slate-800/60 rounded-2xl border border-slate-700/30 overflow-hidden">
          <div class="flex items-center justify-between p-6 border-b border-slate-700/30">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 bg-gradient-to-br from-amber-500 to-orange-500 rounded-xl flex items-center justify-center">
                <Trophy class="w-5 h-5 text-white" />
              </div>
              <div>
                <h3 class="text-lg font-semibold text-white">文件下载排行 TOP 10</h3>
                <p class="text-slate-500 text-xs mt-0.5">按累计下载次数排序</p>
              </div>
            </div>
            <div class="text-right">
              <p class="text-slate-400 text-sm">{{ activeFiles }} 个文件有下载记录</p>
              <p class="text-slate-600 text-xs mt-0.5">共 {{ totalFiles }} 个文件</p>
            </div>
          </div>

          <div v-if="topFiles.length === 0" class="p-12 text-center">
            <Download class="w-14 h-14 text-slate-600 mx-auto mb-4" />
            <p class="text-slate-400">暂无文件数据</p>
          </div>

          <div v-else class="divide-y divide-slate-700/20">
            <div v-for="(f, idx) in topFiles" :key="f.id" class="p-5 hover:bg-slate-700/20 transition-colors">
              <div class="flex items-center gap-4 mb-2.5">
                <div :class="[
                  'w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold flex-shrink-0',
                  idx === 0 ? 'bg-amber-500/30 text-amber-300' : idx === 1 ? 'bg-slate-400/30 text-slate-300' : idx === 2 ? 'bg-orange-700/30 text-orange-300' : 'bg-slate-700/50 text-slate-400'
                ]">{{ idx + 1 }}</div>
                <div class="flex-1 min-w-0">
                  <p class="text-white text-sm font-medium truncate">{{ f.name }}</p>
                  <p class="text-slate-500 text-xs mt-0.5">{{ formatSize(f.size) }}</p>
                </div>
                <div class="text-right flex-shrink-0">
                  <p class="text-white font-bold">{{ formatCount(f.count) }}</p>
                  <p class="text-slate-500 text-xs mt-0.5">占 {{ percentOf(f.count) }}%</p>
                </div>
              </div>
              <div class="h-2.5 bg-slate-700/40 rounded-full overflow-hidden ml-12">
                <div :class="idx === 0 ? 'bg-gradient-to-r from-amber-500 to-orange-500' : 'bg-gradient-to-r from-blue-500 to-cyan-500'"
                  class="h-full rounded-full transition-all duration-700"
                  :style="{ width: Math.max(f.count / maxCount * 100, 1) + '%' }"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- 数据说明 -->
        <div class="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 flex items-start gap-3">
          <Info class="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
          <p class="text-slate-400 text-xs leading-relaxed">
            统计数据来自系统实时汇总：总下载次数为全站累计值，文件排行取下载量最高的前 10 个文件；
            未产生下载记录的文件不计入排行。页面数据不会自动刷新，重新进入页面即可获取最新统计。
          </p>
        </div>
      </div>
    </div>
  </Layout>
</template>
