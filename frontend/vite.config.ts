import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src')
    }
  },
  build: {
    sourcemap: false,
    minify: 'esbuild',
    cssCodeSplit: true,
    reportCompressedSize: false,
    rollupOptions: {
      output: {
        entryFileNames: 'assets/[hash].js',
        chunkFileNames: 'assets/[hash].js',
        assetFileNames: 'assets/[hash][extname]'
      }
    }
  },
  esbuild: {
    legalComments: 'none',
    drop: ['console', 'debugger']
  },
  optimizeDeps: {
    esbuildOptions: {
      tsconfig: resolve(__dirname, 'tsconfig.app.json')
    }
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.VITE_API_BASE_URL || 'http://localhost:15060',
        changeOrigin: true,
        secure: false
      }
    }
  }
})
