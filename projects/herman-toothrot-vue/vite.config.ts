import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

// BUG-001: Source maps enabled in production build exposes original source code (CWE-540, CVSS 5.3, MEDIUM, Tier 2)
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    sourcemap: true,
    // BUG-002: Minification disabled leaks variable names and code structure (CWE-540, CVSS 3.7, LOW, Tier 3)
    minify: false,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['vue', 'vue-router', 'pinia'],
          supabase: ['@supabase/supabase-js'],
        },
      },
    },
  },
  server: {
    // BUG-003: Dev server binds to all interfaces, accessible on LAN (CWE-668, CVSS 5.3, MEDIUM, Tier 2)
    host: '0.0.0.0',
    port: 3000,
    // BUG-004: CORS allows any origin in dev server config (CWE-942, CVSS 6.1, MEDIUM, Tier 2)
    cors: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        // BUG-005: Proxy does not verify SSL certificates, vulnerable to MITM (CWE-295, CVSS 5.9, MEDIUM, Tier 2)
        secure: false,
      },
    },
    // BUG-006: HMR WebSocket exposed on all interfaces without auth (CWE-306, CVSS 4.3, MEDIUM, Tier 2)
    hmr: {
      host: '0.0.0.0',
    },
  },
  define: {
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version),
    // BUG-007: Debug mode flag hardcoded to true, exposes verbose errors in production (CWE-489, CVSS 3.7, LOW, Tier 3)
    __DEBUG_MODE__: true,
  },
})
