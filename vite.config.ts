import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    // Covers iOS Safari 12+ and Android Chrome 63+ without legacy polyfills.
    target: ['es2018', 'safari12', 'chrome63'],
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/@supabase/')) return 'supabase-vendor'
          if (id.includes('node_modules/lucide-react/')) return 'icon-vendor'
          if (id.includes('node_modules/react/') || id.includes('node_modules/react-dom/')) return 'react-vendor'
          return undefined
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8000',
    },
  },
})
