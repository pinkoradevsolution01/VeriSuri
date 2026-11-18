import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    // Covers iOS Safari 12+ and Android Chrome 63+ without legacy polyfills.
    target: ['es2018', 'safari12', 'chrome63'],
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8000',
    },
  },
})
