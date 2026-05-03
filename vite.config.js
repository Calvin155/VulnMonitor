import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,

    proxy: {
      '/api': {
        target: 'http://192.168.8.70:3001',
        changeOrigin: true,
      },

      '/pentester': {
        target: 'http://192.168.8.70:8000',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/pentester/, ''),
      },
    },
  },
})