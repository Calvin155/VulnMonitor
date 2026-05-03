import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true, // 🔥 THIS IS THE FIX
    port: 5173, // optional but nice to fix port
    proxy: {
      '/api': 'http://localhost:3001',
      '/pentester': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/pentester/, ''),
      },
    },
  },
})
