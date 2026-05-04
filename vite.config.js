import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'

export default defineConfig({
  plugins: [react()],

  server: {
    host: true,
    port: 5173,

    https: {
      key: fs.readFileSync('./localhost+1-key.pem'),
      cert: fs.readFileSync('./localhost+1.pem'),
    },

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