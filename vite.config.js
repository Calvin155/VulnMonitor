import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'

const certExists = fs.existsSync('./localhost+1-key.pem') && fs.existsSync('./localhost+1.pem')

// Local dev: HTTP on 5173
// Pi (certs present): HTTPS on 443
const port = Number(process.env.PORT) || (certExists ? 443 : 5173)

export default defineConfig({
  plugins: [react()],

  server: {
    host: true,
    port,

    https: certExists ? {
      key: fs.readFileSync('./localhost+1-key.pem'),
      cert: fs.readFileSync('./localhost+1.pem'),
    } : false,

    proxy: {
      '/api': {
        target: process.env.API_URL || 'http://localhost:3001',
        changeOrigin: true,
      },
      '/pentester': {
        target: process.env.PENTESTER_URL || 'http://localhost:8000',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/pentester/, ''),
      },
    },
  },
})
