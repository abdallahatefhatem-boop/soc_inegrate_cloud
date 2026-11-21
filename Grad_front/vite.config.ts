import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'VITE_')
  const backendTarget = env.VITE_DEV_PROXY_TARGET || 'http://127.0.0.1:5086'
  const devHost = env.VITE_DEV_HOST || '127.0.0.1'
  return {
    plugins: [react()],
    server: {
      host: devHost,
      port: 5173,
      strictPort: true,
      proxy: {
        '/logs': { target: backendTarget, changeOrigin: true, ws: true },
        '/health': { target: backendTarget, changeOrigin: true },
        '/api': { target: backendTarget, changeOrigin: true },
      },
    },
  }
})
