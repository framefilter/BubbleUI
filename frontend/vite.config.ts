import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  build: {
    target: 'es2022',
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        manualChunks: undefined,
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Each daemon listens on its own port in dev. On the router
      // they all sit behind uhttpd at the same origin.
      '/auth': 'http://127.0.0.1:8765', // bubble-authd
      '/api':  'http://127.0.0.1:8765',
      '/vpn':  'http://127.0.0.1:8766', // bubble-vpnd
      '/net':  'http://127.0.0.1:8767', // bubble-netd
      '/ubus': 'http://127.0.0.1:8765',
    },
  },
});
