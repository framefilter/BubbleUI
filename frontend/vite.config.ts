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
      // bubble-authd defaults to :8765. /api/* and /auth/* both go there.
      // /ubus will eventually point at uhttpd on the router; for dev it
      // also routes through bubble-authd if/when a stub is added.
      '/auth': 'http://127.0.0.1:8765',
      '/api':  'http://127.0.0.1:8765',
      '/ubus': 'http://127.0.0.1:8765',
    },
  },
});
