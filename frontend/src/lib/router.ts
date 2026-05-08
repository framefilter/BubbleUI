// 60-line hash-router. Svelte stores would be overkill for one piece of state.
import type { Component } from 'svelte';

export interface Route {
  path: string;          // e.g. '/wifi'
  label: string;
  icon: string;          // Nerd Font glyph
  load: () => Promise<{ default: Component }>;
}

let listeners: Array<(p: string) => void> = [];

function read(): string {
  const h = window.location.hash;
  return h.startsWith('#') ? h.slice(1) || '/' : '/';
}

export function currentPath(): string {
  return read();
}

export function navigate(path: string): void {
  if (read() === path) return;
  window.location.hash = path;
}

export function onChange(fn: (p: string) => void): () => void {
  listeners.push(fn);
  const handler = () => fn(read());
  window.addEventListener('hashchange', handler);
  return () => {
    listeners = listeners.filter((l) => l !== fn);
    window.removeEventListener('hashchange', handler);
  };
}
