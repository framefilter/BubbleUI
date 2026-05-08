// Nerd Font private-use glyphs we reference. Centralising here lets us
// (a) document what each codepoint is, and (b) keep the subsetting tool
// honest about which glyphs we actually use.

export const ICON = {
  wifi:        '', // nf-fa-wifi
  wifiOff:     '', // nf-mdi-wifi_off
  shield:      '', // nf-fa-shield
  shieldOff:   '', // nf-mdi-shield_off
  lock:        '', // nf-fa-lock
  unlock:      '', // nf-fa-unlock
  key:         '', // nf-fa-key
  globe:       '', // nf-fa-globe
  bolt:        '', // nf-fa-bolt
  router:      '綾', // nf-mdi-router_wireless
  ok:          '', // nf-fa-check_circle
  warn:        '', // nf-fa-warning
  err:         '', // nf-fa-times_circle
  refresh:     '', // nf-fa-refresh
  gear:        '', // nf-fa-gear
} as const;

export type IconKey = keyof typeof ICON;
