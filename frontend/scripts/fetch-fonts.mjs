#!/usr/bin/env node
// Download CaskaydiaMono Nerd Font weights into ./public/fonts/.
//
// This is dev tooling only. We don't commit the binaries (see root
// .gitignore) so any contributor can rerun this and end up with the
// same files. Subsetting + WOFF2 conversion lands in M2.
//
// Requires: curl, unzip on PATH.

import { execSync } from 'node:child_process';
import { mkdirSync, existsSync, copyFileSync, rmSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const out = join(root, 'public', 'fonts');
const tmp = join(root, '.font-tmp');

const VERSION = 'v3.2.1';
const ASSET = 'CascadiaCode.zip';
const URL = `https://github.com/ryanoasis/nerd-fonts/releases/download/${VERSION}/${ASSET}`;

// What we want -> what's in the zip (mono, no ligatures variant).
const WANT = {
  'CaskaydiaMonoNerdFont-Regular.ttf':  'CaskaydiaMonoNerdFont-Regular.ttf',
  'CaskaydiaMonoNerdFont-SemiBold.ttf': 'CaskaydiaMonoNerdFont-SemiBold.ttf',
  'CaskaydiaMonoNerdFont-Italic.ttf':   'CaskaydiaMonoNerdFont-Italic.ttf',
};

mkdirSync(out, { recursive: true });
mkdirSync(tmp, { recursive: true });

const zip = join(tmp, ASSET);
console.log(`fetching ${URL}`);
execSync(`curl -fsSL -o "${zip}" "${URL}"`, { stdio: 'inherit' });

console.log('extracting');
execSync(`unzip -o -q "${zip}" -d "${tmp}"`, { stdio: 'inherit' });

const all = readdirSync(tmp);
let copied = 0;
for (const [target, source] of Object.entries(WANT)) {
  const found = all.includes(source) ? join(tmp, source) : null;
  if (!found) {
    console.warn(`! missing in archive: ${source}`);
    continue;
  }
  copyFileSync(found, join(out, target));
  copied++;
}

rmSync(tmp, { recursive: true, force: true });

if (copied === 0) {
  console.error('no fonts copied; archive layout may have changed');
  process.exit(1);
}

console.log(`done. ${copied} font(s) in ${out}`);
console.log('TODO (M2): subset + convert to woff2.');
