#!/usr/bin/env node
/** Install Puppeteer Chromium to CleanTraffic's app data path. Same as runtime. */
const fs = require('fs');
const { execSync } = require('child_process');
const { getBrowserCacheDir } = require('./app-paths');

const cacheDir = getBrowserCacheDir();
try {
  fs.mkdirSync(cacheDir, { recursive: true });
} catch {
  // ignore
}
process.env.PUPPETEER_CACHE_DIR = cacheDir;
process.env.PUPPETEER_SKIP_CHROMIUM_DOWNLOAD = '0';

try {
  execSync('npx puppeteer browsers install chrome', { stdio: 'inherit' });
} catch (e) {
  process.exit(1);
}
