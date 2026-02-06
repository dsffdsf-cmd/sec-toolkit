#!/usr/bin/env node
/** Install Puppeteer Chromium to CleanTraffic's fixed path. Same everywhere. */
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const cacheDir = path.join(os.homedir(), '.cleantraffic', 'browser');
process.env.PUPPETEER_CACHE_DIR = cacheDir;
process.env.PUPPETEER_SKIP_CHROMIUM_DOWNLOAD = '0';

try {
  execSync('npx puppeteer browsers install chrome', { stdio: 'inherit' });
} catch (e) {
  process.exit(1);
}
