#!/usr/bin/env node
/**
 * App data root – same path as Electron userData.
 * Used by install-browser.js so Chromium installs where the app expects it.
 * Single source for path logic outside the main process.
 */
const path = require('path');
const os = require('os');

const APP_NAME = 'CleanTraffic';

function getAppDataRoot() {
  const home = os.homedir();
  if (!home) return path.join(process.cwd(), '.cleantraffic');
  if (process.platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', APP_NAME);
  }
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
    return path.join(appData, APP_NAME);
  }
  const config = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
  return path.join(config, APP_NAME);
}

/** Subpaths – same structure everywhere */
function getBrowserCacheDir() {
  return path.join(getAppDataRoot(), 'browser');
}

function getBrowserProfileDir() {
  return path.join(getAppDataRoot(), 'browser-profile');
}

module.exports = {
  APP_NAME,
  getAppDataRoot,
  getBrowserCacheDir,
  getBrowserProfileDir,
};
