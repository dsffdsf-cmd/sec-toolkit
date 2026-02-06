/**
 * Launch Electron for dev. On Linux when running as root (e.g. WSL/Docker),
 * adds --no-sandbox to avoid: "Running as root without --no-sandbox is not supported"
 */
const { spawn } = require('child_process');
const path = require('path');

const electron = require('electron');
const args = [path.join(__dirname, '..')];

if (process.platform === 'linux' && typeof process.getuid === 'function' && process.getuid() === 0) {
  args.unshift('--no-sandbox');
}

spawn(electron, args, { stdio: 'inherit' }).on('exit', (code) => process.exit(code || 0));
