# Cross-Platform Compatibility Guide (2024–2026)

CleanTraffic is designed to run on **Windows**, **macOS**, and **Linux**. This document describes how compatibility is achieved and how to troubleshoot platform-specific issues.

## Supported Platforms

| Platform | Versions | Notes |
|----------|----------|-------|
| **Windows** | 10, 11 (x64) | NSIS installer, portable exe |
| **macOS** | 10.15+ (Intel & Apple Silicon) | DMG, ZIP |
| **Linux** | Ubuntu 20.04+, Fedora, etc. (x64) | AppImage, .deb, .rpm |

## Path Resolution

All paths use Node.js `path` module and `path.join()` for correct separators. No hardcoded `/` or `\`.

### App Paths (`paths.ts`)

| Function | Purpose |
|----------|---------|
| `getUserDataPath()` | App data root (Electron `userData`) |
| `getPuppeteerCacheDir()` | Chromium binary cache |
| `getChromiumUserDataDir()` | Chromium profile (short path for macOS socket) |
| `getCertsDir()` | CA certs |
| `getSessionsDir()` | Sessions |
| `getRulesDir()` | Semgrep rules |
| `getScannerWorkerPath()` | Worker script |
| `getPreloadPath()` | Preload script |
| `getHtmlPath()` | Renderer `index.html` |
| `shellEscapePath()` | Escape paths for shell commands |

### User Data – unified structure

One root, same layout everywhere (dev, prod, packaged):

- **Windows**: `%APPDATA%\CleanTraffic`
- **macOS**: `~/Library/Application Support/CleanTraffic`
- **Linux**: `~/.config/CleanTraffic`

Subdirs: `browser/`, `browser-profile/`, `certs/`, `sessions/`

### Certificate Migration

Legacy certs from `~/.sec-toolkit` (or `%APPDATA%\.sec-toolkit` on Windows) are automatically migrated to `{userData}/certs` on first run.

## Shell & Exec

### Windows

- `exec`/`execSync` use `COMSPEC` or `cmd.exe` when `shell` is needed
- Paths are double-quoted and backslashes escaped for `cmd.exe`
- Semgrep and git clone commands use platform-aware options

### macOS / Linux

- Paths are single-quoted with embedded quotes escaped
- No `shell` for `exec` unless required (avoids shell injection)

## Module Loading

- **Prettier**: Lazy-loaded in scanner; fallback formatter if unavailable (avoids `MODULE_NOT_FOUND` on packaged macOS)
- **Electron**: `app.getPath()` used only when `app.isReady()`
- **Workers**: Paths resolved via `paths.ts` for dev and packaged

## Platform-Specific Behavior

### Linux

- Hardware acceleration disabled to avoid GPU crashes (WSL, some distros)
- `GIO_USE_VFS=local` set to suppress GLib warnings
- Semgrep/git: no `shell` by default

### macOS

- `titleBarStyle: 'hidden'` for native look
- Browser: `--use-mock-keychain` to avoid keychain prompts
- Certificate install: Keychain integration

### Windows

- `exec` uses `cmd.exe` for git clone and similar commands
- Paths with spaces handled via `shellEscapePath`

## Troubleshooting

### "HTML file not found"

- Run `npm run build` before `npm start`
- In packaged app, ensure `dist/` and `renderer/` are in the build

### "Rules not found" / Semgrep config missing

- Ensure `rules/` exists at project root (dev) or in `extraResources` (packaged)
- Check `getRulesDir()` returns a path where `javascript-security.yml` exists

### Prettier / MODULE_NOT_FOUND

- Scanner falls back to simple formatter; scan still works
- Ensure `prettier` is in `dependencies` (not just devDependencies) for packaged builds

### Certificate path errors

- Certs live in `{userData}/certs`
- Legacy `~/.sec-toolkit` is migrated automatically
- Reinstall CA if migration fails

### GitHub Scanner clone fails on Windows

- Ensure `git` is in PATH
- `execSync` uses `cmd.exe`; paths are quoted
- Check antivirus isn’t blocking git

## References

- [Electron process.resourcesPath](https://www.electronjs.org/docs/latest/api/process)
- [Node path module](https://nodejs.org/api/path.html)
- [docs/BROWSER.md](BROWSER.md) – Browser/Chromium compatibility
