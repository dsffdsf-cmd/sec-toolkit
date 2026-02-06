# Browser Compatibility Guide (2024–2026)

CleanTraffic uses Puppeteer to launch Chromium for traffic interception. This document covers cross-platform compatibility, troubleshooting, and manual setup.

## Overview

When you click **Launch** to capture browser traffic, CleanTraffic tries these strategies in order:

1. **Puppeteer Chromium** – Bundled Chromium (auto-downloaded on first run, ~150MB)
2. **System Chrome/Chromium** – Uses installed Google Chrome, Chromium, or Edge
3. **Chrome channel** – Puppeteer’s `channel: 'chrome'` (standard install locations)

This fallback chain improves compatibility, especially on macOS where bundled Chromium can trigger firewall prompts.

## Platform Support

| Platform | Puppeteer Chromium | System Chrome Fallback | Notes |
|----------|--------------------|------------------------|------|
| **Windows** | ✅ | ✅ | Uses Chrome/Edge from Program Files |
| **macOS** (Intel & Apple Silicon) | ✅ | ✅ | System Chrome avoids firewall prompts |
| **Linux** | ✅ | ✅ | Uses `/usr/bin/google-chrome` or `chromium` |

## First Run

On first **Launch**, Puppeteer downloads Chromium to:

- **Electron (packaged)**: `{userData}/puppeteer-cache`
- **Development**: `~/.cleantraffic/puppeteer-cache` or `{userData}/puppeteer-cache`

The download is one-time and persists across app updates.

## Pre-download Chromium (Optional)

To download Chromium before first use:

```bash
npx puppeteer browsers install chrome
```

Or with a custom cache directory:

```bash
PUPPETEER_CACHE_DIR=./puppeteer-cache npx puppeteer browsers install chrome
```

## macOS-Specific Notes

### Firewall Prompts

Bundled Chromium may trigger: *"Do you want the application Chromium.app to accept incoming network connections?"*

**Options:**

1. **Use system Chrome** – Install [Google Chrome](https://www.google.com/chrome/). CleanTraffic will fall back to it if Puppeteer Chromium fails.
2. **Allow in Firewall** – System Settings → Privacy & Security → Firewall → Allow Chromium.
3. **Disable Firewall** – Not recommended for security.

### macOS 15+ Local Network

On macOS 15 and later, check:

- **System Settings → Privacy & Security → Local Network** – Ensure your browser or CleanTraffic is allowed if you test local IPs.

### Apple Silicon (M1/M2/M3)

Fully supported. Puppeteer 21+ handles arm64 correctly. Both bundled Chromium and system Chrome work on Apple Silicon.

## Linux-Specific Notes

### Dependencies

Chromium on Linux may need:

```bash
# Debian/Ubuntu
sudo apt install -y libgtk-3-0 libnss3 libxss1 libxtst6 xdg-utils libatspi2.0-0 libsecret-1-0

# Fedora/RHEL
sudo dnf install -y gtk3 nss libXScrnSaver libXtst xdg-utils at-spi2-core libsecret
```

### Headless / No Display

If running without a display (e.g. SSH, CI), use `xvfb`:

```bash
xvfb-run -a npm start
```

## Windows-Specific Notes

Chrome is typically at:

- `C:\Program Files\Google\Chrome\Application\chrome.exe`
- `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`
- `%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe`

CleanTraffic checks these paths for fallback.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `PUPPETEER_CACHE_DIR` | Override Chromium cache directory |
| `PUPPETEER_EXECUTABLE_PATH` | Force a specific Chrome/Chromium executable |
| `PUPPETEER_SKIP_CHROMIUM_DOWNLOAD` | Set to `1` to skip download (use system Chrome only) |

## Troubleshooting

### "Failed to launch browser"

1. Ensure Chrome or Chromium is installed if you rely on fallback.
2. On macOS: allow Chromium in Firewall or install Google Chrome.
3. On Linux: install the dependencies above.
4. Check logs for `[Browser]` messages to see which strategy was tried.

### Chromium Crashes on Launch

- **Linux**: Try `--disable-gpu` (already in our args) or run under `xvfb`.
- **macOS**: Use system Chrome as fallback.
- **All**: Ensure enough free disk space for the cache (~200MB).

### Slow First Launch

First launch downloads Chromium (~150MB). Later launches use the cached binary.

## Scanner & Path Compatibility

The Scanner (and Intruder) use cross-platform path resolution:

- **Rules directory**: Tries `process.resourcesPath/rules` (packaged) then `__dirname/../../rules` (dev)
- **Worker path**: Resolved via `app-paths.ts` for dev and packaged apps
- **Prettier**: Lazy-loaded; if unavailable (e.g. MODULE_NOT_FOUND on macOS), the scanner falls back to a simple formatter for minified code
- **Semgrep**: Paths are shell-escaped for macOS/Windows/Linux

If you see path-related errors when clicking Scan, ensure:
1. The `rules/` folder exists (bundled in the app)
2. Prettier is in `node_modules` (or the fallback formatter will be used)
3. On macOS: paths with spaces are properly escaped

## References

- [Puppeteer Configuration](https://pptr.dev/guides/configuration)
- [Chrome for Testing](https://developer.chrome.com/blog/chrome-for-testing/)
- [Puppeteer Browser Management](https://pptr.dev/browsers-api)
