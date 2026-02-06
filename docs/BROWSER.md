# Browser

CleanTraffic uses **one browser**: Puppeteer's bundled Chromium. Same on Windows, macOS, Linux.

## Paths – unified structure

All app data lives under one root (Electron `userData`):

| Platform | Root |
|----------|------|
| macOS | `~/Library/Application Support/CleanTraffic` |
| Windows | `%APPDATA%\CleanTraffic` |
| Linux | `~/.config/CleanTraffic` |

Same structure everywhere:

```
{root}/
  browser/           # Chromium binary cache (Puppeteer)
  browser-profile/    # Chromium userDataDir (avoids macOS socket hangup)
  certs/
  sessions/
```

## Install

Chromium is installed automatically on `npm install` (postinstall). If it fails:

```bash
npm run browser:install
```

This installs to the same path the app uses at runtime.

## No fallbacks

No system Chrome. No WSL hacks. One browser, one path.
