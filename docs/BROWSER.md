# Browser

CleanTraffic uses **one browser**: Puppeteer's bundled Chromium. Same on Windows, macOS, Linux.

## Paths

| What | Path |
|------|------|
| Chromium cache | `~/.cleantraffic/browser` |
| Certs | `{userData}/certs` |
| Sessions | `{userData}/sessions` |

`userData` = Electron app data (e.g. `~/Library/Application Support/CleanTraffic` on macOS).

## Install

Chromium is installed automatically on `npm install` (postinstall). If it fails:

```bash
npm run browser:install
```

## No fallbacks

No system Chrome. No WSL hacks. One browser, one path.
