# CleanTraffic

A security-focused HTTP testing toolkit similar to Burp Suite and HTTP Toolkit. Built with Electron and TypeScript.

## Features

### Traffic
- **HTTP/HTTPS Interception** – Capture and inspect browser/mobile traffic
- **Repeater** – Modify and resend requests (Postman-style)
- **Scanner** – JS vulnerability scanning with Semgrep rules
- **Intruder** – Fuzzing and parameter testing

### Analysis
- **Sequencer** – Token/entropy analysis
- **Extractor** – Extract data from responses
- **Response Analyzer** – Inspect responses

### Utilities
- **JWT Decoder** – Decode and verify JWTs
- **Notes & Tags** – Annotate requests

### Integrations
- **GitHub Scanner** – Scan repos for vulnerabilities
- **Web3 Tools** – Smart contract and wallet analysis

## Installation

1. Clone the repository:
```bash
cd sec-toolkit
npm install
```

2. Build the application:
```bash
npm run build
```

3. Start the application:
```bash
npm start
```

For development:
```bash
npm run dev
```

## Usage

### Desktop Traffic Capture

1. Start the application
2. The proxy server will start automatically on port 8000
3. Configure your browser/system to use the proxy:
   - HTTP Proxy: `localhost:8000`
   - HTTPS Proxy: `localhost:8001`

### Mobile Traffic Capture

1. Ensure your mobile device and computer are on the same network
2. Find your computer's IP address
3. Configure your mobile device's proxy settings:
   - Host: `<your-computer-ip>`
   - Port: `8000`
4. Install the certificate on your mobile device (certificate location will be shown in the app)
5. Start browsing - all traffic will be captured!

### Using the Repeater

1. Select a request from the list
2. Click "Repeater" in the sidebar
3. Modify the request (method, URL, headers, body)
4. Click "Send" to resend the modified request

### Scanning JavaScript Files

1. Right-click on a JavaScript request in the list
2. Select "Send to Scanner"
3. View security vulnerabilities detected by Semgrep rules

### GraphQL Support

The toolkit automatically detects GraphQL requests and responses, providing:
- Operation name display
- Query/mutation viewing
- Variables inspection
- Response data visualization

## Building Installers

CleanTraffic supports native installers for **Windows**, **Linux**, and **macOS**. Build on each platform for best results:

| Platform | Command | Output |
|----------|---------|--------|
| Windows | `npm run dist:win` | NSIS installer + portable exe |
| Linux | `npm run dist:linux` | AppImage, .deb, .rpm |
| macOS | `npm run dist:mac` | DMG + ZIP (x64 & Apple Silicon) |
| All (Win+Linux) | `npm run dist:all` | Windows + Linux from any OS |
| macOS | `npm run dist:mac` | DMG/ZIP (must run on macOS) |

**Note:** macOS builds require running on macOS. Use `dist:all` for Windows + Linux; use `dist:mac` on a Mac for macOS installers. Output goes to `release/`.

### Browser (Chromium)

When you click **Launch** to capture traffic, CleanTraffic uses Puppeteer to run Chromium. On first launch, Chromium is downloaded automatically (~150MB) and cached in your app data. This works on all platforms (Windows, Linux, macOS). No manual browser installation is required.

## Project Structure

```
sec-toolkit/
├── src/
│   ├── main/              # Electron main process
│   │   ├── main.ts        # Entry point
│   │   ├── proxy-server.ts
│   │   ├── scanner.ts     # JS vulnerability scanner
│   │   ├── github-scanner.ts
│   │   └── ...
│   ├── renderer/          # React UI
│   │   ├── App.tsx
│   │   ├── components/    # UI components
│   │   ├── context/       # React context
│   │   └── hooks/
│   ├── preload/
│   └── shared/            # Shared types & config
│       ├── view-types.ts  # Tool/sidebar config
│       └── integration-config.ts
├── rules/                 # Semgrep rules
└── scripts/
```

## Technologies

- **Electron**: Desktop application framework
- **TypeScript**: Type-safe development
- **React**: UI framework
- **Semgrep**: Security scanning
- **Node.js**: Backend proxy server

## Security Rules

The scanner includes built-in security rules for:
- Dangerous eval() usage
- XSS vulnerabilities (innerHTML, document.write)
- Hardcoded credentials
- SQL injection patterns
- Insecure random number generation
- Sensitive data in localStorage

Custom Semgrep rules can be added in the `rules/` directory.

## License

MIT

