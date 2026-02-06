const fs = require('fs');
const path = require('path');

// Ensure dist/renderer directory exists
const distRendererDir = path.join(__dirname, '../dist/renderer');
if (!fs.existsSync(distRendererDir)) {
  fs.mkdirSync(distRendererDir, { recursive: true });
}

// Copy HTML file if it doesn't exist or is outdated
const srcHtml = path.join(__dirname, '../src/renderer/index.html');
const distHtml = path.join(distRendererDir, 'index.html');

if (fs.existsSync(srcHtml)) {
  fs.copyFileSync(srcHtml, distHtml);
  console.log('HTML file copied to:', distHtml);
} else {
  console.error('Source HTML file not found:', srcHtml);
}

// Copy logo and launch SVGs for favicon and assets
const assetsDir = path.join(__dirname, '../src/renderer/assets');
const assets = ['logo.svg', 'launch.svg'];
assets.forEach((name) => {
  const src = path.join(assetsDir, name);
  const dest = path.join(distRendererDir, name);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dest);
    console.log('Copied:', name);
  }
});

