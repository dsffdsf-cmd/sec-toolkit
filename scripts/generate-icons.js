/**
 * Generate Electron app icons from logo.svg.
 * Creates icon.ico (Windows), icon.png (fallback), and build/icons/*.png (Linux).
 */
const fs = require('fs');
const path = require('path');

const buildDir = path.join(__dirname, '../build');
const logoPath = path.join(buildDir, 'logo.svg');
const iconPngPath = path.join(buildDir, 'icon.png');
const iconsDir = path.join(buildDir, 'icons');

if (!fs.existsSync(logoPath)) {
  console.warn('[generate-icons] logo.svg not found in build/, skipping icon generation');
  process.exit(0);
}

async function generateIcons() {
  let sharp;
  try {
    sharp = require('sharp');
  } catch {
    console.warn('[generate-icons] sharp not installed. Run: npm install -D sharp');
    process.exit(0);
  }

  const sizes = [16, 32, 48, 64, 128, 256, 512];
  const svgBuffer = fs.readFileSync(logoPath);

  // Generate 1024x1024 PNG for electron-builder (used as source for all platforms)
  await sharp(svgBuffer)
    .resize(1024, 1024)
    .png()
    .toFile(iconPngPath);
  console.log('[generate-icons] Created icon.png (1024x1024)');

  // Generate Linux icons
  if (!fs.existsSync(iconsDir)) fs.mkdirSync(iconsDir, { recursive: true });
  for (const size of sizes) {
    await sharp(svgBuffer)
      .resize(size, size)
      .png()
      .toFile(path.join(iconsDir, `${size}x${size}.png`));
  }
  console.log('[generate-icons] Created build/icons/*.png');

  console.log('[generate-icons] Done');
}

generateIcons().catch((err) => {
  console.error('[generate-icons] Error:', err.message);
  process.exit(1);
});
