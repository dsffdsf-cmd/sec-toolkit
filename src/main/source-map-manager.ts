import * as fs from 'fs';
import * as path from 'path';
import { SourceMapConsumer } from 'source-map';
import * as prettier from 'prettier';

export interface SourceMapInfo {
  url: string;
  host: string;
  originalSource: string;
  sources: string[];
  prettified: boolean;
  timestamp: number;
}

export class SourceMapManager {
  private sourceMaps: Map<string, SourceMapInfo> = new Map();
  private prettierConfig: any;

  constructor() {
    // Prettier config for JavaScript
    this.prettierConfig = {
      parser: 'babel',
      printWidth: 120,
      tabWidth: 2,
      useTabs: false,
      semi: true,
      singleQuote: true,
      trailingComma: 'es5',
      bracketSpacing: true,
      arrowParens: 'avoid',
    };
  }

  /**
   * Extract source map URL from JavaScript code
   */
  extractSourceMapUrl(code: string): string | null {
    // Look for sourceMappingURL comment
    const sourceMapRegex = /\/\/# sourceMappingURL=(.+?)(?:\s|$)/;
    const match = code.match(sourceMapRegex);
    if (match) {
      return match[1].trim();
    }
    return null;
  }

  /**
   * Prettify JavaScript code using Prettier
   */
  async prettifyCode(code: string): Promise<string> {
    try {
      // Check if code is minified (single line, very long)
      const isMinified = code.split('\n').length < 10 && code.length > 1000;
      
      if (!isMinified) {
        // Already formatted, just return
        return code;
      }

      // Use Prettier to format
      const formatted = await prettier.format(code, this.prettierConfig);
      return formatted;
    } catch (error: any) {
      console.warn('[SourceMap] Prettier formatting failed:', error.message);
      // Return original code if prettier fails
      return code;
    }
  }

  /**
   * Parse and process a source map
   */
  async processSourceMap(
    sourceMapUrl: string,
    jsUrl: string,
    sourceMapContent: string
  ): Promise<SourceMapInfo | null> {
    try {
      const sourceMapData = JSON.parse(sourceMapContent);
      const consumer = await new SourceMapConsumer(sourceMapData);

      // Extract original sources
      const sources: string[] = sourceMapData.sources || [];
      let originalSource = '';

      // Try to get the original source if available
      if (sources.length > 0 && sourceMapData.sourcesContent) {
        // Combine all sources
        originalSource = sourceMapData.sourcesContent
          .map((content: string, index: number) => {
            const sourcePath = sources[index] || `source${index}.js`;
            return `// Source: ${sourcePath}\n${content || ''}`;
          })
          .join('\n\n');
      } else if (sourceMapData.sourcesContent && sourceMapData.sourcesContent.length > 0) {
        originalSource = sourceMapData.sourcesContent.join('\n\n');
      }

      // Prettify the original source
      let prettifiedSource = originalSource;
      if (originalSource) {
        prettifiedSource = await this.prettifyCode(originalSource);
      }

      // Extract host from URL
      const host = this.extractHost(jsUrl);

      const sourceMapInfo: SourceMapInfo = {
        url: sourceMapUrl,
        host: host,
        originalSource: prettifiedSource,
        sources: sources,
        prettified: true,
        timestamp: Date.now(),
      };

      // Store by both source map URL and JS URL
      this.sourceMaps.set(sourceMapUrl, sourceMapInfo);
      this.sourceMaps.set(jsUrl, sourceMapInfo);

      consumer.destroy();
      return sourceMapInfo;
    } catch (error: any) {
      console.error('[SourceMap] Failed to process source map:', error.message);
      return null;
    }
  }

  /**
   * Get source map info for a URL
   */
  getSourceMapInfo(url: string): SourceMapInfo | null {
    return this.sourceMaps.get(url) || null;
  }

  /**
   * Get all source maps for a specific host
   */
  getSourceMapsByHost(host: string): SourceMapInfo[] {
    const results: SourceMapInfo[] = [];
    for (const [key, info] of this.sourceMaps.entries()) {
      if (info.host === host) {
        results.push(info);
      }
    }
    return results;
  }

  /**
   * Get all source maps
   */
  getAllSourceMaps(): SourceMapInfo[] {
    return Array.from(this.sourceMaps.values());
  }

  /**
   * Extract host from URL
   */
  private extractHost(url: string): string {
    try {
      return new URL(url).hostname;
    } catch {
      return 'unknown';
    }
  }

  /**
   * Resolve source map URL (handle relative paths)
   */
  resolveSourceMapUrl(sourceMapUrl: string, baseUrl: string): string {
    try {
      // If it's already absolute, return as is
      if (sourceMapUrl.startsWith('http://') || sourceMapUrl.startsWith('https://')) {
        return sourceMapUrl;
      }

      // If it's a data URL, return as is
      if (sourceMapUrl.startsWith('data:')) {
        return sourceMapUrl;
      }

      // Resolve relative to base URL
      const base = new URL(baseUrl);
      if (sourceMapUrl.startsWith('/')) {
        return `${base.protocol}//${base.host}${sourceMapUrl}`;
      } else {
        const lastSlash = base.pathname.lastIndexOf('/');
        const basePath = lastSlash >= 0 ? base.pathname.substring(0, lastSlash) : '';
        return `${base.protocol}//${base.host}${basePath}/${sourceMapUrl}`;
      }
    } catch {
      return sourceMapUrl;
    }
  }
}

