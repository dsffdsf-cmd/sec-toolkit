/**
 * CleanTraffic - Integration config persisted in main process (userData).
 * Used for webhook, GitHub token (when passed from renderer), Etherscan, etc.
 */

import { app } from 'electron';
import * as fs from 'fs';
import * as path from 'path';
import type { IntegrationConfig } from '../shared/integration-config';
import { DEFAULT_INTEGRATION_CONFIG, mergeIntegrationConfig } from '../shared/integration-config';

const CONFIG_FILENAME = 'integration-config.json';

function getConfigPath(): string {
  const userData = app.getPath('userData');
  return path.join(userData, CONFIG_FILENAME);
}

let cached: IntegrationConfig | null = null;

export function loadIntegrationConfig(): IntegrationConfig {
  if (cached) return cached;
  try {
    const filePath = getConfigPath();
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(raw);
      cached = mergeIntegrationConfig(parsed);
      return cached;
    }
  } catch {
    // Use default on any error
  }
  cached = { ...DEFAULT_INTEGRATION_CONFIG };
  return cached;
}

export function saveIntegrationConfig(config: IntegrationConfig | Partial<IntegrationConfig>): void {
  const merged = mergeIntegrationConfig(config);
  cached = merged;
  try {
    const filePath = getConfigPath();
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(merged, null, 2), 'utf8');
  } catch (err) {
    console.error('[Integration] Failed to save config:', err);
  }
}

export function getIntegrationConfig(): IntegrationConfig {
  return loadIntegrationConfig();
}

/** POST scan results to configured webhook URL (Slack, Discord, custom). */
export async function sendWebhookIfConfigured(payload: {
  source: 'scanner' | 'github';
  summary: string;
  totalFindings: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
  findings?: unknown[];
}): Promise<void> {
  const config = getIntegrationConfig();
  const url = (config.webhookUrl || '').trim();
  if (!url || !url.startsWith('http')) return;
  try {
    const body = JSON.stringify({
      text: payload.summary,
      cleantraffic: true,
      source: payload.source,
      totalFindings: payload.totalFindings,
      severity: {
        critical: payload.critical ?? 0,
        high: payload.high ?? 0,
        medium: payload.medium ?? 0,
        low: payload.low ?? 0,
        info: payload.info ?? 0,
      },
      findings: payload.findings?.slice(0, 20) ?? [],
    });
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    if (!res.ok) console.warn('[Integration] Webhook POST failed:', res.status, await res.text());
  } catch (err) {
    console.warn('[Integration] Webhook error:', err);
  }
}
