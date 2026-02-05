/**
 * CleanTraffic - Integration & API configuration (web traffic / security focus)
 * Shared types for renderer and main process. Sensitive values stored in main userData.
 */

export interface IntegrationConfig {
  /** GitHub Personal Access Token - private repos, higher rate limits */
  githubToken: string;
  /** Webhook URL - POST scan results (Slack, Discord, custom) */
  webhookUrl: string;
  /** Semgrep Cloud / CodeQL token (optional, for future) */
  semgrepCloudToken: string;
}

export const DEFAULT_INTEGRATION_CONFIG: IntegrationConfig = {
  githubToken: '',
  webhookUrl: '',
  semgrepCloudToken: '',
};

export function mergeIntegrationConfig(partial: Partial<IntegrationConfig> | null | undefined): IntegrationConfig {
  if (partial == null) return { ...DEFAULT_INTEGRATION_CONFIG };
  return { ...DEFAULT_INTEGRATION_CONFIG, ...partial };
}
