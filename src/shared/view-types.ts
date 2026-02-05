/**
 * CleanTraffic - Shared view/tool configuration
 * Single source of truth for sidebar order, labels, and grouping.
 */

export type ViewMode =
  | 'view'
  | 'repeater'
  | 'scanner'
  | 'intruder'
  | 'jwt-decoder'
  | 'notes-tags'
  | 'sequencer'
  | 'extractor'
  | 'analyzer'
  | 'github-scanner'
  | 'web3-tools';

export interface ToolConfig {
  id: ViewMode;
  label: string;
  group: 'traffic' | 'analysis' | 'utilities' | 'integrations';
  requiresRequest?: boolean;
}

/** Ordered tool list: traffic tools → analysis → utilities → integrations */
export const TOOL_CONFIG: ToolConfig[] = [
  { id: 'view', label: 'View', group: 'traffic', requiresRequest: true },
  { id: 'repeater', label: 'Repeater', group: 'traffic', requiresRequest: true },
  { id: 'scanner', label: 'Scanner', group: 'traffic', requiresRequest: true },
  { id: 'intruder', label: 'Intruder', group: 'traffic', requiresRequest: true },
  { id: 'jwt-decoder', label: 'JWT Decoder', group: 'utilities' },
  { id: 'notes-tags', label: 'Notes & Tags', group: 'utilities', requiresRequest: true },
  { id: 'sequencer', label: 'Sequencer', group: 'analysis', requiresRequest: true },
  { id: 'extractor', label: 'Extractor', group: 'analysis', requiresRequest: true },
  { id: 'analyzer', label: 'Response Analyzer', group: 'analysis', requiresRequest: true },
  { id: 'github-scanner', label: 'GitHub Scanner', group: 'integrations' },
  { id: 'web3-tools', label: 'Web3 Tools', group: 'integrations' },
];

export const GROUP_LABELS: Record<ToolConfig['group'], string> = {
  traffic: 'Traffic',
  analysis: 'Analysis',
  utilities: 'Utilities',
  integrations: 'Integrations',
};
