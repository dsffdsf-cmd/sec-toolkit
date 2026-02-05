/**
 * CleanTraffic - SARIF 2.1.0 export for Scanner and GitHub Scanner findings.
 * For GitHub Code Scanning, GitLab SAST, Azure Pipelines.
 */

export interface GenericFinding {
  ruleId: string;
  severity: string;
  message: string;
  file?: string;
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  code?: string;
  cwe?: string;
  category?: string;
  [key: string]: unknown;
}

const SEVERITY_MAP: Record<string, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  error: 'error',
  medium: 'warning',
  warning: 'warning',
  low: 'warning',
  info: 'note',
  note: 'note',
};

function sarifSeverity(severity: string): 'error' | 'warning' | 'note' {
  const s = (severity || '').toLowerCase();
  return SEVERITY_MAP[s] ?? 'warning';
}

export function findingsToSarif(findings: GenericFinding[], toolName = 'CleanTraffic Scanner'): string {
  const rulesMap = new Map<string, { id: string; shortDescription: { text: string }; fullDescription?: { text: string }; properties?: Record<string, unknown> }>();
  const artifactsMap = new Map<string, number>();
  const results: Record<string, unknown>[] = [];
  let artifactIndex = 0;

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    const ruleId = f.ruleId || `finding-${i}`;
    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        shortDescription: { text: f.message?.slice(0, 200) || ruleId },
        fullDescription: f.message ? { text: f.message } : undefined,
        properties: f.cwe ? { 'security-severity': f.severity, cwe: f.cwe } : { 'security-severity': f.severity },
      });
    }

    const uri = f.file ? (f.file.startsWith('file://') ? f.file : `file:///${f.file.replace(/\\/g, '/')}`) : undefined;
    let artifactId = -1;
    if (uri) {
      const key = uri;
      if (!artifactsMap.has(key)) {
        artifactsMap.set(key, artifactIndex);
        artifactId = artifactIndex;
        artifactIndex++;
      } else {
        artifactId = artifactsMap.get(key)!;
      }
    }

    const result: Record<string, unknown> = {
      ruleId,
      level: sarifSeverity(f.severity),
      message: { text: f.message },
    };

    if (f.line != null && artifactId >= 0) {
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: { index: artifactId, uri: uri!.replace(/^file:\/\/\//, '') },
            region: {
              startLine: f.line ?? 1,
              startColumn: f.column ?? 1,
              endLine: f.endLine ?? f.line ?? 1,
              endColumn: f.endColumn ?? f.column ?? 1,
            },
          },
        },
      ];
    }

    results.push(result);
  }

  const artifacts = Array.from(artifactsMap.entries())
    .sort((a, b) => a[1] - b[1])
    .map(([uri]) => ({
      location: { uri: uri.replace(/^file:\/\//, '').replace(/^\/+/, '') },
    }));

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: toolName,
            version: '1.0.0',
            informationUri: 'https://github.com/cleantraffic/sec-toolkit',
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
        artifacts: artifacts.length ? artifacts : undefined,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
