/**
 * CleanTraffic - JUnit XML export for Scanner and GitHub Scanner findings.
 * For Jenkins, GitLab JUnit, and other CI that consume JUnit reports.
 */

export interface GenericFinding {
  ruleId: string;
  severity: string;
  message: string;
  file?: string;
  line?: number;
  column?: number;
  code?: string;
  cwe?: string;
  [key: string]: unknown;
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function findingsToJunit(findings: GenericFinding[], toolName = 'CleanTraffic Scanner'): string {
  const suiteName = escapeXml(toolName);
  const timestamp = new Date().toISOString();
  const testCases = findings.map((f, i) => {
    const name = escapeXml((f.message || f.ruleId || `finding-${i}`).slice(0, 200));
    const ruleId = escapeXml(String(f.ruleId || 'unknown'));
    const severity = (f.severity || '').toLowerCase();
    const isFailure = ['critical', 'high', 'medium', 'error'].includes(severity);
    const location = [f.file, f.line != null ? `:${f.line}` : ''].filter(Boolean).join('');
    const detail = [f.message, location, f.cwe ? `CWE: ${f.cwe}` : ''].filter(Boolean).join(' | ');
    const escapedDetail = escapeXml(detail.slice(0, 1000));
    if (isFailure) {
      return `<testcase classname="${suiteName}" name="${name}" time="0"><failure message="${ruleId}">${escapedDetail}</failure></testcase>`;
    }
    return `<testcase classname="${suiteName}" name="${name}" time="0"/>`;
  });
  const failures = findings.filter(
    (f) => ['critical', 'high', 'medium', 'error'].includes((f.severity || '').toLowerCase())
  ).length;
  const header = `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="${suiteName}" tests="${findings.length}" failures="${failures}" time="0" timestamp="${escapeXml(timestamp)}">\n`;
  const suite = `  <testsuite name="${suiteName}" tests="${findings.length}" failures="${failures}" time="0">\n${testCases.map((tc) => '    ' + tc).join('\n')}\n  </testsuite>\n`;
  const footer = '</testsuites>';
  return header + suite + footer;
}
