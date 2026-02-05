#!/usr/bin/env node
/**
 * Local Semgrep rule validation. Runs without Semgrep CLI.
 * Checks: YAML parse, structure, duplicate IDs, required fields, severity/languages.
 */

const fs = require('fs');
const path = require('path');

const RULES_FILE = path.join(__dirname, '../rules/javascript-security.yml');
const VALID_SEVERITIES = new Set(['ERROR', 'WARNING', 'INFO']);
const VALID_LANGUAGES = new Set(['javascript', 'typescript', 'python', 'go', 'java', 'generic']);
const VALID_MODES = new Set(['taint', 'search', undefined]);

function main() {
  let yaml;
  try {
    yaml = require('js-yaml');
  } catch (e) {
    console.error('validate-rules: js-yaml not found. Install: npm install --save-dev js-yaml');
    process.exit(1);
  }

  let raw;
  try {
    raw = fs.readFileSync(RULES_FILE, 'utf8');
  } catch (e) {
    console.error('validate-rules: Cannot read', RULES_FILE, e.message);
    process.exit(1);
  }

  let doc;
  try {
    doc = yaml.load(raw);
  } catch (e) {
    console.error('validate-rules: YAML parse error:', e.message);
    process.exit(1);
  }

  if (!doc || typeof doc !== 'object') {
    console.error('validate-rules: Expected root object');
    process.exit(1);
  }

  const rules = doc.rules;
  if (!Array.isArray(rules)) {
    console.error('validate-rules: Missing or invalid "rules" array');
    process.exit(1);
  }

  const seenIds = new Set();
  const errors = [];
  let idx = 0;

  for (const r of rules) {
    idx++;
    if (!r || typeof r !== 'object') {
      errors.push(`[${idx}] Rule is not an object`);
      continue;
    }

    const id = r.id;
    if (!id || typeof id !== 'string') {
      errors.push(`[${idx}] Missing or invalid "id"`);
    } else {
      if (seenIds.has(id)) errors.push(`[${idx}] Duplicate rule id: ${id}`);
      seenIds.add(id);
    }

    if (!r.message || typeof r.message !== 'string') {
      errors.push(`[${idx}] (${id || '?'}) Missing or invalid "message"`);
    }

    const sev = r.severity;
    if (!VALID_SEVERITIES.has(sev)) {
      errors.push(`[${idx}] (${id || '?'}) Invalid "severity": ${sev}. Use ERROR, WARNING, or INFO.`);
    }

    const langs = r.languages;
    if (!langs) {
      errors.push(`[${idx}] (${id || '?'}) Missing "languages"`);
    } else if (!Array.isArray(langs)) {
      errors.push(`[${idx}] (${id || '?'}) "languages" must be array`);
    } else {
      const bad = langs.filter((l) => !VALID_LANGUAGES.has(l));
      if (bad.length) errors.push(`[${idx}] (${id || '?'}) Invalid languages: ${bad.join(', ')}`);
    }

    const mode = r.mode;
    if (mode !== undefined && !VALID_MODES.has(mode)) {
      errors.push(`[${idx}] (${id || '?'}) Invalid "mode": ${mode}. Use taint or search.`);
    }

    if (mode === 'taint') {
      if (!Array.isArray(r['pattern-sources']) || !r['pattern-sources'].length) {
        errors.push(`[${idx}] (${id || '?'}) Taint rule missing non-empty "pattern-sources"`);
      }
      if (!Array.isArray(r['pattern-sinks']) || !r['pattern-sinks'].length) {
        errors.push(`[${idx}] (${id || '?'}) Taint rule missing non-empty "pattern-sinks"`);
      }
    } else {
      const hasPattern = r.pattern
        || (Array.isArray(r.patterns) && r.patterns.length)
        || (Array.isArray(r['pattern-either']) && r['pattern-either'].length)
        || (typeof r['pattern-regex'] === 'string' && r['pattern-regex'].length);
      if (!hasPattern && !r['pattern-sources']) {
        errors.push(`[${idx}] (${id || '?'}) Non-taint rule missing "pattern", "patterns", "pattern-either", or "pattern-regex"`);
      }
    }

    if (r.options && typeof r.options !== 'object') {
      errors.push(`[${idx}] (${id || '?'}) "options" must be object`);
    }
  }

  if (errors.length) {
    console.error('validate-rules: FAILED\n');
    errors.forEach((e) => console.error('  ' + e));
    process.exit(1);
  }

  const taintCount = rules.filter((r) => r.mode === 'taint').length;
  const patternCount = rules.length - taintCount;
  console.log(`validate-rules: OK (${rules.length} rules: ${taintCount} taint, ${patternCount} pattern)`);
  process.exit(0);
}

main();
