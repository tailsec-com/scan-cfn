export { scanCfn, CfnFinding } from './cfn.js';
import type { CfnFinding } from './cfn.js';

export function formatCfnOutput(findings: CfnFinding[], format: 'json' | 'text' = 'text'): string {
  if (format === 'json') {
    return JSON.stringify(findings, null, 2);
  }

  if (findings.length === 0) {
    return 'No security issues found.';
  }

  const lines: string[] = [];
  lines.push(`Found ${findings.length} security issue(s):\n`);

  for (const f of findings) {
    lines.push(`[${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`  Rule: ${f.ruleId}`);
    lines.push(`  Resource: ${f.resource}`);
    if (f.line) {
      lines.push(`  Line: ${f.line}`);
    }
    lines.push(`  Advice:`);
    for (const advice of f.advice) {
      lines.push(`    - ${advice}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}