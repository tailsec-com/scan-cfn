import { scanCfn, CfnFinding } from './cfn.js';
import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';

interface CliOptions {
  paths: string[];
  outputFormat?: 'json' | 'text';
}

function findCfnFiles(dir: string): string[] {
  const files: string[] = [];
  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      const fullPath = join(dir, entry);
      const stat = statSync(fullPath);
      if (stat.isDirectory()) {
        files.push(...findCfnFiles(fullPath));
      } else {
        const ext = extname(entry).toLowerCase();
        if (ext === '.yaml' || ext === '.yml' || ext === '.json') {
          files.push(fullPath);
        }
      }
    }
  } catch {
    // Skip inaccessible directories
  }
  return files;
}

function formatFinding(findings: CfnFinding[], format: 'json' | 'text'): string {
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

function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(`Usage: tailsec-scan-cfn <paths...> [options]
Options:
  --json    Output in JSON format
  --text    Output in text format (default)
  --help    Show this help message
`);
    process.exit(0);
  }

  const outputFormat = args.includes('--json') ? 'json' : 'text';
  const paths = args.filter((a) => !a.startsWith('--'));

  if (paths.length === 0) {
    paths.push('.');
  }

  const allFindings: CfnFinding[] = [];

  for (const targetPath of paths) {
    const stat = statSync(targetPath);
    const files = stat.isDirectory() ? findCfnFiles(targetPath) : [targetPath];

    for (const file of files) {
      try {
        const content = readFileSync(file, 'utf-8');
        const findings = scanCfn(content, file);
        allFindings.push(...findings);
      } catch (err) {
        // Skip files that can't be read
      }
    }
  }

  console.log(formatFinding(allFindings, outputFormat));

  process.exit(allFindings.length > 0 ? 1 : 0);
}

main();