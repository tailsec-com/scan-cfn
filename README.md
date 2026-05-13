# @tailsec/scan-cfn

Security scanner for AWS CloudFormation templates (YAML/JSON). Detects IAM wildcards, open security groups, public S3 buckets, unencrypted RDS instances, plaintext secrets, and other CloudFormation misconfigurations.

[![npm](https://img.shields.io/npm/v/@tailsec/scan-cfn)](https://www.npmjs.com/package/@tailsec/scan-cfn)
[![CI](https://github.com/tailsec-com/scan-cfn/actions/workflows/ci.yml/badge.svg)](https://github.com/tailsec-com/scan-cfn)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

## Features

- Scans CloudFormation templates (YAML and JSON)
- Pattern-based detection with regex rules
- JSON output for CI/CD integration
- No external dependencies

## Installation

```bash
npm install -g @tailsec/scan-cfn
```

## Usage

```bash
# Scan current directory
tailsec-scan-cfn .

# Scan specific files
tailsec-scan-cfn template.yaml

# Output as JSON
tailsec-scan-cfn template.yaml --json

# Scan with JSON output via npx
npx @tailsec/scan-cfn ./templates --json
```

### Programmatic

```typescript
import { scanCfn, formatCfnOutput } from '@tailsec/scan-cfn';

const findings = scanCfn(templateContent, 'template.yaml');
console.log(formatCfnOutput(findings, 'text'));
console.log(formatCfnOutput(findings, 'json'));
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--json` | false | Output as JSON |

## Supported File Types

| Format | Extensions |
|--------|------------|
| YAML | `.yaml`, `.yml` |
| JSON | `.json` |

## Detection Rules

| Rule ID | Severity | Title |
|---------|----------|-------|
| cfn-iam-wildcard | Critical | IAM policy grants wildcard (*:* or Action:* or Resource:*) |
| cfn-sg-open-rdp | Critical | Security group opens RDP (port 3389) to 0.0.0.0/0 |
| cfn-sg-all-traffic | Critical | Security group allows all traffic from 0.0.0.0/0 |
| cfn-secret-plaintext | Critical | Secret value appears to be plaintext |
| cfn-s3-public-acl | High | S3 bucket has public ACL (PublicRead or PublicReadWrite) |
| cfn-rds-unencrypted | High | RDS instance has storage encryption disabled |
| cfn-elb-no-ssl | High | ELB/ALB does not enforce SSL (uses HTTP protocol) |
| cfn-sg-openssh | High | Security group opens SSH (port 22) to 0.0.0.0/0 |
| cfn-cf-no-https | Medium | CloudFront viewer protocol policy not set to redirect to HTTPS |
| cfn-ebs-unencrypted | Medium | EBS volume not encrypted |

## Exit Codes

- `0` — Scan completed, no issues found
- `1` — Scan completed, issues found
- `2` — Scan failed (file errors, parse errors)

## Contributing

Rules are defined in `src/cfn.ts` in the `CFN_RULES` array. Each rule is an object with:

- `id` — Rule identifier (e.g., `cfn-iam-wildcard`)
- `severity` — One of: `critical`, `high`, `medium`, `low`
- `title` — Human-readable description
- `pattern` — RegExp to match against the template content

To add a new rule, append to the `CFN_RULES` array:

```typescript
{
  id: 'cfn-my-new-rule',
  severity: 'high',
  title: 'Description of the issue',
  pattern: /pattern-to-match/,
},
```

Also add corresponding advice in the `getAdvice()` function.

## License

MIT