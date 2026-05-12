# @tailsec/scan-cfn

Security scanner for AWS CloudFormation templates (YAML/JSON).

## Installation

```bash
npm install @tailsec/scan-cfn
```

## Usage

### CLI

```bash
# Scan current directory
tailsec-scan-cfn .

# Scan specific files
tailsec-scan-cfn template.yaml

# Output JSON
tailsec-scan-cfn . --json
```

### Programmatic

```typescript
import { scanCfn, formatCfnOutput } from '@tailsec/scan-cfn';

const findings = scanCfn(templateContent, 'template.yaml');
console.log(formatCfnOutput(findings));
```

## Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| cfn-iam-wildcard | critical | IAM policy grants wildcard (*:* or Action:* or Resource:*) |
| cfn-sg-openssh | high | Security group opens SSH (port 22) to 0.0.0.0/0 |
| cfn-sg-open-rdp | critical | Security group opens RDP to 0.0.0.0/0 |
| cfn-sg-all-traffic | critical | Security group allows all traffic from 0.0.0.0/0 |
| cfn-s3-public-acl | high | S3 bucket has public ACL |
| cfn-rds-unencrypted | high | RDS instance has storage encryption disabled |
| cfn-elb-no-ssl | high | ELB/ALB does not enforce SSL |
| cfn-secret-plaintext | critical | Secret value appears to be plaintext |
| cfn-cf-no-https | medium | CloudFront viewer protocol policy not set to redirect to HTTPS |
| cfn-ebs-unencrypted | medium | EBS volume not encrypted |

## License

MIT