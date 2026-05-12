export interface CfnFinding {
  ruleId: string;
  type: string;
  severity: string;
  title: string;
  resource: string;
  line?: number;
  advice: string[];
}

export interface CfnRule {
  id: string;
  severity: string;
  title: string;
  pattern: RegExp;
}

const CFN_RULES: CfnRule[] = [
  {
    id: 'cfn-iam-wildcard',
    severity: 'critical',
    title: 'IAM policy grants wildcard (*:* or Action:* or Resource:*)',
    pattern: /Action\s*:\s*["']?\*["']?|Resource\s*:\s*["']?\*["']?/,
  },
  {
    id: 'cfn-sg-openssh',
    severity: 'high',
    title: 'Security group opens SSH (port 22) to 0.0.0.0/0',
    pattern: /FromPort\s*:\s*22/,
  },
  {
    id: 'cfn-sg-open-rdp',
    severity: 'critical',
    title: 'Security group opens RDP to 0.0.0.0/0',
    pattern: /FromPort\s*:\s*3389/,
  },
  {
    id: 'cfn-sg-all-traffic',
    severity: 'critical',
    title: 'Security group allows all traffic from 0.0.0.0/0',
    pattern: /IpProtocol\s*:\s*-1[\s\S]*?CidrIp\s*:\s*0\.0\.0\.0\/0/,
  },
  {
    id: 'cfn-s3-public-acl',
    severity: 'high',
    title: 'S3 bucket has public ACL',
    pattern: /AccessControl.*:.*(PublicRead|PublicReadWrite)/,
  },
  {
    id: 'cfn-rds-unencrypted',
    severity: 'high',
    title: 'RDS instance has storage encryption disabled',
    pattern: /StorageEncrypted\s*:\s*false/,
  },
  {
    id: 'cfn-elb-no-ssl',
    severity: 'high',
    title: 'ELB/ALB does not enforce SSL',
    pattern: /Protocol\s*:\s*HTTP\b/,
  },
  {
    id: 'cfn-secret-plaintext',
    severity: 'critical',
    title: 'Secret value appears to be plaintext',
    pattern: /Default\s*:\s*["'][^"']{20,}["']/,
  },
  {
    id: 'cfn-cf-no-https',
    severity: 'medium',
    title: 'CloudFront viewer protocol policy not set to redirect to HTTPS',
    pattern: /ViewerProtocolPolicy\s*:\s*["']?allow-all["']?/,
  },
  {
    id: 'cfn-ebs-unencrypted',
    severity: 'medium',
    title: 'EBS volume not encrypted',
    pattern: /Encrypted\s*:\s*false/,
  },
];

export function scanCfn(content: string, filename?: string): CfnFinding[] {
  const findings: CfnFinding[] = [];
  const lines = content.split('\n');

  for (const rule of CFN_RULES) {
    if (rule.pattern.test(content)) {
      let line: number | undefined;
      for (let i = 0; i < lines.length; i++) {
        if (rule.pattern.test(lines[i])) {
          line = i + 1;
          break;
        }
      }
      findings.push({
        ruleId: rule.id,
        type: 'CloudFormation',
        severity: rule.severity,
        title: rule.title,
        resource: filename || 'unknown',
        line,
        advice: getAdvice(rule.id),
      });
    }
  }

  return findings;
}

function getAdvice(ruleId: string): string[] {
  const adviceMap: Record<string, string[]> = {
    'cfn-iam-wildcard': [
      'Replace wildcards with specific actions and resources',
      'Use least privilege principle for IAM policies',
    ],
    'cfn-sg-openssh': [
      'Restrict SSH access to known IP ranges',
      'Use AWS SSM Session Manager instead of SSH',
    ],
    'cfn-sg-open-rdp': [
      'Restrict RDP access to known IP ranges',
      'Consider using AWS Systems Manager for remote access',
    ],
    'cfn-sg-all-traffic': [
      'Remove 0.0.0.0/0 access from security groups',
      'Use specific CIDR blocks for necessary access',
    ],
    'cfn-s3-public-acl': [
      'Use private ACLs for buckets',
      'Enable block public access settings',
    ],
    'cfn-rds-unencrypted': [
      'Enable StorageEncrypted: true for RDS instances',
      'Use customer-managed KMS keys for encryption',
    ],
    'cfn-elb-no-ssl': [
      'Configure ELB to use HTTPS-only protocol',
      'Redirect HTTP to HTTPS',
    ],
    'cfn-secret-plaintext': [
      'Use AWS Secrets Manager or Parameter Store for secrets',
      'Never store secrets in plaintext in CloudFormation',
    ],
    'cfn-cf-no-https': [
      'Set ViewerProtocolPolicy to redirect-to-https',
      'Use only HTTPS for CloudFront distributions',
    ],
    'cfn-ebs-unencrypted': [
      'Enable Encrypted: true for EBS volumes',
      'Use customer-managed keys for additional control',
    ],
  };
  return adviceMap[ruleId] || ['Review and fix this security issue'];
}