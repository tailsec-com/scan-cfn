import { describe, it, expect } from '@jest/globals';
import { scanCfn } from '../src/cfn.js';

describe('scanCfn', () => {
  describe('IAM wildcard detection', () => {
    it('detects Action:* in IAM policy', () => {
      const yaml = `
Resources:
  MyPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          - Action: "*"
            Effect: Allow
            Resource: "*"
`;
      const findings = scanCfn(yaml);
      expect(findings.some((f) => f.ruleId === 'cfn-iam-wildcard')).toBe(true);
    });

    it('detects Resource:* in IAM policy', () => {
      const yaml = `
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Action: sts:AssumeRole
            Effect: Allow
            Resource: "*"
`;
      const findings = scanCfn(yaml);
      expect(findings.some((f) => f.ruleId === 'cfn-iam-wildcard')).toBe(true);
    });
  });

  describe('Security group detection', () => {
    it('detects SSH open to 0.0.0.0/0', () => {
      const yaml = `
Resources:
  MySG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
          IpProtocol: tcp
`;
      const findings = scanCfn(yaml);
      expect(findings.some((f) => f.ruleId === 'cfn-sg-openssh')).toBe(true);
    });

    it('detects RDP open to 0.0.0.0/0', () => {
      const yaml = `
Resources:
  MySG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - FromPort: 3389
          ToPort: 3389
          CidrIp: 0.0.0.0/0
          IpProtocol: tcp
`;
      const findings = scanCfn(yaml);
      expect(findings.some((f) => f.ruleId === 'cfn-sg-open-rdp')).toBe(true);
    });

    it('detects all traffic from 0.0.0.0/0', () => {
      const yaml = `
Resources:
  MySG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: -1
          CidrIp: 0.0.0.0/0
`;
      const findings = scanCfn(yaml);
      expect(findings.some((f) => f.ruleId === 'cfn-sg-all-traffic')).toBe(true);
    });
  });

  describe('S3 detection', () => {
    it('detects PublicRead ACL', () => {
      const yaml = `
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
`;
      const findings = scanCfn(yaml);
      expect(findings.some((f) => f.ruleId === 'cfn-s3-public-acl')).toBe(true);
    });

    it('detects PublicReadWrite ACL', () => {
      const json = JSON.stringify({
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: { AccessControl: 'PublicReadWrite' },
          },
        },
      });
      const findings = scanCfn(json);
      expect(findings.some((f) => f.ruleId === 'cfn-s3-public-acl')).toBe(true);
    });
  });

  describe('RDS detection', () => {
    it('detects unencrypted RDS', () => {
      const yaml = `
Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: false
`;
      const findings = scanCfn(yaml);
      expect(findings.some((f) => f.ruleId === 'cfn-rds-unencrypted')).toBe(true);
    });
  });

  describe('ELB detection', () => {
    it('detects HTTP-only ELB', () => {
      const yaml = `
Resources:
  MyELB:
    Type: AWS::ElasticLoadBalancing::LoadBalancer
    Properties:
      Listeners:
        - Protocol: HTTP
          LoadBalancerPort: 80
`;
      const findings = scanCfn(yaml);
      expect(findings.some((f) => f.ruleId === 'cfn-elb-no-ssl')).toBe(true);
    });
  });

  describe('Secrets detection', () => {
    it('detects plaintext secrets in Parameters', () => {
      const yaml = `
Parameters:
  DBPassword:
    Type: String
    Default: "MySecretPassword123!SecretPass"
`;
      const findings = scanCfn(yaml);
      expect(findings.some((f) => f.ruleId === 'cfn-secret-plaintext')).toBe(true);
    });
  });

  describe('CloudFront detection', () => {
    it('detects allow-all viewer protocol', () => {
      const yaml = `
Resources:
  MyDistribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        ViewerProtocolPolicy: allow-all
`;
      const findings = scanCfn(yaml);
      expect(findings.some((f) => f.ruleId === 'cfn-cf-no-https')).toBe(true);
    });
  });

  describe('EBS detection', () => {
    it('detects unencrypted EBS volume', () => {
      const yaml = `
Resources:
  MyVolume:
    Type: AWS::EC2::Volume
    Properties:
      Encrypted: false
`;
      const findings = scanCfn(yaml);
      expect(findings.some((f) => f.ruleId === 'cfn-ebs-unencrypted')).toBe(true);
    });
  });

  describe('No findings', () => {
    it('returns empty array for clean template', () => {
      const yaml = `
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Action: sts:AssumeRole
            Effect: Allow
            Resource: !Sub arn:aws:iam::\${AWS::AccountId}:role/\${MyRole}
`;
      const findings = scanCfn(yaml);
      expect(findings).toHaveLength(0);
    });
  });
});