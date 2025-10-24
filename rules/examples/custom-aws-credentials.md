---
description: Detects hardcoded AWS credentials including Access Keys, Secret Keys, and Session Tokens
languages:
  - python
  - javascript
  - typescript
  - java
  - go
  - ruby
  - php
alwaysApply: true
severity: CRITICAL
cwe: CWE-798
owasp: "A07:2021 - Identification and Authentication Failures"
---

# Hardcoded AWS Credentials

## Critical Principle: Never Commit AWS Credentials to Source Code

AWS credentials (Access Key IDs, Secret Access Keys, Session Tokens) should **NEVER** be committed to version control.
Hardcoded credentials can be discovered by anyone with repository access and lead to unauthorized access to your AWS
resources, data breaches, and significant financial impact.

## Detection Patterns

### AWS Access Key ID Format

AWS Access Key IDs follow a specific pattern: they always start with `AKIA` followed by 16 uppercase alphanumeric
characters.

**INSECURE - Flag as CRITICAL:**

```python
# Python - Hardcoded AWS credentials
import boto3

client = boto3.client(
    's3',
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region_name='us-east-1'
)
```

```javascript
// JavaScript - Hardcoded AWS credentials
const AWS = require('aws-sdk');

AWS.config.update({
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  region: 'us-east-1'
});

const s3 = new AWS.S3();
```

```java
// Java - Hardcoded AWS credentials
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;

BasicAWSCredentials awsCreds = new BasicAWSCredentials(
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
);

AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
    .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
    .withRegion("us-east-1")
    .build();
```

### What to Look For

**High confidence indicators (flag immediately):**

- **AKIA pattern**: Any string matching `AKIA[0-9A-Z]{16}` (AWS Access Key ID format)
- **Variable assignment**: `aws_access_key_id`, `AWS_ACCESS_KEY_ID`, `accessKeyId` assigned to AKIA string
- **Secret key patterns**: `aws_secret_access_key`, `AWS_SECRET_ACCESS_KEY`, `secretAccessKey` assigned to 40-character
  base64-like string
- **Session tokens**: `aws_session_token`, `AWS_SESSION_TOKEN`, `sessionToken` assigned to 100+ character base64 string
- **URL parameters**: `AWSAccessKeyId=` in URLs

**Context to check:**

- boto3.client() calls in Python with credential parameters
- AWS.config.update() in JavaScript with credentials
- BasicAWSCredentials constructor in Java
- Any AWS SDK initialization with explicit credentials

### False Positive Indicators

**Lower severity or don't flag if:**

- Contains words: `example`, `sample`, `dummy`, `placeholder`, `test`, `mock`, `fake`, `YOUR_ACCESS_KEY`
- Exact match to AWS documentation example: `AKIAIOSFODNN7EXAMPLE`
- In test files (unless production credentials accidentally in tests)
- Suppression comment present: `# nosec: aws-credentials`

## Secure Alternatives

### Best Practice: Use IAM Roles (Preferred)

**SECURE - Python with IAM role:**

```python
import boto3

# No credentials needed - will use IAM role attached to EC2/ECS/Lambda
client = boto3.client('s3', region_name='us-east-1')

# Credentials are automatically provided by the AWS runtime
response = client.list_buckets()
```

**SECURE - JavaScript with IAM role:**

```javascript
const AWS = require('aws-sdk');

// Will automatically use IAM role or environment variables
AWS.config.update({ region: 'us-east-1' });
const s3 = new AWS.S3();
```

**SECURE - Java with default credential chain:**

```java
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;

// Will use IAM role, environment variables, or ~/.aws/credentials
AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
    .withRegion("us-east-1")
    .build();
```

### Alternative: Environment Variables (Local Development)

**SECURE - Python with environment variables:**

```python
import boto3
import os

# Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY as environment variables
# AWS SDK will automatically use them
client = boto3.client('s3', region_name='us-east-1')

# Or explicitly validate they're set
if not os.getenv('AWS_ACCESS_KEY_ID'):
    raise ValueError("AWS_ACCESS_KEY_ID environment variable not set")

client = boto3.client('s3', region_name='us-east-1')
```

### Alternative: AWS Secrets Manager (Cross-Account Access)

**SECURE - Python with Secrets Manager:**

```python
import boto3
import json

def get_aws_credentials():
    secrets_client = boto3.client('secretsmanager', region_name='us-east-1')
    secret = secrets_client.get_secret_value(SecretId='my-aws-credentials')
    return json.loads(secret['SecretString'])

creds = get_aws_credentials()
client = boto3.client(
    's3',
    aws_access_key_id=creds['access_key_id'],
    aws_secret_access_key=creds['secret_access_key'],
    region_name='us-east-1'
)
```

**SECURE - JavaScript with Secrets Manager:**

```javascript
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager({ region: 'us-east-1' });

async function getAWSCredentials() {
  const data = await secretsManager.getSecretValue({
    SecretId: 'my-aws-credentials'
  }).promise();

  return JSON.parse(data.SecretString);
}

async function createS3Client() {
  const creds = await getAWSCredentials();
  return new AWS.S3({
    accessKeyId: creds.access_key_id,
    secretAccessKey: creds.secret_access_key,
    region: 'us-east-1'
  });
}
```

## Remediation Steps

If you find hardcoded AWS credentials in code:

1. **IMMEDIATE - Revoke Credentials**: Go to AWS IAM Console and immediately deactivate or delete the exposed
   credentials
2. **Remove from Code**: Delete the hardcoded credentials from source code
3. **Choose Secure Method**:
    - **Preferred**: Use IAM roles for EC2 instances, ECS tasks, Lambda functions, and other AWS services
    - **Alternative**: Use AWS Secrets Manager or Systems Manager Parameter Store
    - **Local Dev Only**: Use environment variables with credentials in `~/.aws/credentials` or exported vars
4. **Update .gitignore**: Add credential files to `.gitignore`:
   ```
   .env
   .aws/credentials
   **/credentials
   **/secrets.*
   ```
5. **Scan Git History**: Use tools like `git-secrets` or `truffleHog` to scan commit history for exposed credentials
6. **Rotate All Potentially Exposed Credentials**: If credentials were ever committed, consider them compromised and
   rotate

## Best Practices

- **Use IAM roles wherever possible** - No credentials in code, automatically rotated
- **Enable MFA for AWS Console access** - Protect against stolen passwords
- **Implement least privilege** - IAM policies should grant minimum required permissions
- **Rotate credentials regularly** - Even for programmatic access
- **Monitor credential usage** - Enable AWS CloudTrail to detect suspicious access patterns
- **Use AWS Organizations SCPs** - Service control policies to prevent risky actions

## Compliance Impact

**PCI DSS 8.2.1**: Do not use vendor-supplied defaults for system passwords and other security parameters

- Hardcoded credentials violate this requirement as they're essentially default credentials in code

**SOC 2 CC6.1**: The entity implements logical access security software, infrastructure, and architectures over
protected information assets

- Credentials must be properly managed, not hardcoded

**NIST CSF PR.AC-1**: Identities and credentials are issued, managed, verified, revoked, and audited

- Hardcoded credentials cannot be audited or revoked properly

## References

- [AWS Access Keys Best Practices](https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Use of Hard-coded Password](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)

## Summary

AWS credentials must never be hardcoded in source code. Always use IAM roles for AWS services, environment variables for
local development, or AWS Secrets Manager for cross-account access. Any exposed credentials should be considered
compromised and immediately rotated.

---

**Rule ID**: CUSTOM-AWS-001
**Version**: 1.0.0
**Last Updated**: 2024-10-24
**Author**: Security Team
