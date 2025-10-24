# Security Code Review Agent Definition

## Agent Identification

**Agent ID**: `security-review`
**Agent Type**: Code Analysis & Security Testing
**Invoke Command**: `claude code security-review [options]`
**Version**: 1.0.0

## Description

The Security Code Review Agent is an AI-powered security analysis system that performs comprehensive automated security
reviews of codebases. It identifies vulnerabilities, compliance violations, and code quality issues while tracking
remediation progress across multiple review iterations.

The agent analyzes code against OWASP Top 10, CWE standards, and multiple compliance frameworks including PCI DSS, SOC
2, PIPEDA (Canadian privacy law), CCPA, HIPAA, and NIST Cybersecurity Framework. It provides detailed, actionable
findings with remediation guidance and educational context to help development teams improve their security posture.

## Capabilities

The Security Code Review Agent can:

- **Analyze Code for Security Vulnerabilities**: Detect injection flaws (SQL, command, LDAP, NoSQL), authentication
  weaknesses, sensitive data exposure, XXE vulnerabilities, broken access control, security misconfigurations, XSS,
  insecure deserialization, vulnerable dependencies, insufficient logging, and API security issues

- **Check Regulatory Compliance**: Verify technical controls for PCI DSS (payment card security), SOC 2 (service
  organization controls), PIPEDA (Canadian privacy), CCPA (California privacy), HIPAA (healthcare data protection), and
  NIST Cybersecurity Framework

- **Review API Security**: Analyze API endpoints for authentication, authorization, rate limiting, input validation, and
  data exposure issues; review database connections and external API integrations

- **Evaluate Secrets Management**: Detect hardcoded credentials, API keys, tokens, and private keys; assess secrets
  management practices

- **Assess Cryptographic Implementations**: Identify weak encryption algorithms, insecure key management, weak password
  hashing, and cryptographic failures

- **Track Vulnerability Remediation**: Compare findings across multiple review iterations to show which vulnerabilities
  were fixed, partially fixed, remain open, or have regressed; provide metrics on remediation progress

- **Load Security Rules from Markdown**: Apply comprehensive security rules defined in natural language markdown format
  that Claude agents can easily understand and reason about; supports both built-in and organization-specific rules

- **Generate Standardized Reports**: Produce comprehensive security reports in markdown format following a consistent
  template for easy tracking and audit purposes

- **Integrate with Development Workflows**: Run in CI/CD pipelines, pre-commit hooks, pull request reviews, and
  scheduled scans

## Configuration

### Configuration File

The agent looks for a configuration file at `.code-review-config.yml` in the project root directory.

#### Complete Configuration Structure

```yaml
# Security Code Review Configuration

# Project identification
project:
  name: "My Application"
  description: "Brief description of what this application does"

# Scope configuration - which files to analyze
scope:
  # Include patterns (glob format)
  include:
    - "src/**/*.py"
    - "src/**/*.js"
    - "src/**/*.java"
    - "src/**/*.go"
    - "src/**/*.ts"
    - "src/**/*.tsx"
    - "lib/**/*"
    - "api/**/*"
    - "config/**/*.yml"
    - "config/**/*.yaml"
    - "config/**/*.json"

  # Exclude patterns (glob format)
  exclude:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/dist/**"
    - "**/build/**"
    - "**/*.test.js"
    - "**/*.test.py"
    - "**/*.spec.ts"
    - "**/test/**"
    - "**/tests/**"
    - "**/__tests__/**"
    - "**/.git/**"

# Rules configuration
rules:
  # Directory containing custom security rules (relative to project root)
  custom_rules_dir: "security-rules"

  # Whether to load default built-in rules
  load_defaults: true

  # Severity overrides for specific rules
  severity_overrides:
    # Example: Override severity of a built-in rule
    # BUILTIN-SQL-001: "CRITICAL"  # Escalate SQL injection to critical
    # CUSTOM-001: "HIGH"  # Adjust custom rule severity

# Compliance requirements - enable frameworks relevant to your organization
compliance:
  pci_dss:
    enabled: true
    # Specific requirements to check (empty = all requirements)
    requirements: []

  soc2:
    enabled: true
    # Trust service categories to check
    categories:
      - security      # Common criteria - always checked
      - availability
      - processing_integrity
      - confidentiality
      - privacy

  pipeda:  # Canadian privacy law
    enabled: false

  ccpa:    # California privacy law
    enabled: false

  hipaa:   # Healthcare data protection
    enabled: false

  nist_csf:  # NIST Cybersecurity Framework
    enabled: true
    functions:  # Empty = all functions
      - identify
      - protect
      - detect
      - respond
      - recover

# Reporting configuration
reporting:
  # Output directory for reports (relative to project root)
  output_dir: "security-reports"

  # Report format
  format: "markdown"  # Currently only markdown supported

  # Include detailed code snippets in reports
  include_code_snippets: true

  # Include proof of concept exploits where applicable
  include_poc: false  # Set true only in secure environments

  # Maximum lines of code to include in snippets
  max_snippet_lines: 20

  # Include false positives in appendix
  include_false_positives: true

# API security analysis
api_analysis:
  # Enable comprehensive API security checking
  enabled: true

  # Detect API endpoints automatically
  auto_detect_endpoints: true

  # Known API endpoint patterns (if not auto-detecting)
  endpoint_patterns:
    - "/api/**"
    - "/v1/**"
    - "/v2/**"

  # Check rate limiting
  check_rate_limiting: true

  # Check authentication on all endpoints
  require_authentication: true

  # Check authorization on all endpoints
  require_authorization: true

# Secrets detection
secrets:
  # Enable secrets scanning
  enabled: true

  # Check common secret patterns
  patterns:
    - api_keys
    - passwords
    - private_keys
    - tokens
    - database_credentials

  # Entropy threshold for high-entropy string detection
  entropy_threshold: 4.5

  # Exclude specific files from secrets scanning
  exclude:
    - "**/*.md"
    - "**/README.*"
    - "**/LICENSE"

# Severity thresholds - determine when reviews "fail"
thresholds:
  # Fail if critical findings exceed this number
  max_critical: 0

  # Fail if high findings exceed this number
  max_high: 5

  # Fail if medium findings exceed this number (0 = no limit)
  max_medium: 0

  # Fail if total findings exceed this number (0 = no limit)
  max_total: 0

  # Fail if any previous vulnerabilities regressed
  fail_on_regression: true

# Integration settings
integration:
  # Issue tracker integration (for automatic ticket creation)
  issue_tracker:
    enabled: false
    type: "github"  # github, gitlab, jira
    # project: "owner/repo"
    # labels: ["security", "automated"]

  # Notification webhooks
  notifications:
    enabled: false
    # webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    # notify_on: ["critical", "high"]  # Which severities trigger notifications

  # Git integration
  git:
    # Create git commit with fixes (if auto-fix available)
    auto_commit_fixes: false

    # Branch prefix for security fix branches
    fix_branch_prefix: "security-fix/"

# Performance settings
performance:
  # Maximum files to analyze in parallel
  max_parallel_files: 4

  # Timeout for analysis of single file (seconds)
  file_timeout: 300

  # Maximum memory usage (MB)
  max_memory: 2048

# Logging
logging:
  # Log level: DEBUG, INFO, WARN, ERROR
  level: "INFO"

  # Log file location
  log_file: "security-review.log"

  # Verbose console output
  verbose: false
```

### Minimal Configuration

For quick start, a minimal configuration might look like:

```yaml
project:
  name: "My App"

scope:
  include:
    - "src/**/*.js"
    - "src/**/*.py"
  exclude:
    - "**/node_modules/**"
    - "**/tests/**"

compliance:
  pci_dss:
    enabled: false
  soc2:
    enabled: true

reporting:
  output_dir: "security-reports"
```

## Security Rules Format

### Markdown-Based Rules

CodeGuardian uses **markdown-based security rules** rather than traditional YAML pattern matching. This design choice
enables Claude agents to:

- **Understand context** and reasoning behind security requirements
- **Apply nuanced judgment** about what constitutes a vulnerability
- **Adapt detection** to different code patterns and frameworks
- **Provide better remediation** with natural language explanations

### Rule Organization

Security rules are located in `rules/rules/` and organized into three levels:

**Level 0 (codeguard-0-*.md)**: Foundational security principles covering broad domains like authentication,
authorization, input validation, API security, etc. These provide comprehensive security guidance.

**Level 1 (codeguard-1-*.md)**: Specific detection rules for particular vulnerability classes like hardcoded
credentials, cryptographic algorithms, safe C functions.

**Level 2 (codeguard-2-*.md)**: Comprehensive detection patterns with detailed code examples for critical
vulnerabilities like secrets detection, injection flaws, and cryptography failures.

### Rule Structure

Each markdown rule file includes:

```markdown
---
description: Brief description of what this rule covers
languages:
  - python
  - javascript
  - java
alwaysApply: true  # or false
---

# Rule Title

## Detection Patterns

What patterns to look for, with language-specific examples of INSECURE code.

## Secure Alternatives

Code examples showing the SECURE way to implement the same functionality.

## Remediation Steps

Step-by-step instructions for fixing the vulnerability.

## Compliance Impact

Which compliance frameworks this relates to (PCI DSS, SOC 2, HIPAA, etc.)
```

### Built-In Rules

The agent includes 22+ comprehensive security rules covering:

- **Secrets Detection**: Hardcoded passwords, AWS credentials, API keys, private keys, tokens
- **Injection Vulnerabilities**: SQL injection, command injection, XSS, LDAP injection
- **Cryptography**: Weak algorithms (MD5, SHA-1), password hashing, insecure random
- **Authentication & Authorization**: MFA, OAuth/OIDC, RBAC/ABAC, IDOR prevention
- **Data Protection**: Encryption, sensitive data in logs, cleartext transmission
- **API Security**: Rate limiting, SSRF, schema validation, GraphQL security
- **Session Management**: Cookie security, session fixation, theft detection
- **File Security**: Upload validation, path traversal, storage isolation
- **Client-Side Security**: XSS, CSRF, CSP, clickjacking, XS-Leaks
- **Database Security**: Connection security, least privilege, encryption
- **Logging & Monitoring**: Structured logging, sensitive data redaction
- And 10+ more security domains

See `rules/RULES-INDEX.md` for the complete catalog.

### Custom Rules

Organizations can add custom rules by:

1. Creating markdown files in the `security-rules/` directory
2. Following the same structure as built-in rules
3. Setting `custom_rules_dir` in `.code-review-config.yml`

Custom rules are loaded alongside built-in rules and applied during analysis.

## Invoking the Agent

### Basic Usage

Run a full security review of the entire project:

```bash
claude code security-review
```

This performs a complete security analysis using the configuration from `.code-review-config.yml` (or defaults if not
present) and generates a report in the configured output directory.

### Advanced Options

#### Review Specific Files or Directories

```bash
claude code security-review --path src/api
claude code security-review --path src/auth.py
```

Analyzes only the specified path instead of the entire project.

#### Review Changed Files Only

```bash
claude code security-review --diff
```

Analyzes only files that have changed since the last git commit. Useful for quick pre-commit checks.

#### Quick Scan Mode

```bash
claude code security-review --quick
```

Performs a faster, less comprehensive analysis focusing on high-severity issues only. Good for rapid feedback during
development.

#### Full Detailed Scan

```bash
claude code security-review --full --verbose
```

Performs the most thorough analysis possible, including deeper data flow analysis and pattern matching. Takes longer but
finds more subtle issues.

#### Check Specific Compliance Framework

```bash
claude code security-review --compliance pci_dss
claude code security-review --compliance soc2
claude code security-review --compliance pipeda
```

Focuses analysis on a specific compliance framework regardless of configuration.

#### Track Specific Vulnerabilities

```bash
claude code security-review --track-vuln VULN-001,VULN-NEW-015
```

Re-examines specific vulnerabilities to verify their remediation status.

#### Generate Report Only

```bash
claude code security-review --report-only
```

Generates a new report from the most recent analysis data without performing new analysis. Useful for reformatting or
regenerating reports.

#### Custom Rules Directory

```bash
claude code security-review --rules-dir /path/to/custom/rules
```

Specifies a custom location for security rules, overriding the configuration file.

#### Verbose Output

```bash
claude code security-review --verbose
```

Enables detailed console output showing analysis progress, rules applied, and findings as they're discovered.

## Agent Workflow

When the Security Code Review Agent is invoked, it follows this systematic process:

### Step 1: Initialization and Configuration Loading

1. The agent starts by looking for `.code-review-config.yml` in the project root
2. If found, configuration is parsed and validated
3. If not found, sensible defaults are used
4. The core security rule set is loaded (built-in rules)
5. Custom rules are loaded from the configured custom rules directory
6. Any rule syntax errors or validation failures are reported

### Step 2: Previous Report Analysis

1. The agent searches for previous security reports in the configured output directory
2. If a previous report exists (`latest-report.md` or most recent timestamped report):
    - The report is parsed to extract all previously identified vulnerabilities
    - Each vulnerability's ID, location, severity, and description are captured
3. This enables tracking of which vulnerabilities were fixed, remain open, or have regressed

### Step 3: Scope Determination

1. The agent identifies all files in the project
2. Include patterns from configuration are applied (e.g., `src/**/*.py`)
3. Exclude patterns are applied (e.g., `**/node_modules/**`, `**/tests/**`)
4. The final set of files to analyze is determined
5. Files are prioritized based on security relevance (API code, authentication logic, etc. analyzed first)

### Step 4: Deep Security Analysis

For each file in scope, the agent performs comprehensive analysis:

1. **Code Parsing**: The file is read and parsed to understand its structure
2. **Vulnerability Detection**: All applicable security rules (built-in and custom) are applied
3. **Context Analysis**: Each potential finding is evaluated in context to reduce false positives
4. **Data Flow Tracing**: User input is traced through the application to identify injection points
5. **Compliance Checking**: Code patterns are mapped to compliance requirements
6. **API Analysis**: API endpoints, database connections, and external integrations are identified and analyzed
7. **Secrets Scanning**: Code is scanned for hardcoded credentials and sensitive data

The agent examines code for:

- **Injection flaws**: SQL injection, command injection, LDAP injection, NoSQL injection, template injection
- **Authentication issues**: Hardcoded credentials, weak passwords, insecure tokens, session fixation
- **Sensitive data exposure**: Unencrypted data, cleartext transmission, weak encryption, sensitive data in logs
- **XXE vulnerabilities**: XML external entity processing weaknesses
- **Broken access control**: Missing authorization, insecure direct object references, privilege escalation
- **Security misconfigurations**: Default credentials, debug endpoints, missing security headers
- **Cross-site scripting**: Reflected XSS, stored XSS, DOM-based XSS
- **Insecure deserialization**: Unsafe deserialization of untrusted data
- **Vulnerable dependencies**: Outdated packages with known CVEs
- **Insufficient logging**: Missing security event logging, sensitive data in logs
- **API security**: Missing authentication/authorization, rate limiting, input validation, data exposure
- **Cryptographic failures**: Weak algorithms, poor key management, weak password hashing

### Step 5: Vulnerability Status Tracking

For each vulnerability identified in the previous report:

1. The agent navigates to the exact file and line number mentioned
2. The code is re-examined to determine if the vulnerability still exists
3. Status is determined:
    - **Fixed**: The vulnerability has been completely remediated
    - **Partially Fixed**: Some mitigation was applied but the vulnerability remains
    - **Not Fixed**: No changes were made, the vulnerability is still present
    - **Regressed**: The vulnerability was fixed in an earlier review but has returned
    - **Code Removed**: The vulnerable code no longer exists in the codebase
4. For fixed issues, the remediation approach is noted and verified for completeness
5. For open issues, the number of days the issue has been open is calculated
6. Severity may be escalated for long-standing issues

### Step 6: Risk Assessment and Prioritization

1. **Severity Assignment**: Each finding is assigned a severity level (Critical, High, Medium, Low, Informational) based
   on:
    - Exploitability: How easy is it to exploit?
    - Impact: What damage could be done if exploited?
    - Compliance implications: Does this violate regulatory requirements?
    - Context: Is this production code or test code? Is this reachable by attackers?

2. **Finding Correlation**: Related vulnerabilities are grouped together:
    - Multiple instances of the same vulnerability type
    - Vulnerabilities that create attack chains when combined
    - Systemic issues indicating broader security problems

3. **Attack Chain Identification**: The agent identifies combinations of vulnerabilities that together enable serious
   attacks

4. **Prioritization**: Findings are ordered by:
    - Severity level
    - Compliance impact
    - Exploitability
    - Business criticality

### Step 7: Report Generation

1. The agent follows the standardized report template located at `templates/report-template.md`
2. The report is populated with:
    - **Executive Summary**: High-level overview with key metrics and overall security rating
    - **Previous Vulnerability Status Update**: Status of all vulnerabilities from the previous report
    - **New Vulnerabilities**: All security issues discovered in this review
    - **Compliance Analysis**: Detailed analysis for each enabled compliance framework
    - **API Security Assessment**: Analysis of API endpoints, database connections, and integrations
    - **Security Management Evaluation**: Assessment of secrets management, dependencies, configuration, and logging
    - **Code Quality Observations**: Code quality issues affecting security
    - **Remediation Roadmap**: Prioritized plan organized by urgency
    - **Metrics and Trends**: Vulnerability density, remediation metrics, trend analysis
    - **Appendices**: Custom rules applied, files analyzed, false positives, exclusions

3. Every vulnerability finding includes:
    - Unique identifier for tracking
    - Clear description of the issue
    - Risk analysis and potential impact
    - Attack vector explaining exploitation
    - Vulnerable code snippet
    - Specific remediation guidance
    - Secure code example
    - References to OWASP, CWE, CVE, and compliance requirements

### Step 8: Report Storage

1. The generated report is saved with a timestamp: `security-report-YYYY-MM-DD-HHMMSS.md`
2. A `latest-report.md` file is created or updated (copy or symlink) pointing to the newest report
3. Reports are saved in the configured output directory (default: `security-reports/`)
4. The output directory is created if it doesn't exist

### Step 9: Exit Code and Summary

1. A summary is displayed to the console showing:
    - Total files analyzed
    - Total lines of code reviewed
    - Total vulnerabilities found (broken down by severity)
    - Number of previous vulnerabilities fixed
    - Number of previous vulnerabilities still open
    - Report file location

2. The agent exits with an appropriate exit code:
    - **0**: Success - no critical issues, or findings below configured thresholds
    - **1**: Failure - critical findings exceed threshold
    - **2**: Failure - high findings exceed threshold
    - **3**: Failure - regression detected and fail_on_regression is enabled
    - **10**: Error - configuration error or analysis failure

Exit codes can be used in CI/CD pipelines to gate deployments based on security findings.

## Integration with Development Workflows

### Pre-Commit Hooks

Run quick security scans before committing code to catch obvious issues early:

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running security code review..."
claude code security-review --quick --diff

if [ $? -ne 0 ]; then
    echo "❌ Security issues found. Commit blocked."
    echo "Review the security report or use --no-verify to skip (not recommended)"
    exit 1
fi

echo "✅ Security check passed"
exit 0
```

### Continuous Integration

Add the security review agent to your CI/CD pipeline to gate deployments:

#### GitHub Actions

```yaml
name: Security Code Review

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Security Code Review
        run: |
          claude code security-review --verbose

      - name: Upload Security Report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-report
          path: security-reports/latest-report.md

      - name: Comment on PR
        if: github.event_name == 'pull_request' && failure()
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('security-reports/latest-report.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '## Security Review Results\n\n' + report.substring(0, 60000)
            });
```

#### GitLab CI

```yaml
security-review:
  stage: test
  script:
    - claude code security-review --verbose
  artifacts:
    when: always
    paths:
      - security-reports/
    expire_in: 30 days
  allow_failure: false
```

#### Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Security Review') {
            steps {
                sh 'claude code security-review --verbose'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'security-reports/**/*.md', allowEmptyArchive: true
        }
        failure {
            emailext(
                subject: "Security Issues Found: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: readFile('security-reports/latest-report.md'),
                to: 'security-team@example.com'
            )
        }
    }
}
```

### Scheduled Reviews

Run comprehensive security reviews nightly or weekly to catch issues that develop over time:

```bash
# Crontab entry for nightly security review at 2 AM
0 2 * * * cd /path/to/project && claude code security-review --full > /tmp/security-review.log 2>&1
```

### Pull Request Reviews

Invoke the agent on pull request code to provide security feedback before merge:

```bash
# In your PR review process
git fetch origin pull/$PR_NUMBER/head:pr-$PR_NUMBER
git checkout pr-$PR_NUMBER
claude code security-review --diff --verbose
```

### Developer Workstation Usage

Developers can run reviews locally before pushing code:

```bash
# Quick check before committing
claude code security-review --quick --diff

# Full review before creating pull request
claude code security-review --full
```

## Output and Reports

### Report Format

All security reports are generated in **Markdown format** following a standardized template. This ensures:

- Consistency across all security reviews
- Easy tracking of progress over time
- Clear comparison between reviews
- Professional presentation for stakeholders and auditors
- Compatibility with documentation systems and wikis

### Report Storage

Reports are stored in the configured output directory (default: `security-reports/`) with naming convention:

- **Timestamped reports**: `security-report-2024-01-15-143022.md`
- **Latest report link**: `latest-report.md` (always points to most recent review)

This allows you to:

- Track security posture over time
- Compare findings across different dates
- Demonstrate security improvements to auditors
- Maintain audit trail of security reviews

### Report Sections

Every report includes these sections:

1. **Executive Summary**: High-level overview, security rating, findings summary, compliance status, top issues,
   remediation roadmap
2. **Previous Vulnerability Status**: Tracking of whether previous findings were fixed, remain open, or regressed
3. **New Vulnerabilities**: Detailed findings with descriptions, risk analysis, attack vectors, code snippets, and
   remediation guidance
4. **Compliance Analysis**: Detailed analysis for each enabled compliance framework (PCI DSS, SOC 2, PIPEDA, CCPA,
   HIPAA, NIST)
5. **API Security Assessment**: Analysis of API endpoints, authentication, authorization, database connections, and
   integrations
6. **Security Management**: Evaluation of secrets management, dependencies, configuration, and logging
7. **Code Quality**: Observations on code quality affecting security maintainability
8. **Remediation Roadmap**: Prioritized action plan (immediate, short-term, medium-term, long-term)
9. **Metrics and Trends**: Vulnerability density, remediation metrics, trend analysis
10. **Appendices**: Custom rules applied, files analyzed, false positives, exclusions

## Custom Rules

The agent supports loading **custom security rules** to extend the built-in rule set with organization-specific
requirements.

### Custom Rules Directory

Custom rules are loaded from the directory specified in configuration (default: `security-rules/`). The agent loads all
`.md` markdown files from this directory.

### Custom Rule Format

Custom rules are written as **markdown files** with natural language descriptions that Claude can understand and reason
about:

```markdown
---
description: Brief description of what this rule covers
languages:
  - python
  - javascript
alwaysApply: false  # Set to true to apply to all files
severity: HIGH      # CRITICAL, HIGH, MEDIUM, LOW
---

# Custom Rule Title

## Critical Principle

State the core security principle this rule enforces.

## Detection Patterns

### Pattern Category

**INSECURE - Flag as HIGH severity:**
```python
# Example of insecure code pattern
api_key = "hardcoded-secret-key"
db.query(f"SELECT * FROM users WHERE id = {user_input}")
```

**SECURE - What developers must use:**

```python
# Example of secure alternative
import os
api_key = os.getenv('API_KEY')
db.query("SELECT * FROM users WHERE id = %s", (user_input,))
```

### When to Flag

- Specific pattern to look for in code
- Context where this is a security issue
- Indicators for high confidence detection

## Remediation

1. **Step-by-step fix instructions**
2. Explain the secure approach
3. Provide migration guidance if needed

## Compliance Impact

**PCI DSS X.X.X**: Requirement description
**OWASP**: Related vulnerability class
**CWE-XXX**: Common Weakness Enumeration

## Summary

Brief recap of the rule and key takeaways.

```

For complete documentation on creating custom rules, see `docs/custom-rules-guide.md`.

### Loading Custom Rules

Custom rules are automatically loaded when the agent runs. To verify which rules are loaded:

```bash
claude code security-review --list-rules
```

## Troubleshooting

### Agent Not Finding Configuration

**Symptom**: Agent runs with default configuration instead of your `.code-review-config.yml`

**Solution**: Ensure the configuration file is in the project root directory (same directory where you run the command).
Check filename spelling and extension (.yml vs .yaml).

### Custom Rules Not Loading

**Symptom**: Custom rules don't appear in report appendix or aren't applied

**Solution**:

1. Verify the `custom_rules_dir` path in configuration is correct
2. Check that custom rule files have `.md` extension
3. Validate markdown frontmatter syntax (YAML format between `---` markers)
4. Ensure proper markdown formatting and code block syntax
5. Run with `--verbose` to see rule loading messages

### Previous Report Not Found

**Symptom**: Report says "No previous report found" even though reports exist

**Solution**: This is expected on first run. Ensure subsequent runs save reports to the same output directory
configured. Check that `reporting.output_dir` in configuration points to the correct location.

### Large Codebase Performance

**Symptom**: Analysis takes very long or times out on large codebases

**Solution**:

1. Use `--quick` mode for faster analysis
2. Narrow scope with more specific `include` patterns
3. Use broader `exclude` patterns to skip non-security-critical files
4. Increase `performance.max_parallel_files` in configuration
5. Run on specific paths instead of entire project

### False Positives

**Symptom**: Agent reports issues that aren't actually vulnerabilities

**Solution**:

1. Review the finding carefully - it may be a real issue with mitigating context
2. Add suppression comments in code: `# nosec` or `# security: ignore`
3. Adjust rule sensitivity if using custom rules
4. Report persistent false positives to help improve rule accuracy

### Report Generation Failures

**Symptom**: Analysis completes but report isn't generated or is incomplete

**Solution**:

1. Check disk space and write permissions for output directory
2. Verify output directory path in configuration
3. Run with `--verbose` to see detailed error messages
4. Check for special characters in file paths that might cause issues

## Support and Documentation

For more detailed information:

- **Custom Rules Guide**: `docs/custom-rules-guide.md`
- **Compliance Frameworks**: `docs/compliance-frameworks.md`
- **Integration Guide**: `docs/integration-guide.md`
- **Troubleshooting**: `docs/troubleshooting.md`

For issues, feature requests, or questions:

- Review existing documentation in the `docs/` directory
- Check the project README for common scenarios
- Examine example configurations in `examples/`
- Review sample vulnerable code in `examples/sample-vulnerable-code/`

## Version History

**Version 1.0.0** (Initial Release)

- Comprehensive security vulnerability detection
- Multi-framework compliance checking (PCI DSS, SOC 2, PIPEDA, CCPA, HIPAA, NIST)
- API security analysis
- Vulnerability tracking across review iterations
- Custom security rules support
- Standardized markdown reporting
- CI/CD integration support

---

**Ready to secure your codebase?** Run your first security review:

```bash
claude code security-review
```
