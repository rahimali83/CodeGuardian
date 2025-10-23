# Security Code Review Agent for Claude Code

> AI-powered security code review agent that performs comprehensive automated security analysis of codebases, identifying vulnerabilities, compliance violations, and code quality issues while tracking remediation progress over time.

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/your-org/security-code-review-agent)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Features

- **🔍 Comprehensive Security Analysis** - Detects vulnerabilities based on OWASP Top 10, CWE standards, and security best practices
- **📋 Multi-Framework Compliance Checking** - Verifies PCI DSS, SOC 2, PIPEDA, CCPA, HIPAA, and NIST Cybersecurity Framework requirements
- **🔌 API Security Analysis** - Reviews API endpoints, authentication, authorization, rate limiting, and data connectivity
- **🔐 Secrets Detection** - Identifies hardcoded credentials, API keys, tokens, and sensitive data exposure
- **📊 Vulnerability Tracking** - Tracks remediation progress across multiple review iterations
- **⚙️ Custom Rules Support** - Extend with organization-specific security requirements
- **📝 Standardized Reporting** - Generates consistent, detailed security reports in markdown format
- **🚀 CI/CD Integration** - Seamlessly integrates with development workflows and pipelines
- **📚 Educational Findings** - Explains not just what is wrong but why and how to fix it

## Quick Start

### Installation

1. **Clone or download this repository**:
   ```bash
   git clone https://github.com/your-org/security-code-review-agent.git
   cd security-code-review-agent
   ```

2. **Copy agent files to Claude Code agents directory**:
   ```bash
   cp -r agent/ ~/.claude-code/agents/security-review/
   ```

3. **Create configuration in your project**:
   ```bash
   cd /path/to/your/project
   cp /path/to/security-code-review-agent/.code-review-config.yml .
   ```

4. **Edit configuration** for your needs (optional):
   ```yaml
   project:
     name: "Your Project Name"

   scope:
     include:
       - "src/**/*.py"
       - "src/**/*.js"

   compliance:
     pci_dss:
       enabled: true  # Enable if handling payment data
     soc2:
       enabled: true
   ```

### First Security Review

Run your first security review:

```bash
claude code security-review
```

Review the generated report:

```bash
cat security-reports/latest-report.md
```

## Usage Examples

### Full Security Review

Analyze entire project with comprehensive checks:

```bash
claude code security-review --full
```

### Quick Scan

Fast analysis focusing on high-severity issues:

```bash
claude code security-review --quick
```

### Review Specific Directory

Analyze only a specific part of your codebase:

```bash
claude code security-review --path src/api
```

### Review Changed Files

Check only files modified since last commit (perfect for pre-commit hooks):

```bash
claude code security-review --diff
```

### Check Specific Compliance Framework

Focus on a particular compliance requirement:

```bash
claude code security-review --compliance pci_dss
```

### Verbose Output

See detailed analysis progress:

```bash
claude code security-review --verbose
```

## Configuration

### Basic Configuration

Create `.code-review-config.yml` in your project root:

```yaml
project:
  name: "My Application"

scope:
  include:
    - "src/**/*.py"
    - "src/**/*.js"
  exclude:
    - "**/test/**"
    - "**/node_modules/**"

compliance:
  pci_dss:
    enabled: false
  soc2:
    enabled: true

reporting:
  output_dir: "security-reports"

thresholds:
  max_critical: 0
  max_high: 5
```

### Advanced Configuration

See [Agent Definition](agent/agent-definition.md) for complete configuration options including:

- Custom rules directory
- API security analysis settings
- Secrets detection configuration
- Performance tuning
- Integration settings

## Custom Rules

Create organization-specific security rules to extend the built-in rule set.

### Example Custom Rule

Create `security-rules/my-rule.yml`:

```yaml
rule_id: CUSTOM-001
title: "Internal API Authentication Required"
description: "All internal API endpoints must use our authentication middleware"

severity: HIGH
category: api_security

detection:
  patterns:
    - pattern: '@app\.route\(["\']/(api|internal)/'
      confidence: 0.6

scope:
  file_patterns:
    - "**/*.py"

remediation:
  description: "Add @require_auth decorator to all internal API routes"

  code_examples:
    - language: python
      insecure: |
        @app.route('/api/users')
        def get_users():
            return jsonify(users)

      secure: |
        @app.route('/api/users')
        @require_auth  # Authentication required
        def get_users():
            return jsonify(users)
```

See [Custom Rules Guide](docs/custom-rules-guide.md) for comprehensive documentation.

## Compliance Frameworks

### Supported Frameworks

| Framework | Description | When to Enable |
|-----------|-------------|----------------|
| **PCI DSS** | Payment Card Industry Data Security Standard | Payment card processing |
| **SOC 2** | Service Organization Control 2 | SaaS providers, cloud services |
| **PIPEDA** | Canadian privacy law | Canadian operations, personal data |
| **CCPA** | California Consumer Privacy Act | California residents' data |
| **HIPAA** | Health Insurance Portability and Accountability Act | Healthcare data (PHI) |
| **NIST CSF** | NIST Cybersecurity Framework | General cybersecurity posture |

### Compliance Checking

The agent verifies technical controls for each enabled framework:

- Encryption requirements (data at rest and in transit)
- Access controls and authentication
- Audit logging and monitoring
- Data handling and retention
- Incident response capabilities

See [Compliance Frameworks Guide](docs/compliance-frameworks.md) for details.

## Integration with Development Workflows

### Pre-Commit Hooks

Catch security issues before committing:

```bash
#!/bin/bash
# .git/hooks/pre-commit
claude code security-review --quick --diff || exit 1
```

### GitHub Actions

```yaml
name: Security Review

on: [pull_request, push]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: claude code security-review
      - uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-reports/latest-report.md
```

### GitLab CI

```yaml
security-review:
  stage: test
  script:
    - claude code security-review
  artifacts:
    paths:
      - security-reports/
```

See [Integration Guide](docs/integration-guide.md) for comprehensive integration examples.

## Report Format

Every security review generates a standardized report including:

1. **Executive Summary** - High-level overview, security rating, key metrics
2. **Previous Vulnerability Status** - Tracking of what was fixed, remains open, or regressed
3. **New Vulnerabilities** - Detailed findings with descriptions, risk analysis, attack vectors, and remediation guidance
4. **Compliance Analysis** - Detailed analysis for each enabled compliance framework
5. **API Security Assessment** - Analysis of API endpoints and data connectivity
6. **Security Management** - Evaluation of secrets, dependencies, configuration, and logging
7. **Remediation Roadmap** - Prioritized action plan organized by urgency
8. **Metrics and Trends** - Vulnerability density, remediation metrics, trend analysis

### Example Finding

Each vulnerability includes:

- Clear description and location
- Risk analysis and potential impact
- Step-by-step attack vector
- Vulnerable code snippet
- Specific remediation guidance
- Secure code example
- References to CWE, OWASP, compliance requirements

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[Custom Rules Guide](docs/custom-rules-guide.md)** - Creating organization-specific security rules
- **[Compliance Frameworks](docs/compliance-frameworks.md)** - Detailed compliance requirements and checking
- **[Integration Guide](docs/integration-guide.md)** - CI/CD integration and workflow automation
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions

## Project Structure

```
security-code-review-agent/
├── README.md                     # This file
├── .code-review-config.yml       # Example configuration
├── agent/                        # Agent files for Claude Code
│   ├── agent-definition.md       # Agent configuration and usage
│   ├── core-prompt.md            # AI agent system instructions
│   └── agent-metadata.json       # Agent metadata
├── templates/                    # Report templates
│   └── report-template.md        # Standardized report format
├── rules/                        # Security rules
│   ├── README.md                 # Rules documentation
│   ├── built-in-rules.yml        # Built-in security rules
│   └── examples/                 # Example custom rules
│       ├── custom-aws-credentials.yml
│       ├── custom-database-security.yml
│       ├── custom-api-rate-limiting.yml
│       └── custom-logging-security.yml
├── docs/                         # Comprehensive documentation
│   ├── custom-rules-guide.md
│   ├── compliance-frameworks.md
│   ├── integration-guide.md
│   └── troubleshooting.md
└── examples/                     # Examples and samples
    ├── sample-config-full.yml
    └── sample-vulnerable-code/
        ├── sql-injection.py
        ├── xss-vulnerability.js
        └── hardcoded-secrets.java
```

## Examples

### Sample Vulnerable Code

The `examples/sample-vulnerable-code/` directory contains intentionally vulnerable code for testing:

- `sql-injection.py` - SQL injection patterns
- `xss-vulnerability.js` - Cross-site scripting vulnerabilities
- `hardcoded-secrets.java` - Hardcoded credentials and API keys

Run the agent on these examples to see how vulnerabilities are detected and reported.

### Sample Configuration Files

The `examples/` directory includes configuration examples for different scenarios:

- Web application security
- API service security
- Financial services (PCI DSS compliance)
- Healthcare applications (HIPAA compliance)

## Security Vulnerabilities Detected

The agent detects these vulnerability categories:

### Injection Flaws
- SQL injection
- Command injection
- LDAP injection
- NoSQL injection
- Template injection
- XML external entity (XXE)

### Authentication & Session Management
- Hardcoded credentials
- Weak password hashing
- Insecure token generation
- Session fixation
- Missing multi-factor authentication

### Sensitive Data Exposure
- Unencrypted sensitive data storage
- Cleartext transmission
- Weak encryption
- Sensitive data in logs
- Verbose error messages

### Broken Access Control
- Missing authorization checks
- Insecure direct object references
- Path traversal
- Privilege escalation
- CORS misconfiguration

### Security Misconfiguration
- Default credentials
- Debug mode enabled
- Missing security headers
- Unnecessary services exposed

### Cross-Site Scripting (XSS)
- Reflected XSS
- Stored XSS
- DOM-based XSS

### Insecure Deserialization
- Unsafe pickle/YAML deserialization
- Unvalidated data deserialization

### Vulnerable Dependencies
- Outdated packages
- Known CVEs in dependencies
- Unpinned dependencies

### Insufficient Logging & Monitoring
- Missing security event logging
- Sensitive data in logs
- Unprotected logs

### API Security
- Missing rate limiting
- Missing authentication/authorization
- Excessive data exposure
- Mass assignment

### Cryptographic Failures
- Weak hashing for passwords
- Insecure random number generation
- Weak encryption algorithms
- Poor key management

## Best Practices

1. **Run Regularly** - Integrate into CI/CD for every pull request
2. **Review Findings Promptly** - Address critical and high severity issues immediately
3. **Track Progress** - Use vulnerability tracking to monitor remediation
4. **Customize Rules** - Add organization-specific security requirements
5. **Enable Relevant Compliance** - Configure frameworks that apply to your organization
6. **Educate Developers** - Use findings as teaching opportunities
7. **Maintain Configuration** - Keep rules and configuration up-to-date
8. **Document Exceptions** - Use suppression comments with explanations for accepted risks

## Contributing

Contributions are welcome! Here's how you can help:

- **Report Bugs** - Create issues for bugs or unexpected behavior
- **Suggest Features** - Propose new capabilities or improvements
- **Submit Rules** - Share useful custom rules with the community
- **Improve Documentation** - Help make documentation clearer and more comprehensive
- **Share Examples** - Contribute example configurations or use cases

## Troubleshooting

### Common Issues

**Configuration not loaded**: Ensure `.code-review-config.yml` is in project root with correct YAML syntax

**Custom rules not working**: Verify rules directory path, YAML syntax, and file patterns match target files

**Slow analysis**: Use `--quick` mode, narrow scope with specific include patterns, or exclude test files and dependencies

**False positives**: Add false positive indicators to rules, use suppression comments, or exclude irrelevant files

See [Troubleshooting Guide](docs/troubleshooting.md) for detailed solutions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.

## Support

- **Documentation**: Check the `docs/` directory for comprehensive guides
- **Examples**: Review the `examples/` directory for sample configurations and code
- **Issues**: Create a GitHub issue for bugs or feature requests
- **Security**: For security vulnerabilities in the agent itself, please report privately

---

## Getting Started Checklist

- [ ] Install the agent to Claude Code agents directory
- [ ] Create `.code-review-config.yml` in your project
- [ ] Run first security review: `claude code security-review`
- [ ] Review the generated report in `security-reports/`
- [ ] Address critical and high severity findings
- [ ] Configure relevant compliance frameworks
- [ ] Create custom rules for organization-specific requirements
- [ ] Integrate into pre-commit hooks
- [ ] Add to CI/CD pipeline
- [ ] Schedule regular comprehensive reviews

---

**Ready to secure your codebase?** Start with a comprehensive security review:

```bash
claude code security-review --verbose
```

Review the report and begin addressing findings. Security is a journey, not a destination. This agent helps you continuously improve your security posture with every code review.
