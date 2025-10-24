# CodeGuardian - Security Code Review Agent

> AI-powered security code review agent for Claude Code that uses natural language markdown rules to perform comprehensive, context-aware security analysis of codebases.

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/your-org/codeguardian)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rules](https://img.shields.io/badge/security_rules-25-brightgreen.svg)](rules/RULES-INDEX.md)

## What Makes CodeGuardian Different?

### 🧠 Markdown-Based Natural Language Rules

Unlike traditional security tools that rely on rigid regex patterns, CodeGuardian uses **markdown-based natural language security rules** that Claude agents can truly understand and reason about.

**Why this matters:**
- ✅ **Context-aware detection** - Understands the difference between test code and production code
- ✅ **Semantic understanding** - Finds vulnerabilities even when code patterns vary
- ✅ **Lower false positives** - Can reason about whether something is actually vulnerable
- ✅ **Better explanations** - Provides natural language explanations of why something is dangerous
- ✅ **Easier to maintain** - Rules are human-readable markdown, not complex YAML schemas

## Features

### 🔍 Comprehensive Security Coverage

- **25+ Security Rules** covering all critical vulnerability categories
- **OWASP Top 10 2021** complete coverage
- **30+ CWE mappings** for vulnerability classification
- **15+ Languages** supported (Python, JavaScript, Java, PHP, Ruby, Go, TypeScript, etc.)
- **100+ Code Examples** showing insecure and secure patterns

### 🎯 Intelligent Detection

- **Secrets Detection**: Hardcoded passwords, AWS credentials, API keys, private keys, tokens
- **Injection Vulnerabilities**: SQL injection, command injection, XSS, LDAP, NoSQL
- **Cryptography Issues**: Weak algorithms (MD5, SHA-1), password hashing, insecure random
- **Authentication & Authorization**: MFA, OAuth/OIDC, RBAC/ABAC, IDOR prevention
- **Data Protection**: Encryption, sensitive data in logs, cleartext transmission
- **API Security**: Rate limiting, SSRF, schema validation, GraphQL security
- **Session Management**: Cookie security, session fixation, theft detection
- **And 18 more security domains** - see [Rules Index](rules/RULES-INDEX.md)

### 📋 Compliance Framework Support

Built-in compliance checking for:
- **PCI DSS** - Payment Card Industry Data Security Standard
- **SOC 2** - Service Organization Control 2
- **HIPAA** - Health Insurance Portability and Accountability Act
- **GDPR** - General Data Protection Regulation
- **CCPA** - California Consumer Privacy Act
- **NIST CSF** - NIST Cybersecurity Framework

### 📊 Vulnerability Tracking

- Track remediation progress across multiple reviews
- Identify fixed, open, and regressed vulnerabilities
- Monitor security improvement over time
- Metrics and trends analysis

### 📝 Educational Findings

Every finding includes:
- Clear explanation of the vulnerability
- Why it's dangerous and what could happen
- Step-by-step remediation instructions
- Code examples showing secure alternatives
- Compliance framework mappings
- CWE and OWASP references

## Quick Start

### Installation

1. **Ensure you have Claude Code installed**

2. **Clone this repository**:
   ```bash
   git clone https://github.com/your-org/codeguardian.git
   cd codeguardian
   ```

3. **Install as Claude Code agent** (if applicable):
   ```bash
   # Copy agent files to Claude Code agents directory
   cp -r agent/ ~/.claude-code/agents/security-review/
   ```

### First Security Review

1. **Navigate to your project**:
   ```bash
   cd /path/to/your/project
   ```

2. **Create configuration** (optional - defaults work for most projects):
   ```bash
   cat > .code-review-config.yml << 'EOF'
   project:
     name: "My Application"

   scope:
     include:
       - "src/**/*.py"
       - "src/**/*.js"
       - "src/**/*.java"
     exclude:
       - "**/test/**"
       - "**/node_modules/**"

   compliance:
     pci_dss:
       enabled: false
     soc2:
       enabled: true
   EOF
   ```

3. **Run security review**:
   ```bash
   claude code security-review
   ```

4. **View the report**:
   ```bash
   cat security-reports/latest-report.md
   ```

## Usage Examples

### Basic Security Review

Analyze your entire project:

```bash
claude code security-review
```

### Quick Scan (High-Priority Only)

Fast scan focusing on critical and high severity issues:

```bash
claude code security-review --quick
```

### Full Comprehensive Scan

Most thorough analysis with all checks:

```bash
claude code security-review --full
```

### Analyze Specific Path

Review only a specific directory or file:

```bash
claude code security-review --path src/api/
claude code security-review --path src/auth/login.py
```

### Review Changed Files Only

Perfect for pre-commit hooks:

```bash
claude code security-review --diff
```

### Verbose Output

See detailed progress and which rules are being applied:

```bash
claude code security-review --verbose
```

### Check Specific Compliance

Focus on specific compliance framework:

```bash
claude code security-review --compliance pci_dss
claude code security-review --compliance hipaa
```

## Security Rules

### Rule Organization

CodeGuardian's security rules are organized into three levels:

**📘 Level 0 (`codeguard-0-*.md`)**: Foundational Security Principles
- Broad domain coverage (authentication, authorization, injection, APIs, etc.)
- 17 comprehensive guidance documents
- Covers secure design patterns and best practices

**📗 Level 1 (`codeguard-1-*.md`)**: Specific Vulnerability Classes
- Focused detection for particular vulnerability types
- 5 targeted detection rules
- Examples: hardcoded credentials, crypto algorithms, safe C functions

**📕 Level 2 (`codeguard-2-*.md`)**: Comprehensive Detection Patterns
- Detailed vulnerability detection with extensive code examples
- 3 in-depth rules covering critical areas
- Examples: secrets detection, injection vulnerabilities, cryptography

### Featured Rules

#### 🔐 Comprehensive Secrets Detection
Detects hardcoded credentials across all secret types:
- Passwords, connection strings (MySQL, PostgreSQL, MongoDB)
- AWS credentials (AKIA pattern, secret keys, session tokens)
- API keys: Stripe (sk_live_), Google (AIza), GitHub (ghp_)
- Private keys and certificates (RSA, EC, PGP)
- Bearer tokens, OAuth tokens

#### 💉 Injection Vulnerability Detection
Complete coverage for injection attacks:
- **SQL Injection**: Python, Java, JavaScript, PHP with parameterization examples
- **Command Injection**: os.system, subprocess, Runtime.exec patterns
- **XSS**: DOM-based XSS with dangerous sinks (innerHTML, eval, dangerouslySetInnerHTML)

#### 🔒 Cryptography Security
Ensures proper cryptographic implementations:
- **Weak Algorithms**: MD5, SHA-1, DES, RC4 detection
- **Password Hashing**: Requires bcrypt, Argon2id, or scrypt
- **Insecure Random**: Math.random vs crypto.randomBytes

**See [Rules Index](rules/RULES-INDEX.md) for complete catalog of all 25 rules**

### Rule Structure

Each markdown rule includes:

```markdown
---
description: What this rule covers
languages:
  - python
  - javascript
  - java
alwaysApply: true  # or false
---

# Rule Title

## Detection Patterns
Language-specific patterns with INSECURE code examples

## Secure Alternatives
SECURE code examples showing proper implementation

## Remediation Steps
Step-by-step fix instructions

## Compliance Impact
PCI DSS, SOC 2, HIPAA, etc. requirements
```

## Configuration

### Configuration File

Create `.code-review-config.yml` in your project root:

```yaml
# Project identification
project:
  name: "Your Application"
  description: "Brief description"

# Analysis scope
scope:
  include:
    - "src/**/*.py"
    - "src/**/*.js"
    - "src/**/*.ts"
    - "api/**/*"
  exclude:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/test/**"
    - "**/*.test.*"

# Rules configuration
rules:
  # Directory for custom organization-specific rules
  custom_rules_dir: "security-rules"

  # Load built-in rules (recommended)
  load_defaults: true

# Compliance frameworks
compliance:
  pci_dss:
    enabled: true   # Enable if handling payment data
  soc2:
    enabled: true   # Service organization controls
  hipaa:
    enabled: false  # Enable if handling health data
  gdpr:
    enabled: false  # European privacy regulation
  ccpa:
    enabled: false  # California privacy law
  nist_csf:
    enabled: true   # NIST Cybersecurity Framework

# API analysis
api_analysis:
  enabled: true
  auto_detect_endpoints: true
  check_rate_limiting: true

# Secrets detection
secrets:
  enabled: true
  entropy_threshold: 4.5

# Reporting
reporting:
  output_dir: "security-reports"
  format: "markdown"
  include_code_snippets: true

# Build/CI thresholds
thresholds:
  max_critical: 0       # Fail if critical issues found
  max_high: 5           # Fail if high issues exceed 5
  fail_on_regression: true
```

### Minimal Configuration

For quick start, minimal config:

```yaml
project:
  name: "My App"

scope:
  include:
    - "src/**/*"
  exclude:
    - "**/test/**"
```

## Custom Rules

### Creating Custom Rules

Organizations can add custom security rules:

1. **Create `security-rules/` directory** in your project
2. **Add markdown rule files** following the standard format
3. **Configure** in `.code-review-config.yml`:
   ```yaml
   rules:
     custom_rules_dir: "security-rules"
   ```

### Custom Rule Example

```markdown
---
description: Enforce internal API authentication
languages:
  - python
  - javascript
alwaysApply: false
---

# Internal API Authentication

## Rule

All internal API endpoints must use mTLS authentication.

## Detection

Look for:
- API route definitions without certificate verification
- Missing client certificate validation
- HTTP instead of HTTPS for internal services

## Insecure Example

```python
# INSECURE - No mTLS
@app.route('/internal/api/data')
def internal_api():
    return sensitive_data()
```

## Secure Example

```python
# SECURE - mTLS required
@app.route('/internal/api/data')
@require_client_cert
def internal_api():
    verify_client_certificate()
    return sensitive_data()
```

## Remediation

1. Enable mTLS in your web server configuration
2. Require client certificates for internal endpoints
3. Validate certificate CN matches expected services
4. Use certificate pinning for critical services
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Review

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Security Code Review
        run: claude code security-review --verbose

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-reports/latest-report.md

      - name: Check Thresholds
        run: |
          if grep -q "CRITICAL" security-reports/latest-report.md; then
            echo "Critical security issues found!"
            exit 1
          fi
```

### Pre-Commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running security review on changed files..."
claude code security-review --quick --diff

if [ $? -ne 0 ]; then
    echo "Security issues found. Fix them before committing."
    exit 1
fi
```

### GitLab CI

```yaml
security-review:
  stage: test
  script:
    - claude code security-review --verbose
  artifacts:
    paths:
      - security-reports/
    expire_in: 30 days
  allow_failure: false
```

## Report Output

### Report Structure

Generated reports include:

1. **Executive Summary**
   - Overall security rating
   - Findings by severity
   - Compliance status

2. **Vulnerability Tracking**
   - Fixed vulnerabilities
   - Open vulnerabilities
   - Regressed vulnerabilities
   - New findings

3. **Detailed Findings**
   - Location (file:line)
   - Description and impact
   - Vulnerable code snippet
   - Remediation steps with secure examples
   - CWE, OWASP, compliance mappings

4. **Compliance Analysis**
   - Framework-specific findings
   - Technical control verification

5. **API Security Assessment**
   - Endpoints discovered
   - Authentication/authorization issues
   - Rate limiting analysis

6. **Remediation Roadmap**
   - Prioritized action plan
   - Estimated effort

### Report Location

Reports are saved to `security-reports/` (configurable):

- **Timestamped**: `security-report-2024-10-24-143022.md`
- **Latest link**: `latest-report.md` (always points to most recent)

## Project Structure

```
CodeGuardian/
├── agent/                      # Claude Code agent files
│   ├── agent-definition.md    # Agent configuration
│   ├── agent-metadata.json    # Agent metadata
│   └── core-prompt.md         # System prompt
├── rules/                      # Security rules
│   ├── rules/                 # All markdown rules
│   │   ├── codeguard-0-*.md  # Level 0: Foundational (18 files)
│   │   ├── codeguard-1-*.md  # Level 1: Specific (4 files)
│   │   └── codeguard-2-*.md  # Level 2: Comprehensive (3 files)
│   ├── examples/              # Custom rule examples
│   ├── RULES-INDEX.md        # Complete rules catalog
│   └── README.md             # Rules documentation
├── docs/                       # Documentation
│   ├── custom-rules-guide.md
│   ├── compliance-frameworks.md
│   └── integration-guide.md
├── templates/                  # Report templates
│   └── report-template.md
├── examples/                   # Sample code
│   └── sample-vulnerable-code/
├── archive/                    # Historical files
│   └── yaml-rules/            # Legacy YAML rules (archived)
├── .code-review-config.yml    # Example configuration
├── CLAUDE.md                  # Claude Code project guidance
├── MARKDOWN-RULES-MIGRATION.md # Migration documentation
├── CONTRIBUTING.md
└── README.md                  # This file
```

## Documentation

- **[Rules Index](rules/RULES-INDEX.md)** - Complete catalog of all 25 security rules
- **[CLAUDE.md](CLAUDE.md)** - Project guidance for Claude Code agents
- **[Migration Guide](MARKDOWN-RULES-MIGRATION.md)** - Understanding the markdown rules approach
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute rules and improvements

## Language Support

Comprehensive coverage for:

- **Python** (20 rules) - Django, Flask, FastAPI
- **JavaScript/TypeScript** (15 rules) - Node.js, React, Vue, Angular
- **Java** (12 rules) - Spring, Jakarta EE
- **PHP** (10 rules) - Laravel, Symfony
- **Ruby** (6 rules) - Rails
- **Go** (4 rules)
- **C/C++** - Memory safety, OpenSSL
- **And more**: Kotlin, Swift, Shell, PowerShell, SQL

## Compliance Coverage

### PCI DSS (Payment Card Industry)
- Requirement 3.4: Protect stored cardholder data
- Requirement 4.1: Encrypt transmission of cardholder data
- Requirement 6.5.1: Injection flaws
- Requirement 8.2.1: Strong authentication
- Requirement 10: Track and monitor all access

### SOC 2 (Service Organization Control)
- CC6.1: Logical and physical access controls
- CC6.7: System infrastructure and software
- CC7.2: System monitoring

### HIPAA (Healthcare)
- 164.312(a)(1): Access controls for ePHI
- 164.312(e)(1): Transmission security
- 164.308(a)(5): Security awareness and training

### GDPR/CCPA (Privacy)
- Data encryption and protection
- Access control and authentication
- Logging and monitoring
- Data minimization

## Exit Codes

For CI/CD integration:

- **0**: Success - no issues above threshold
- **1**: Critical findings exceed threshold
- **2**: High findings exceed threshold
- **3**: Regression detected (fixed vulnerability returned)
- **10**: Configuration or analysis error

## Performance

Typical performance on medium-sized projects:

- **Quick Scan**: 30-60 seconds for ~1000 files
- **Full Scan**: 2-5 minutes for ~1000 files
- **Parallel Analysis**: Configurable (default: 4 files at once)
- **Memory Usage**: ~2GB for large projects

Configure in `.code-review-config.yml`:
```yaml
performance:
  max_parallel_files: 4
  file_timeout: 300
  max_memory: 2048
```

## Troubleshooting

### No Issues Found

If no issues are found but you expect some:
1. Check `.code-review-config.yml` scope includes your files
2. Run with `--verbose` to see which files are analyzed
3. Verify rules are loaded: check for `rules/rules/*.md` files

### False Positives

If you get false positives:
1. Add suppression comment in code: `# nosec` or `# security: ignore`
2. Add file/directory to `scope.exclude` in config
3. Create custom rule with more specific pattern

### Performance Issues

For large codebases:
1. Use `--quick` mode for faster scans
2. Narrow `scope.include` to relevant directories
3. Increase `max_parallel_files` in config
4. Exclude test files and dependencies

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

Ways to contribute:
- Add new security rules
- Improve existing rules
- Add language support
- Fix bugs
- Improve documentation
- Share custom rules

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

**Latest**: v2.0.0 (2024-10-24)
- Migrated to markdown-based natural language rules
- Added 3 comprehensive Level 2 detection rules
- Enhanced context-aware analysis
- Improved false positive reduction
- Better remediation guidance

## License

MIT License - see [LICENSE](LICENSE) file.

## Support

- **Issues**: [GitHub Issues](https://github.com/your-org/codeguardian/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/codeguardian/discussions)
- **Documentation**: [Wiki](https://github.com/your-org/codeguardian/wiki)

## Acknowledgments

- Powered by Claude Code from Anthropic
- Security rules based on OWASP, CWE, and industry best practices
- Compliance guidance from PCI SSC, SOC 2, NIST, and regulatory bodies

---

**CodeGuardian** - AI-powered security code review with natural language understanding.

Built with ❤️ for secure software development.
