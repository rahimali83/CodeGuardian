# CodeGuardian Quick Start Guide

Get started with CodeGuardian Security Code Review Agent in 5 minutes.

## What is CodeGuardian?

CodeGuardian is an AI-powered security code review agent for Claude Code that:
- Detects vulnerabilities (OWASP Top 10, CWE standards)
- Checks compliance (PCI DSS, SOC 2, HIPAA, GDPR, etc.)
- Tracks remediation progress across reviews
- Provides detailed fix guidance with secure code examples

**Key Feature**: Uses **markdown-based natural language rules** that Claude agents understand contextually, reducing false positives and providing better explanations.

## Prerequisites

- Claude Code installed and configured
- A codebase to analyze (any language: Python, JavaScript, Java, Go, PHP, Ruby, etc.)

## Step 1: Run Your First Security Review

No configuration needed! Just run:

```bash
claude code security-review
```

This performs a full security analysis using default settings and generates a report in `security-reports/`.

### Quick Options

```bash
# Fast scan (high-severity only) - great for CI/CD
claude code security-review --quick

# Review specific directory
claude code security-review --path src/api

# Review only changed files (perfect for pre-commit hooks)
claude code security-review --diff

# Verbose output to see what's happening
claude code security-review --verbose
```

## Step 2: Review the Report

Reports are saved to `security-reports/` directory:

```bash
# View the latest report
cat security-reports/latest-report.md

# Or open in your editor
code security-reports/latest-report.md
```

### Report Sections

1. **Executive Summary**: Overall security rating and findings count
2. **Vulnerability Status**: What was fixed, what's still open, any regressions
3. **New Vulnerabilities**: Detailed findings with:
   - Location (file:line)
   - Risk analysis
   - Vulnerable code snippet
   - Secure alternative with code example
   - Remediation steps
   - Compliance impact
4. **Compliance Analysis**: Technical control verification per framework
5. **API Security Assessment**: Endpoint and integration security
6. **Remediation Roadmap**: Prioritized action plan

## Step 3: Fix Vulnerabilities

For each finding in the report:

1. **Locate the vulnerability** using file:line reference
2. **Review the explanation** to understand the security risk
3. **Apply the secure alternative** code provided in the report
4. **Test your changes** to ensure functionality
5. **Re-run the review** to verify the fix

### Example Fix Workflow

```bash
# 1. Initial scan finds 3 critical issues
claude code security-review --quick

# 2. Fix the issues based on report guidance
# (edit files...)

# 3. Re-scan to verify fixes
claude code security-review --quick

# 4. Review shows "Fixed: 3 vulnerabilities"
```

## Step 4: Configure for Your Project (Optional)

Create `.code-review-config.yml` in your project root:

```yaml
project:
  name: "My Application"

scope:
  include:
    - "src/**/*.py"
    - "api/**/*.js"
  exclude:
    - "**/test/**"
    - "**/node_modules/**"

compliance:
  pci_dss:
    enabled: true    # Enable if handling payment data
  soc2:
    enabled: true
  hipaa:
    enabled: false   # Enable if handling health data

reporting:
  output_dir: "security-reports"

thresholds:
  max_critical: 0       # Fail if any critical findings
  max_high: 5           # Fail if more than 5 high findings
  fail_on_regression: true  # Fail if fixed issues return
```

### Configuration Benefits

- **Faster scans**: Exclude test files and dependencies
- **Compliance focus**: Enable only relevant frameworks
- **CI/CD integration**: Set thresholds for build failures
- **Custom output**: Configure report location

## Step 5: Integrate with Your Workflow

### Pre-Commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
echo "Running security scan on changed files..."
claude code security-review --quick --diff || {
  echo "Security issues found. Fix before committing."
  exit 1
}
```

Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

### GitHub Actions

Add to `.github/workflows/security.yml`:

```yaml
name: Security Review

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Security Review
        run: claude code security-review --verbose

      - name: Upload Report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-report
          path: security-reports/latest-report.md
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
security-review:
  stage: test
  script:
    - claude code security-review --verbose
  artifacts:
    paths:
      - security-reports/
    when: always
  allow_failure: false
```

## Understanding Security Rules

CodeGuardian uses **25 comprehensive security rules** organized in three levels:

### Level 0 (Foundational) - 17 Rules
Core security principles covering authentication, authorization, input validation, API security, cryptography, logging, and more.

### Level 1 (Specific) - 5 Rules
Focused vulnerability detection for hardcoded credentials, weak algorithms, certificates, and safe C functions.

### Level 2 (Comprehensive) - 3 Rules
Deep detection patterns for:
- **Secrets**: Passwords, AWS keys, API tokens, private keys
- **Injection**: SQL, command, XSS vulnerabilities
- **Cryptography**: Weak algorithms, password hashing, insecure random

See `rules/RULES-INDEX.md` for complete catalog.

## Common Findings and Quick Fixes

### 1. Hardcoded Secrets

**Finding**: `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`

**Fix**: Use environment variables
```python
import os
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
if not AWS_ACCESS_KEY_ID:
    raise ValueError("AWS_ACCESS_KEY_ID not set")
```

### 2. SQL Injection

**Finding**: `query = f"SELECT * FROM users WHERE id = {user_id}"`

**Fix**: Use parameterized queries
```python
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```

### 3. Weak Password Hashing

**Finding**: `password_hash = hashlib.sha256(password.encode()).hexdigest()`

**Fix**: Use bcrypt
```python
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

### 4. Insecure Random

**Finding**: `token = str(random.random())`

**Fix**: Use secrets module
```python
import secrets
token = secrets.token_hex(32)
```

## Creating Custom Rules

Need organization-specific detection? Create custom rules in `security-rules/`:

1. **Create markdown file**: `security-rules/custom-my-rule.md`

2. **Use this template**:
```markdown
---
description: What this rule checks
languages:
  - python
alwaysApply: false
severity: HIGH
---

# Rule Title

## Detection Patterns

**INSECURE:**
```python
# Vulnerable code example
```

**SECURE:**
```python
# Secure alternative
```

## Remediation

Step-by-step fix instructions.
```

3. **Test your rule**:
```bash
claude code security-review --verbose
```

See `rules/examples/custom-aws-credentials.md` for a complete example.

## Command Reference

```bash
# Full review with all rules
claude code security-review

# Quick scan (CI/CD friendly)
claude code security-review --quick

# Specific path
claude code security-review --path src/

# Changed files only
claude code security-review --diff

# Verbose output
claude code security-review --verbose

# Compliance focus
claude code security-review --compliance pci_dss

# List loaded rules
claude code security-review --list-rules
```

## Exit Codes (for CI/CD)

- **0**: Success - findings below thresholds
- **1**: Critical findings exceed threshold
- **2**: High findings exceed threshold
- **3**: Regression detected (fixed vulnerability returned)
- **10**: Configuration or analysis error

## Troubleshooting

### "No configuration found"

Normal on first run. CodeGuardian uses sensible defaults. Create `.code-review-config.yml` if you need custom settings.

### "Analysis takes too long"

Use `--quick` mode or narrow scope in configuration:
```yaml
scope:
  include:
    - "src/**/*.py"  # More specific
  exclude:
    - "**/test/**"
    - "**/node_modules/**"
```

### "Too many false positives"

1. Review carefully - many "false positives" are real issues
2. Add suppression comments: `# nosec` or `# security: ignore`
3. Report persistent issues to improve rule accuracy

### "Custom rules not loading"

1. Check file extension is `.md`
2. Verify frontmatter syntax (YAML between `---` markers)
3. Run with `--verbose` to see rule loading messages

## Next Steps

1. **Run your first scan**: `claude code security-review`
2. **Review the report**: `cat security-reports/latest-report.md`
3. **Fix critical issues**: Follow remediation guidance in report
4. **Configure for your needs**: Create `.code-review-config.yml`
5. **Integrate with CI/CD**: Add to your pipeline
6. **Create custom rules**: Add organization-specific detection

## Resources

- **Full Documentation**: See `README.md`
- **Rule Catalog**: See `rules/RULES-INDEX.md`
- **Agent Details**: See `agent/agent-definition.md`
- **Custom Rules Guide**: See `docs/custom-rules-guide.md`
- **Migration Guide**: See `MARKDOWN-RULES-MIGRATION.md`

## Getting Help

- **Documentation**: Start with `README.md` and `CLAUDE.md`
- **Examples**: Check `rules/examples/` for custom rule templates
- **Sample Vulnerable Code**: Test on `examples/sample-vulnerable-code/`

---

**Ready to secure your code?** Run `claude code security-review` now!

**Version**: 2.0.0 | **Last Updated**: 2024-10-24
