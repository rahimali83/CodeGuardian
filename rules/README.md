# Security Rules

## Overview

This directory contains the built-in security rules for the CodeGuardian Security Code Review Agent. CodeGuardian uses **markdown-based security rules** that Claude agents can understand and reason about contextually.

Custom rules can be created and placed in your project's custom rules directory (default: `security-rules/` in your project root).

## Why Markdown Rules?

CodeGuardian uses natural language markdown rules instead of traditional pattern matching because:

- **Better Context Understanding**: Claude agents excel at understanding natural language explanations
- **Reduced False Positives**: Context-aware detection distinguishes real vulnerabilities from safe patterns
- **Educational Value**: Rules serve as security documentation and training material
- **Easier Maintenance**: Human-readable format that doesn't require regex expertise
- **Adaptive Detection**: Can understand semantic equivalence across different coding styles

## Built-in Rules Organization

Rules are organized in three levels for progressive coverage:

### Level 0: Foundational Security Principles (18 rules)

Core security domains covering essential practices:

- `codeguard-0-authentication-mfa.md` - Authentication, MFA, password policies
- `codeguard-0-authorization-access-control.md` - RBAC, IDOR prevention, access control
- `codeguard-0-input-validation-injection.md` - Input validation, injection defense
- `codeguard-0-api-web-services.md` - REST, GraphQL, SOAP security
- `codeguard-0-client-side-web-security.md` - XSS, CSRF, CSP, clickjacking
- `codeguard-0-data-storage.md` - Database security, encryption at rest
- `codeguard-0-file-handling-and-uploads.md` - File upload security
- `codeguard-0-session-management-and-cookies.md` - Session handling, cookie security
- `codeguard-0-logging.md` - Secure logging, sensitive data redaction
- `codeguard-0-additional-cryptography.md` - Key management, TLS configuration
- `codeguard-0-cloud-orchestration-kubernetes.md` - Kubernetes, container security
- `codeguard-0-devops-ci-cd-containers.md` - DevOps and CI/CD security
- `codeguard-0-framework-and-languages.md` - Framework-specific patterns
- `codeguard-0-iac-security.md` - Infrastructure as Code security
- `codeguard-0-mobile-apps.md` - Mobile application security
- `codeguard-0-privacy-data-protection.md` - GDPR, CCPA compliance
- `codeguard-0-supply-chain-security.md` - Supply chain and dependency security
- `codeguard-0-xml-and-serialization.md` - XXE, deserialization vulnerabilities

### Level 1: Specific Vulnerability Classes (4 rules)

Focused detection for common vulnerability types:

- `codeguard-1-hardcoded-credentials.md` - Secrets in source code
- `codeguard-1-crypto-algorithms.md` - Banned and deprecated algorithms
- `codeguard-1-digital-certificates.md` - Certificate validation
- `codeguard-1-safe-c-functions.md` - Memory-safe C function alternatives

### Level 2: Comprehensive Detection (3 rules)

Deep, detailed detection with extensive code examples:

- `codeguard-2-secrets-detection.md` - Comprehensive secrets detection (passwords, AWS, API keys, private keys)
- `codeguard-2-injection-vulnerabilities.md` - SQL, command, and XSS injection across all languages
- `codeguard-2-cryptography-security.md` - Weak crypto, password hashing, insecure random

**Total: 25 comprehensive security rules**

## Rule Coverage

### Vulnerability Types

- **Injection Flaws**: SQL injection, command injection, XSS, LDAP injection, NoSQL injection, template injection
- **Authentication Issues**: Hardcoded credentials, weak passwords, insecure tokens, missing MFA
- **Sensitive Data Exposure**: Cleartext transmission, secrets in logs, unencrypted storage
- **Access Control**: Missing authorization, IDOR, path traversal, privilege escalation
- **Cryptographic Failures**: Weak algorithms (MD5, SHA-1), fast password hashing, insecure random
- **API Security**: Missing rate limiting, excessive data exposure, missing authentication
- **Configuration Issues**: Debug mode, missing security headers, insecure defaults
- **File Security**: Unsafe uploads, path traversal, missing validation
- **Session Management**: Session fixation, weak session IDs, missing cookie flags

### Language Support

Rules include detection patterns and secure examples for:

- **Python**, **JavaScript**, **TypeScript**, **Java**, **PHP**, **Ruby**, **Go**
- **C**, **C++**, **C#**, **Kotlin**, **Swift**
- **SQL**, **HTML**, **YAML**, **JSON**, **XML**
- **Shell**, **PowerShell**

### Compliance Frameworks

All rules are mapped to relevant compliance requirements:

- **PCI DSS** - Payment Card Industry Data Security Standard
- **SOC 2** - Service Organization Control 2
- **HIPAA** - Health Insurance Portability and Accountability Act
- **GDPR** - General Data Protection Regulation
- **CCPA** - California Consumer Privacy Act
- **NIST CSF** - NIST Cybersecurity Framework
- **OWASP Top 10** - Complete coverage
- **CWE** - Common Weakness Enumeration mappings

## Rule Index

For a complete catalog with descriptions, see **[RULES-INDEX.md](RULES-INDEX.md)**.

The index provides:
- Quick reference by vulnerability type
- Search by technology or language
- Compliance framework mappings
- When to apply each rule
- Rule priority levels

## Custom Rules Examples

The `examples/` directory contains example custom rules:

- **`custom-aws-credentials.md`** - Comprehensive markdown rule for detecting hardcoded AWS credentials
- **`README.md`** - Template and guide for creating custom markdown rules

**Legacy YAML examples** (`*.yml` files) are preserved for reference but should **not** be used as templates for new rules.

## Creating Custom Rules

### Quick Start

1. **Create a markdown file** in your custom rules directory:
   ```bash
   mkdir -p security-rules
   touch security-rules/custom-my-rule.md
   ```

2. **Use the markdown template**:
   ```markdown
   ---
   description: Brief description of what this rule covers
   languages:
     - python
     - javascript
   alwaysApply: false  # Set to true to apply to all files
   severity: HIGH      # CRITICAL, HIGH, MEDIUM, LOW
   ---

   # Rule Title

   ## Critical Principle

   State the core security principle this rule enforces.

   ## Detection Patterns

   ### Pattern Category

   **INSECURE - Flag as HIGH severity:**
   ```python
   # Example of insecure code pattern
   ```

   **SECURE - What developers must use:**
   ```python
   # Example of secure alternative
   ```

   ### When to Flag

   - Specific patterns to look for
   - Context indicators
   - Confidence criteria

   ## Remediation

   Step-by-step fix instructions.

   ## Compliance Impact

   **Framework X.X.X**: Requirement description

   ## Summary

   Key takeaways.
   ```

3. **Configure custom rules directory** in `.code-review-config.yml`:
   ```yaml
   rules:
     custom_rules_dir: "security-rules"
     load_defaults: true
   ```

4. **Test your rule**:
   ```bash
   claude code security-review --verbose
   ```

### Detailed Guides

- **[examples/README.md](examples/README.md)** - Complete guide with templates
- **[examples/custom-aws-credentials.md](examples/custom-aws-credentials.md)** - Full example rule
- **[../QUICKSTART.md](../QUICKSTART.md)** - Quick start guide with custom rule examples

## Rule Format

### Frontmatter (Required)

Every rule must have YAML frontmatter:

```markdown
---
description: What this rule checks
languages:
  - python
  - javascript
alwaysApply: false
severity: HIGH
---
```

### Rule Sections

A complete rule should include:

1. **Critical Principle** - Core security concept
2. **Detection Patterns** - What to look for with insecure/secure code examples
3. **When to Flag** - Confidence indicators and context
4. **False Positive Indicators** - When NOT to flag
5. **Secure Alternatives** - Detailed secure implementations
6. **Remediation Steps** - How to fix the issue
7. **Compliance Impact** - Related framework requirements
8. **References** - External documentation links
9. **Summary** - Key takeaways

## Rule Categories

- **security**: General security vulnerabilities
- **compliance**: Compliance-specific requirements
- **api_security**: API security issues
- **quality**: Code quality affecting security

## Severity Levels

- **CRITICAL**: Immediate system compromise, data breach, critical compliance violation
  - Examples: Hardcoded secrets, SQL injection, RCE vulnerabilities
- **HIGH**: Significant security weakness, exploitable with moderate effort
  - Examples: XSS, weak cryptography, missing authentication
- **MEDIUM**: Requires specific conditions to exploit, limited impact
  - Examples: Weak random generation, missing rate limiting, debug mode
- **LOW**: Minor improvements, best practice violations
  - Examples: Weak input validation, code quality issues

## Testing Rules

### Test on Sample Code

```bash
# Test on intentionally vulnerable examples
claude code security-review --path examples/sample-vulnerable-code/ --verbose
```

### Verify Rule Loading

```bash
# List all loaded rules
claude code security-review --list-rules

# Run with verbose to see rule loading
claude code security-review --verbose
```

## Contributing Rules

If you've created useful custom rules, consider sharing them:

1. **Test thoroughly** - Verify detection works across different code styles
2. **Add code examples** - Both insecure and secure versions
3. **Include remediation** - Step-by-step fix instructions
4. **Document compliance** - Map to relevant frameworks
5. **Test for false positives** - Verify it doesn't flag safe code
6. **Submit contribution** - Share with the community

## Resources

- **[RULES-INDEX.md](RULES-INDEX.md)** - Complete catalog of all 25 rules
- **[examples/custom-aws-credentials.md](examples/custom-aws-credentials.md)** - Full example custom rule
- **[examples/README.md](examples/README.md)** - Template and guide
- **[../QUICKSTART.md](../QUICKSTART.md)** - Quick start guide
- **[../docs/custom-rules-guide.md](../docs/custom-rules-guide.md)** - Legacy YAML guide (historical reference)

## Migration from YAML

If you have existing YAML-based custom rules:

1. Review **[../MARKDOWN-RULES-MIGRATION.md](../MARKDOWN-RULES-MIGRATION.md)** for migration guidance
2. Use markdown template from **[examples/README.md](examples/README.md)**
3. Convert patterns to natural language descriptions with code examples
4. Test converted rules thoroughly

---

**Version**: 2.1.0 (Markdown-based rules - 25 comprehensive rules)
**Last Updated**: 2025-10-24
**Total Rules**: 25 (18 Level 0 + 4 Level 1 + 3 Level 2)
**Total Lines**: 3,186+ lines of security guidance
**Format**: Markdown with YAML frontmatter
