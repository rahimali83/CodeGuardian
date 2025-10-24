# Custom Security Rules Examples

This directory contains example custom security rules to help you create organization-specific detection rules for
CodeGuardian.

## Format: Markdown (Recommended)

**CodeGuardian now uses markdown-based rules** that Claude agents can understand and reason about. Markdown rules
provide:

- Natural language descriptions that are easier to maintain
- Context-aware detection that reduces false positives
- Better explanations and remediation guidance
- Educational value as security documentation

## Example Rule: AWS Credentials Detection

See **`custom-aws-credentials.md`** for a comprehensive example of a markdown-based custom rule. This example
demonstrates:

- YAML frontmatter for rule metadata (languages, severity, compliance)
- Natural language detection patterns with code examples
- Insecure vs. secure code comparisons
- Step-by-step remediation instructions
- Compliance framework mappings (PCI DSS, SOC 2, NIST CSF)
- False positive handling
- Best practices guidance

## Creating Your Own Custom Rules

### 1. Create a Markdown File

Create a new `.md` file in the `security-rules/` directory (or your configured custom rules directory):

```bash
touch security-rules/custom-my-rule.md
```

### 2. Use the Template Structure

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

State the core security principle.

## Detection Patterns

### Pattern Category

**INSECURE - Flag as HIGH severity:**
```python
# Example of vulnerable code
```

**SECURE - What developers must use:**

```python
# Example of secure alternative
```

### What to Look For

- Specific patterns to detect
- Context indicators
- Confidence criteria

### False Positive Indicators

- When NOT to flag
- Exception cases

## Secure Alternatives

Detailed secure implementations with code examples.

## Remediation Steps

1. Step-by-step fix instructions
2. Choose secure method
3. Test and verify

## Compliance Impact

**Framework X.X.X**: Requirement description

## References

- Relevant documentation links
- CWE/OWASP references

## Summary

Key takeaways.

```

### 3. Test Your Rule

```bash
# Test on sample code
claude code security-review --path path/to/test/file --verbose

# Verify rule is loaded
claude code security-review --list-rules
```

## Rule Organization

### Rule Severity Levels

- **CRITICAL**: Immediate security risk (hardcoded secrets, SQL injection, RCE)
- **HIGH**: Serious vulnerability (XSS, weak crypto, missing auth)
- **MEDIUM**: Moderate risk (weak random, missing rate limiting, debug mode)
- **LOW**: Best practice violation (weak validation, code quality)

### Rule Scope

**`alwaysApply: true`** - Apply to all files regardless of extension

- Use for: Secrets detection, hardcoded credentials, sensitive data exposure
- Example: Detecting AWS keys works across all file types

**`alwaysApply: false`** - Apply only to files matching specified languages

- Use for: Language-specific vulnerabilities (SQL injection, XSS, command injection)
- Example: Python-specific SQL injection patterns

### Language Support

Specify languages in frontmatter:

```yaml
languages:
  - python
  - javascript
  - java
  - go
```

Common language identifiers:

- `python`, `javascript`, `typescript`, `java`, `go`, `ruby`, `php`, `c`, `cpp`, `csharp`, `kotlin`, `swift`
- `sql`, `html`, `css`, `yaml`, `json`, `xml`, `shell`, `powershell`

## Common Custom Rule Patterns

### Organization-Specific Secrets

Detect internal API keys, tokens, or credentials unique to your organization:

```markdown
**Detection Pattern:**
- Internal API token format: `MYORG_[A-Z0-9]{32}`
- Internal service keys: `myservice-api-key-[a-z0-9-]+`
```

### Framework-Specific Security

Detect security issues in your specific framework or library:

```markdown
**Detection Pattern:**
- Django: Missing `@login_required` decorator on views
- Express: Missing authentication middleware on routes
- Spring: Missing `@Secured` annotation on controllers
```

### Compliance-Specific Controls

Enforce compliance requirements specific to your industry:

```markdown
**Detection Pattern:**
- HIPAA: PHI data must be encrypted at rest and in transit
- PCI DSS: Cardholder data must not be logged
- SOX: Financial data access must be audited
```

### Internal Security Policies

Enforce internal security policies:

```markdown
**Detection Pattern:**
- All database queries must use prepared statements
- All external API calls must have timeouts
- All user input must be validated against schema
```

## Legacy YAML Examples

This directory also contains YAML-based rule examples (`*.yml` files) for historical reference:

- `custom-api-rate-limiting.yml` - API rate limiting detection
- `custom-database-security.yml` - Database security patterns
- `custom-logging-security.yml` - Logging security controls

**Note**: YAML rules are no longer the recommended format. These files are kept as reference but should not be used as
templates for new rules. Use the markdown format shown in `custom-aws-credentials.md` instead.

## Integration with CI/CD

Custom rules are automatically loaded during security reviews:

```bash
# In your CI/CD pipeline
claude code security-review --verbose

# Pre-commit hook
claude code security-review --quick --diff
```

## Documentation

For more details on creating custom rules:

- See `docs/custom-rules-guide.md` for comprehensive documentation
- Review built-in rules in `rules/rules/codeguard-*.md` for patterns
- Check `rules/RULES-INDEX.md` for complete rule catalog

## Questions?

If you have questions about creating custom rules:

1. Review the built-in rules for patterns and structure
2. Check the documentation in `docs/`
3. Examine `custom-aws-credentials.md` for a complete example
4. Test your rules with `--verbose` flag to see detection behavior

---

**Last Updated**: 2024-10-24
**Format Version**: 2.0.0 (Markdown-based rules)
