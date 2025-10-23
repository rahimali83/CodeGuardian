# Security Rules

## Overview

This directory contains the built-in security rules for the Security Code Review Agent. Custom rules can be created and placed in your project's custom rules directory (default: `/security-rules/` in your project root).

## Built-in Rules

The `built-in-rules.yml` file contains comprehensive security rules covering:

- **Injection Vulnerabilities**: SQL injection, command injection, XSS, LDAP injection
- **Authentication & Session Management**: Hardcoded credentials, weak password hashing, session issues
- **Sensitive Data Exposure**: Cleartext transmission, logging of sensitive data
- **Access Control**: Missing authorization, path traversal
- **Cryptographic Issues**: Weak algorithms, insecure random numbers
- **API Security**: Missing rate limiting
- **Configuration Issues**: Debug mode enabled, missing security headers

**Total Built-in Rules**: 17 rules covering the most critical vulnerability types

## Custom Rules Examples

The `examples/` directory contains example custom rules demonstrating:

- `custom-aws-credentials.yml`: Detecting hardcoded AWS credentials
- `custom-database-security.yml`: Insecure database connection practices
- `custom-api-rate-limiting.yml`: Missing API rate limiting
- `custom-logging-security.yml`: Insecure logging practices

These examples show how to create effective custom rules for your organization.

## Creating Custom Rules

See `docs/custom-rules-guide.md` for comprehensive documentation on creating custom security rules.

### Quick Start

1. Create a directory for your custom rules (e.g., `security-rules/` in your project)
2. Create YAML files following the rule format (see examples)
3. Configure rules directory in `.code-review-config.yml`:
   ```yaml
   rules:
     custom_rules_dir: "security-rules"
     load_defaults: true
   ```
4. Run security review - custom rules are automatically loaded

## Rule Categories

- **security**: General security vulnerabilities
- **compliance**: Compliance-specific requirements
- **api_security**: API security issues
- **quality**: Code quality affecting security

## Severity Levels

- **CRITICAL**: Immediate system compromise, data breach, critical compliance violation
- **HIGH**: Significant security weakness, exploitable with moderate effort
- **MEDIUM**: Requires specific conditions to exploit, limited impact
- **LOW**: Minor improvements, best practice violations
- **INFORMATIONAL**: Suggestions for security enhancements

## Contributing Rules

If you've created useful custom rules, consider sharing them with the community:

1. Ensure the rule is well-tested and documented
2. Include test cases
3. Add clear remediation guidance with code examples
4. Submit as contribution to the project

## Resources

- [Custom Rules Guide](../docs/custom-rules-guide.md)
- [Built-in Rules Reference](built-in-rules.yml)
- [Example Custom Rules](examples/)
