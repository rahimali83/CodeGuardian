# Custom Security Rules Guide

> **⚠️ IMPORTANT UPDATE (Version 2.0.0)**: CodeGuardian now uses **markdown-based security rules** instead of YAML.
>
> **For the current markdown rule format**, see:
> - `rules/examples/custom-aws-credentials.md` - Complete markdown rule example
> - `rules/examples/README.md` - Markdown rule template and guide
> - `QUICKSTART.md` - Quick guide to creating custom rules
>
> **This document describes the legacy YAML format** and is kept for historical reference only. New custom rules should use the markdown format.

## Overview

The Security Code Review Agent supports custom security rules that extend the built-in rule set with organization-specific requirements, industry-specific compliance checks, or rules for internal frameworks and libraries. Custom rules allow you to tailor the security analysis to your unique needs while maintaining the standardized reporting and tracking capabilities of the agent.

**Note**: This guide describes the **legacy YAML-based format**. For current markdown-based rules, see the resources listed at the top of this document.

## Why Create Custom Rules?

Custom rules enable you to:

- **Enforce Organization-Specific Standards**: Implement security policies unique to your organization
- **Check Internal Frameworks**: Add rules for your custom libraries, frameworks, or APIs
- **Industry-Specific Compliance**: Implement industry-specific regulations beyond built-in frameworks
- **Technology-Specific Checks**: Add rules for specific technologies or languages your team uses
- **Custom Vulnerability Patterns**: Detect security issues specific to your architecture
- **Proprietary Code Patterns**: Flag anti-patterns or deprecated practices in your codebase

## Custom Rules Directory Structure

Custom rules are YAML files placed in your project's custom rules directory:

```
your-project/
├── security-rules/               # Default custom rules directory
│   ├── aws-security.yml         # AWS-specific rules
│   ├── internal-api-rules.yml   # Internal API security rules
│   ├── pii-handling.yml         # PII handling rules
│   └── company-standards.yml    # Company coding standards
├── src/
│   └── ...
└── .code-review-config.yml      # Configuration specifying rules directory
```

The agent automatically loads all `.yml` and `.yaml` files from the configured directory when performing security reviews.

## Complete Rule File Structure

Here's the comprehensive structure of a custom rule file with all available fields:

```yaml
rule_id: CUSTOM-XXX-NNN
title: "Brief Descriptive Title"
description: |
  Detailed multi-line description explaining:
  - What this rule checks for
  - Why it's a security concern
  - When it applies
  - What makes it different from similar rules

severity: CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
category: security | compliance | quality | api_security

# Optional: CWE mapping
cwe: CWE-XXX

# Optional: OWASP mapping
owasp: "A0X:2021 - Category Name"

# Optional: Compliance framework mappings
compliance:
  - framework: PCI_DSS | SOC2 | PIPEDA | CCPA | HIPAA | NIST_CSF
    requirement: "Requirement number or identifier"
    description: "How this rule relates to the requirement"
  - framework: ANOTHER_FRAMEWORK
    requirement: "Another requirement"
    description: "Description"

# Required: Detection patterns (at least one method)
detection:
  # Regex patterns
  patterns:
    - pattern: 'regular expression here'
      description: "What this pattern detects"
      confidence: 0.0-1.0  # 0 = low confidence, 1 = certain
      language: python | javascript | java | go | ruby | php | typescript

  # Exact string matching
  exact_strings:
    - "exact string to match"
    - "another exact string"

  # Dangerous function calls
  function_calls:
    - "function_name"
    - "module.function_name"

  # Dangerous imports
  dangerous_imports:
    - "module_name"
    - "package.module"

  # AST-based patterns (for structural matching)
  ast_patterns:
    - type: function_definition | class_definition | variable_assignment
      name_pattern: "regex for name"
      has_decorator: "decorator_name"
      missing_decorator: "required_decorator"
      description: "What this pattern detects"

# Required: Scope configuration
scope:
  # Glob patterns for files this rule applies to
  file_patterns:
    - "**/*.py"
    - "**/*.js"

  # Optional: Patterns to exclude
  exclude:
    - "**/test/**"
    - "**/node_modules/**"

  # Languages this rule applies to
  languages:
    - python
    - javascript
    - java

# Optional: Context requirements
context:
  # Whether to check inside comments
  check_comments: true | false

  # Whether to check string literals
  check_strings: true | false

  # Whether to check variable names
  check_variable_names: true | false

  # Whether rule requires certain context
  requires_network_access: true | false
  requires_database_connection: true | false

# Optional: False positive handling
false_positive_indicators:
  - pattern: 'regex pattern suggesting false positive'
    description: "Why this indicates a false positive"

# Optional: Suppression comment
suppression_comment: "# nosec: rule-name"

# Required: Remediation guidance
remediation:
  description: |
    Detailed explanation of how to fix violations of this rule.

  steps:
    - "Step 1: Specific action to take"
    - "Step 2: Another action"
    - "Step 3: Final verification step"

  best_practices:
    - "Best practice 1"
    - "Best practice 2"

  code_examples:
    - language: python
      framework: optional_framework_name
      insecure: |
        # Insecure code example showing the violation
        bad_code_here()

      secure: |
        # Secure code example showing the fix
        good_code_here()

    - language: javascript
      insecure: |
        // Another language example
      secure: |
        // Secure version

  recommended_tools:
    - "Tool or library that helps implement the fix"

# Optional but recommended: References
references:
  - "https://cwe.mitre.org/..."
  - "https://owasp.org/..."
  - "Internal documentation URL"

# Optional but recommended: Test cases
test_cases:
  - should_trigger: true | false
    code: |
      Code that should or shouldn't trigger the rule
    description: "What this test case validates"

  - should_trigger: false
    code: |
      Code that should not trigger
    description: "Negative test case"

# Optional: Metadata
created: YYYY-MM-DD
author: "Author Name or Team"
last_updated: YYYY-MM-DD
version: "1.0.0"
status: active | experimental | deprecated
tags:
  - tag1
  - tag2
  - tag3
```

## Field Descriptions

### Required Fields

#### rule_id

**Format**: `CUSTOM-XXX-NNN` where XXX is a category code and NNN is a number

**Example**: `CUSTOM-AWS-001`, `CUSTOM-API-042`

**Purpose**: Unique identifier for tracking findings across reports. Must be unique across all custom rules.

**Important**: Once assigned, never change a rule_id. This breaks tracking of vulnerabilities across review iterations.

#### title

**Format**: Brief descriptive title (under 80 characters)

**Example**: "Hardcoded AWS Credentials", "Missing API Rate Limiting"

**Purpose**: Concise identification of what the rule checks

#### description

**Format**: Multi-line detailed description

**Purpose**: Explain what the rule checks, why it matters, and relevant context

**Best Practice**: Include:
- What is being checked
- Why it's a security concern
- What makes code vulnerable
- When the rule applies vs doesn't apply

#### severity

**Values**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`

**Guidelines**:
- **CRITICAL**: Allows immediate system compromise, data breach, or critical compliance violation
- **HIGH**: Significant security weakness exploitable with moderate effort
- **MEDIUM**: Issues requiring specific conditions or having limited impact
- **LOW**: Minor improvements, best practices violations
- **INFORMATIONAL**: Suggestions and opportunities for defense in depth

#### category

**Values**: `security`, `compliance`, `quality`, `api_security`

**Purpose**: Organizes rules and allows filtering during analysis

#### detection

**Purpose**: Defines how the agent detects violations

**Required**: At least one detection method

**Methods**:
1. **Regex Patterns**: Most flexible, matches code patterns
2. **Exact Strings**: Fast matching for specific strings
3. **Function Calls**: Identifies specific function usage
4. **Dangerous Imports**: Flags problematic libraries
5. **AST Patterns**: Structural code matching (most precise, language-specific)

#### scope

**Purpose**: Defines which files the rule applies to

**Required Subfields**:
- `file_patterns`: Glob patterns for file matching
- `languages`: Programming languages the rule applies to

#### remediation

**Purpose**: Tells developers how to fix violations

**Required Subfields**:
- `description`: Overall remediation approach
- `steps`: Specific actions to take
- `code_examples`: Insecure and secure code examples

### Optional but Recommended Fields

#### cwe

Maps to Common Weakness Enumeration for standardized vulnerability classification

**Example**: `CWE-798` (Use of Hard-coded Credentials)

**Purpose**: Links to established vulnerability taxonomy

#### owasp

Maps to OWASP Top 10 or other OWASP classifications

**Example**: `A07:2021 - Identification and Authentication Failures`

#### compliance

Maps rules to specific compliance requirements

**Why Important**: Automatically populates compliance sections of reports

**Example**:
```yaml
compliance:
  - framework: PCI_DSS
    requirement: "8.2.1"
    description: "Do not use vendor-supplied defaults"
  - framework: SOC2
    requirement: "CC6.1"
    description: "Logical access controls"
```

#### test_cases

Validates that rules work as intended

**Best Practice**: Include both positive (should trigger) and negative (shouldn't trigger) test cases

**Example**:
```yaml
test_cases:
  - should_trigger: true
    code: |
      password = "hardcoded_password"
    description: "Hardcoded password should be flagged"

  - should_trigger: false
    code: |
      password = os.environ.get('PASSWORD')
    description: "Environment variable should not be flagged"
```

## Detection Patterns Deep Dive

### Regex Patterns

Most flexible detection method. Matches code patterns using regular expressions.

**Fields**:
- `pattern`: Regular expression (ripgrep syntax)
- `description`: What this pattern detects
- `confidence`: 0.0-1.0 (how likely findings are true positives)
- `language`: Optional language specification

**Examples**:

```yaml
# Detect hardcoded API keys
- pattern: '(api_key|apikey|api-key)\s*=\s*["\'][A-Za-z0-9]{20,}["\']'
  description: "Hardcoded API key"
  confidence: 0.9

# Detect SQL injection in Python
- pattern: 'cursor\.execute\([^)]*%s[^)]*%[^)]*\)'
  description: "SQL query with string formatting"
  confidence: 0.8
  language: python

# Detect eval usage
- pattern: '\beval\s*\('
  description: "Use of eval() function"
  confidence: 0.95
```

**Tips**:
- Use `\b` for word boundaries to avoid partial matches
- Escape special regex characters: `\.`, `\(`, `\)`, `\[`, `\]`, `\{`, `\}`, etc.
- Test patterns thoroughly with various code styles
- Use confidence levels to indicate likelihood of false positives

### Exact String Matching

Fast and precise for specific strings.

**Use When**: Looking for specific function names, keywords, or configuration values

**Examples**:

```yaml
exact_strings:
  - "eval("
  - "exec("
  - "aws_access_key_id="
  - "DEBUG = True"
```

**Advantages**: Very fast, no false positives from pattern variations
**Disadvantages**: Miss variations (spacing, case, etc.)

### Function Calls

Identifies usage of specific functions.

**Use When**: Flagging dangerous or deprecated functions

**Examples**:

```yaml
function_calls:
  - "os.system"
  - "subprocess.call"
  - "eval"
  - "exec"
  - "pickle.loads"
  - "yaml.load"  # Unsafe YAML deserialization
```

### Dangerous Imports

Flags import of problematic libraries.

**Use When**: Certain libraries shouldn't be used in production

**Examples**:

```yaml
dangerous_imports:
  - "pickle"  # Insecure deserialization
  - "marshal"  # Insecure deserialization
  - "shelve"  # Uses pickle internally
```

### AST Patterns

Most sophisticated detection using Abstract Syntax Tree analysis.

**Use When**: Need to understand code structure, not just text

**Limitations**: Language-specific, requires AST support

**Example**:

```yaml
ast_patterns:
  - type: function_definition
    name_pattern: "^(login|authenticate).*"
    missing_decorator: "rate_limit"
    description: "Authentication function without rate limiting"
```

## Scope Configuration Best Practices

### File Patterns

Use glob patterns to target specific files:

```yaml
scope:
  file_patterns:
    # Include all Python files in src
    - "src/**/*.py"

    # Include JavaScript and TypeScript
    - "**/*.js"
    - "**/*.jsx"
    - "**/*.ts"
    - "**/*.tsx"

    # Include configuration files
    - "**/*.yml"
    - "**/*.yaml"
    - "**/*.json"

  exclude:
    # Exclude dependencies
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/venv/**"

    # Exclude tests
    - "**/test/**"
    - "**/tests/**"
    - "**/*.test.js"
    - "**/*.spec.ts"

    # Exclude build artifacts
    - "**/dist/**"
    - "**/build/**"
```

### Language Specification

Limit rules to specific languages for performance and accuracy:

```yaml
scope:
  languages:
    - python
    - javascript
    - typescript
```

**Available Languages**: python, javascript, typescript, java, go, c, cpp, csharp, ruby, php, kotlin, swift, rust

## Writing Effective Remediation Guidance

Remediation is where you educate developers. Make it actionable and clear.

### Structure

```yaml
remediation:
  description: |
    High-level explanation of how to fix the issue and why the fix works.

  steps:
    - "Concrete step 1 with specifics"
    - "Concrete step 2"
    - "Verification step"

  best_practices:
    - "Related best practice"
    - "Defense in depth recommendation"

  code_examples:
    - language: python
      insecure: |
        # Show the problematic code
      secure: |
        # Show the correct implementation

  recommended_tools:
    - "Tool or library name with brief description"
```

### Writing Code Examples

**Insecure Example**: Show exactly what's wrong

```python
# INSECURE - SQL Injection vulnerability
username = request.GET.get('username')
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
```

**Secure Example**: Show the correct approach with explanation

```python
# SECURE - Parameterized query prevents SQL injection
username = request.GET.get('username')
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))

# The database driver handles escaping, making injection impossible
```

**Best Practices**:
- Include comments explaining why secure code is secure
- Show real, runnable code, not pseudocode
- Include imports and context if needed
- Provide examples for multiple languages/frameworks when applicable

## Complete Rule Examples

### Example 1: Simple Pattern-Based Rule

```yaml
rule_id: CUSTOM-EVAL-001
title: "Use of eval() Function"
description: |
  The eval() function executes arbitrary code and is dangerous when used with
  untrusted input. It can lead to code injection vulnerabilities.

severity: HIGH
category: security
cwe: CWE-95
owasp: "A03:2021 - Injection"

detection:
  patterns:
    - pattern: '\beval\s*\('
      description: "eval() function call"
      confidence: 0.95

scope:
  file_patterns:
    - "**/*.py"
    - "**/*.js"
  languages:
    - python
    - javascript

remediation:
  description: |
    Avoid eval(). Use safer alternatives like ast.literal_eval() for Python
    or JSON.parse() for JavaScript.

  steps:
    - "Replace eval() with safer alternatives"
    - "If eval() is absolutely necessary, strictly validate input"
    - "Never use eval() with user-controllable input"

  code_examples:
    - language: python
      insecure: |
        user_input = request.GET.get('expr')
        result = eval(user_input)  # DANGEROUS

      secure: |
        import ast
        user_input = request.GET.get('expr')
        result = ast.literal_eval(user_input)  # SAFE for literals only

references:
  - "https://cwe.mitre.org/data/definitions/95.html"

created: 2024-01-15
version: "1.0.0"
status: active
```

### Example 2: Compliance-Focused Rule

```yaml
rule_id: CUSTOM-PII-001
title: "Unencrypted Storage of Personally Identifiable Information"
description: |
  Detects storage of PII (email, phone, address) in files without indication
  of encryption. PII must be encrypted at rest per PIPEDA and GDPR requirements.

severity: HIGH
category: compliance
cwe: CWE-311

compliance:
  - framework: PIPEDA
    requirement: "Principle 7 - Safeguards"
    description: "Personal information shall be protected by security safeguards appropriate to the sensitivity"

  - framework: GDPR
    requirement: "Article 32"
    description: "Security of processing"

detection:
  patterns:
    - pattern: '(email|phone|address|ssn|sin)\s*=\s*["\'][^"\']+["\']'
      description: "Hardcoded PII"
      confidence: 0.7

    - pattern: 'INSERT INTO (users|customers|contacts).*VALUES.*\('
      description: "Database insertion (check if PII fields are encrypted)"
      confidence: 0.4

scope:
  file_patterns:
    - "**/*.py"
    - "**/*.js"
    - "**/*.sql"
  languages:
    - python
    - javascript
    - sql

remediation:
  description: |
    Encrypt PII at rest using strong encryption (AES-256). Use application-level
    or database-level encryption.

  steps:
    - "Identify all PII fields in your data model"
    - "Implement encryption at rest using AES-256 or equivalent"
    - "Store encryption keys securely (key management system)"
    - "Encrypt before storing, decrypt only when needed"
    - "Implement access controls on encrypted data"

  code_examples:
    - language: python
      insecure: |
        # INSECURE - Storing PII in plaintext
        user = User(
            email=email,
            phone=phone,
            ssn=ssn
        )
        db.session.add(user)

      secure: |
        # SECURE - Encrypting PII before storage
        from cryptography.fernet import Fernet

        encryption_key = get_encryption_key()
        cipher = Fernet(encryption_key)

        user = User(
            email=cipher.encrypt(email.encode()),
            phone=cipher.encrypt(phone.encode()),
            ssn=cipher.encrypt(ssn.encode())
        )
        db.session.add(user)

references:
  - "https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/"

created: 2024-01-15
version: "1.0.0"
status: active
```

## Testing Custom Rules

### Manual Testing

Test rules on sample code to verify they work correctly:

```bash
# Create test file
cat > test_rule.py << 'EOF'
# This should trigger the rule
password = "hardcoded_password"

# This should not trigger
password = os.environ.get('PASSWORD')
EOF

# Run security review on test file
claude code security-review --path test_rule.py --verbose
```

### Automated Testing with Test Cases

Include test cases in your rule definition:

```yaml
test_cases:
  - should_trigger: true
    code: |
      api_key = "AKIAIOSFODNN7EXAMPLE"
    description: "Hardcoded AWS key should be detected"

  - should_trigger: false
    code: |
      api_key = os.environ.get('AWS_ACCESS_KEY_ID')
    description: "Environment variable should not trigger"
```

### Iterative Refinement

1. **Run on small sample**: Test rule on a few files
2. **Review findings**: Check for false positives and false negatives
3. **Adjust patterns**: Refine detection patterns based on results
4. **Adjust confidence**: Lower confidence if many false positives
5. **Add false positive indicators**: Handle known false positive patterns
6. **Expand testing**: Run on larger codebase
7. **Monitor in production**: Track findings over time

## Common Pitfalls and Solutions

### Pitfall 1: Overly Broad Patterns

**Problem**: Pattern matches too much, many false positives

**Example**: `password` matches "password_reset_token", "password_policy", etc.

**Solution**: Make patterns more specific

```yaml
# Too broad
- pattern: 'password'

# Better - looks for assignment
- pattern: 'password\s*=\s*["\'][^"\']+["\']'

# Even better - excludes common false positives
- pattern: 'password\s*=\s*["\'][^"\']{6,}["\']'
  false_positive_indicators:
    - pattern: 'password_(reset|policy|strength|length|reset_token)'
      description: "Password-related variables that aren't credentials"
```

### Pitfall 2: Missing Context

**Problem**: Rule flags code that's actually safe due to other controls

**Solution**: Consider code context, add false positive indicators

```yaml
# Rule: Flag SQL queries with user input
# Problem: Misses parameterized queries, flags safe code

# Better approach:
detection:
  patterns:
    # Flag string concatenation/formatting
    - pattern: 'cursor\.execute\([^)]*\+[^)]*\)'
      description: "SQL with string concatenation"
    - pattern: 'cursor\.execute\([^)]*%s[^)]*%'
      description: "SQL with % formatting"

false_positive_indicators:
  # Don't flag parameterized queries
  - pattern: 'cursor\.execute\([^,]+,\s*\([^)]+\)\s*\)'
    description: "Parameterized query with tuple"
```

### Pitfall 3: Language-Specific Patterns

**Problem**: Pattern written for one language used across multiple languages

**Solution**: Specify language or create language-specific patterns

```yaml
detection:
  patterns:
    # Python-specific
    - pattern: 'os\.system\('
      language: python
      confidence: 0.9

    # JavaScript-specific
    - pattern: 'child_process\.exec\('
      language: javascript
      confidence: 0.9
```

### Pitfall 4: Hardcoded Paths

**Problem**: Rule assumes specific file structure

**Solution**: Use flexible patterns

```yaml
# Bad - assumes specific path
scope:
  file_patterns:
    - "src/api/routes/*.py"

# Good - flexible pattern
scope:
  file_patterns:
    - "**/api/**/*.py"
    - "**/routes/**/*.py"
```

## Best Practices Summary

1. **Start Simple**: Begin with clear, specific rules before adding complexity
2. **Test Thoroughly**: Use test cases and real code samples
3. **Be Specific**: Narrow scopes prevent false positives and improve performance
4. **Provide Context**: Explain why rules exist and why violations matter
5. **Actionable Remediation**: Give developers clear steps to fix issues
6. **Include Examples**: Code examples are the most valuable part of remediation
7. **Map to Standards**: Link to CWE, OWASP, compliance frameworks
8. **Handle False Positives**: Anticipate and handle known false positive patterns
9. **Document Everything**: Future you will thank present you
10. **Version Control**: Track rule changes like code

## Getting Help

- Review example rules in `rules/examples/`
- Check built-in rules in `rules/built-in-rules.yml` for patterns
- Test rules incrementally on small code samples
- Use `--verbose` flag to see rule loading and matching details
- Check agent logs for rule parsing errors

## Next Steps

1. Study the example rules in `rules/examples/`
2. Identify security requirements specific to your organization
3. Create simple rules for your most critical security policies
4. Test rules on sample code
5. Deploy rules and monitor findings
6. Refine based on false positives/negatives
7. Share effective rules with your team

Custom rules make the Security Code Review Agent truly yours. Start small, iterate, and build a comprehensive set of rules that protect your unique codebase.
