# Archived YAML Rules - Historical Reference Only

## ⚠️ DO NOT USE THESE FILES FOR NEW RULES

This directory contains **archived YAML-based security rules** from CodeGuardian v1.x. These files are preserved for
historical reference only.

**As of CodeGuardian v2.0.0 (2024-10-24), all security rules use markdown format.**

## Why These Files Are Archived

CodeGuardian migrated from YAML pattern-matching rules to markdown-based natural language rules because:

- **Better for Claude agents**: Natural language is easier for AI to understand contextually
- **Reduced false positives**: Context-aware detection vs rigid regex patterns
- **Easier to maintain**: Human-readable format without regex expertise required
- **Educational value**: Rules serve as security documentation
- **Adaptive detection**: Can understand semantic equivalence across coding styles

For details on the migration, see: `../MARKDOWN-RULES-MIGRATION.md`

## Contents of This Archive

### Built-in Rules (YAML format - v1.x)

- **`built-in-rules.yml`** - Final version of YAML rules before migration
- **`built-in-rules-comprehensive.yml`** - Enhanced YAML rules (never released)
- **`built-in-rules-backup.yml`** - Original backup of YAML rules

These are **replaced by** the 25 markdown rules in `rules/rules/codeguard-*.md`

### Custom Rule Examples (YAML format - v1.x)

- **`custom-aws-credentials.yml`** - AWS credentials detection (YAML)
- **`custom-api-rate-limiting.yml`** - API rate limiting detection (YAML)
- **`custom-database-security.yml`** - Database security patterns (YAML)
- **`custom-logging-security.yml`** - Logging security controls (YAML)

These are **replaced by**:

- Markdown example: `rules/examples/custom-aws-credentials.md`
- Markdown template: `rules/examples/README.md`

### Documentation

- **`YAML-INTEGRATION-HISTORICAL.md`** - Documentation of YAML integration effort (historical reference)

## Using Current Markdown Rules

### For New Custom Rules

**DO NOT** copy these YAML files. Instead, use the markdown format:

```bash
# See the markdown example
cat rules/examples/custom-aws-credentials.md

# Read the guide
cat rules/examples/README.md

# Quick start
cat QUICKSTART.md
```

### Markdown Rule Template

```markdown
---
description: What this rule checks
languages:
  - python
  - javascript
alwaysApply: false
severity: HIGH
---

# Rule Title

## Critical Principle

Core security principle.

## Detection Patterns

**INSECURE:**
```python
# Vulnerable code
```

**SECURE:**

```python
# Secure alternative
```

## Remediation

Fix instructions.

```

## Migration Path

If you have existing YAML custom rules:

1. **Review**: `../MARKDOWN-RULES-MIGRATION.md` for migration guidance
2. **Template**: Use `rules/examples/README.md` for markdown template
3. **Example**: Study `rules/examples/custom-aws-credentials.md`
4. **Convert**: Transform regex patterns to natural language descriptions
5. **Test**: Verify converted rules with `claude code security-review --verbose`

## Why Keep These Files?

These files are preserved to:

1. **Historical reference**: Document the evolution of CodeGuardian
2. **Pattern reference**: YAML regex patterns can inform markdown descriptions
3. **Migration aid**: Help users convert existing YAML rules to markdown
4. **Comparison**: Show the difference between approaches

## File Organization

```

archive/yaml-rules/
├── README.md (this file)
├── built-in-rules.yml (v1.x built-in rules)
├── built-in-rules-comprehensive.yml (unreleased enhanced version)
├── built-in-rules-backup.yml (original backup)
├── custom-aws-credentials.yml (example - YAML)
├── custom-api-rate-limiting.yml (example - YAML)
├── custom-database-security.yml (example - YAML)
├── custom-logging-security.yml (example - YAML)
└── YAML-INTEGRATION-HISTORICAL.md (integration documentation)

```

## Current Active Files

The **current, actively used** files are:

### Built-in Rules (Markdown)
```

rules/rules/
├── codeguard-0-*.md (17 foundational rules)
├── codeguard-1-*.md (5 specific rules)
└── codeguard-2-*.md (3 comprehensive rules)

```

### Custom Rule Examples (Markdown)
```

rules/examples/
├── custom-aws-credentials.md (markdown example)
└── README.md (template and guide)

```

### Documentation
```

/
├── README.md (main documentation)
├── QUICKSTART.md (quick start guide)
├── MARKDOWN-RULES-MIGRATION.md (migration details)
├── CLAUDE.md (Claude Code guidance)
└── rules/RULES-INDEX.md (complete rule catalog)

```

## Questions?

- **Creating new rules**: See `rules/examples/README.md`
- **Migration from YAML**: See `../MARKDOWN-RULES-MIGRATION.md`
- **Quick start**: See `../QUICKSTART.md`
- **Full documentation**: See `../README.md`

---

**Archive Date**: 2024-10-24
**Archived Version**: 1.x (YAML-based rules)
**Current Version**: 2.0.0 (Markdown-based rules)
**Status**: Historical reference only - DO NOT USE for new rules
