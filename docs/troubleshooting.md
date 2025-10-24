# Troubleshooting Guide

## Common Issues and Solutions

### Configuration Issues

#### Agent Not Finding Configuration File

**Symptoms**:
- Agent runs with default configuration
- Custom settings not applied

**Causes**:
- Configuration file not in project root
- Wrong filename or extension

**Solutions**:
1. Ensure `.code-review-config.yml` is in project root directory (where you run the command)
2. Check filename spelling: must be `.code-review-config.yml` (starts with dot)
3. Verify YAML syntax: use a YAML validator
4. Run with `--verbose` to see config loading messages

**Verify**:
```bash
ls -la .code-review-config.yml  # Should show the file
```

#### Custom Rules Not Loading

**Symptoms**:
- Custom rules don't appear in report appendix
- Expected violations not found

**Causes**:
- Wrong rules directory path
- Invalid markdown frontmatter syntax in rules
- Missing `.md` file extension
- Rules excluded by language scope

**Solutions**:
1. Verify `custom_rules_dir` in configuration points to correct directory
2. Check that custom rule files have `.md` extension
3. Validate markdown frontmatter syntax (YAML format between `---` markers)
4. Ensure `languages` in frontmatter match target file types
5. Run with `--verbose` to see rule loading messages
6. Use `--list-rules` to see loaded rules

**Debug**:
```bash
# Check rule files exist
ls -la security-rules/*.md

# Check directory path
cat .code-review-config.yml | grep custom_rules_dir

# See loaded rules
claude code security-review --list-rules

# Run with verbose to see loading messages
claude code security-review --verbose
```

#### Invalid Rule Frontmatter

**Symptoms**:
- Error messages about rule parsing
- Custom rules not loaded

**Solutions**:
1. Ensure frontmatter is surrounded by `---` markers
2. Check YAML syntax within frontmatter (indentation, colons, lists)
3. Verify required fields: `description`, `languages`, `alwaysApply`, `severity`
4. Use proper list format for languages

**Common Frontmatter Mistakes**:
```markdown
# WRONG - no closing ---
---
description: My rule
languages:
  - python

# CORRECT - proper YAML frontmatter
---
description: My rule
languages:
  - python
alwaysApply: false
severity: HIGH
---

# WRONG - tabs for indentation
---
description: My rule
languages:
	- python
---

# CORRECT - spaces for indentation
---
description: My rule
languages:
  - python
---

# WRONG - missing required fields
---
description: My rule
---

# CORRECT - all required fields
---
description: My rule
languages:
  - python
alwaysApply: false
severity: HIGH
---
```

### Performance Issues

#### Slow Analysis of Large Codebases

**Symptoms**:
- Analysis takes very long time
- High memory usage
- Timeouts

**Solutions**:
1. Use `--quick` mode for faster analysis:
   ```bash
   claude code security-review --quick
   ```

2. Narrow scope with more specific include patterns:
   ```yaml
   scope:
     include:
       - "src/**/*.py"  # Specific directory
     exclude:
       - "**/test/**"   # Exclude test files
       - "**/vendor/**" # Exclude dependencies
   ```

3. Analyze specific paths instead of entire project:
   ```bash
   claude code security-review --path src/api
   ```

4. Increase performance settings:
   ```yaml
   performance:
     max_parallel_files: 8      # More parallelism
     file_timeout: 600          # Longer timeout
     max_memory: 4096           # More memory
   ```

5. Split analysis into multiple runs for different directories

#### Memory Usage Problems

**Symptoms**:
- Out of memory errors
- System slowdown during analysis

**Solutions**:
1. Reduce `max_parallel_files` in configuration
2. Exclude large binary files and dependencies
3. Analyze smaller portions of codebase separately
4. Increase system swap space
5. Run on machine with more RAM

#### Timeout Errors

**Symptoms**:
- Analysis stops with timeout error
- Incomplete reports

**Solutions**:
1. Increase timeout settings:
   ```yaml
   performance:
     file_timeout: 900  # 15 minutes per file
   ```

2. Use `--quick` mode
3. Narrow scope to exclude problematic files
4. Check for infinite loops in analysis rules

### False Positives

#### Too Many False Positive Findings

**Symptoms**:
- Many findings that aren't real security issues
- Findings in test code or examples

**Solutions**:
1. Add false positive indicators to custom rules:
   ```yaml
   false_positive_indicators:
     - pattern: 'test|example|mock'
       description: "Test or example code"
   ```

2. Use suppression comments in code:
   ```python
   # nosec: hardcoded-credential
   EXAMPLE_KEY = "example_key_for_documentation"
   ```

3. Exclude test directories:
   ```yaml
   scope:
     exclude:
       - "**/test/**"
       - "**/tests/**"
       - "**/*.test.*"
   ```

4. Adjust rule confidence levels in custom rules
5. Report persistent false positives for rule improvement

#### Suppressing Specific Findings

**Method 1 - Inline Suppression**:
```python
# nosec: rule-name
dangerous_but_safe_code()
```

**Method 2 - Block Suppression**:
```python
# nosec: start
multiple_lines()
of_code_to_suppress()
# nosec: end
```

**Method 3 - File Exclusion**:
```yaml
scope:
  exclude:
    - "path/to/file.py"
```

### Report Issues

#### Reports Not Generating

**Symptoms**:
- Analysis completes but no report file
- Incomplete reports

**Solutions**:
1. Check disk space and write permissions:
   ```bash
   df -h .                    # Check disk space
   ls -ld security-reports/   # Check permissions
   ```

2. Verify output directory in configuration:
   ```yaml
   reporting:
     output_dir: "security-reports"  # Must be writable
   ```

3. Check for special characters in file paths
4. Run with `--verbose` to see detailed error messages
5. Check agent logs for errors

#### Incorrect Vulnerability Status Tracking

**Symptoms**:
- Previous vulnerabilities not found
- Wrong status (fixed vs not fixed)

**Solutions**:
1. Ensure previous report exists in output directory
2. Check that file paths in previous report are still valid
3. Verify code hasn't moved to different files/lines
4. Previous report must be in same output directory

#### Missing Compliance Sections

**Symptoms**:
- Expected compliance framework sections missing from report
- "N/A" for all compliance requirements

**Solutions**:
1. Enable frameworks in configuration:
   ```yaml
   compliance:
     pci_dss:
       enabled: true
     soc2:
       enabled: true
   ```

2. Verify framework names are correct (case-sensitive)
3. Check that codebase contains relevant code (e.g., payment processing for PCI DSS)

### Integration Problems

#### Pre-Commit Hook Failures

**Symptoms**:
- Commits blocked unexpectedly
- Hook errors

**Solutions**:
1. Make hook executable:
   ```bash
   chmod +x .git/hooks/pre-commit
   ```

2. Use `--quick` mode in pre-commit hooks
3. Add proper error handling in hook script
4. Test hook standalone before using:
   ```bash
   .git/hooks/pre-commit
   ```

5. Temporarily bypass hook for testing:
   ```bash
   git commit --no-verify -m "message"
   ```

#### CI Pipeline Failures

**Symptoms**:
- Pipeline fails on security review step
- Inconsistent CI results

**Solutions**:
1. Verify agent is installed in CI environment
2. Check CI environment has access to configuration file
3. Ensure sufficient CI runner resources (memory, timeout)
4. Use `--quick` mode for CI to reduce runtime
5. Set appropriate failure thresholds:
   ```yaml
   thresholds:
     max_critical: 0
     max_high: 5
   ```

6. Check CI logs with `--verbose` flag

#### Webhook Notification Failures

**Symptoms**:
- Notifications not sent
- Webhook errors

**Solutions**:
1. Verify webhook URL is correct
2. Check network connectivity from CI to webhook endpoint
3. Validate webhook authentication/secrets
4. Test webhook manually with curl:
   ```bash
   curl -X POST webhook_url -H "Content-Type: application/json" -d '{"test": "message"}'
   ```

5. Check webhook endpoint logs for errors

### Analysis Issues

#### No Findings When Vulnerabilities Exist

**Symptoms**:
- Known vulnerabilities not detected
- Empty or minimal reports

**Causes**:
- Files not in scope
- Rules not matching code patterns
- Overly specific scope patterns

**Solutions**:
1. Verify files are in scope:
   ```bash
   claude code security-review --verbose  # Shows files analyzed
   ```

2. Check include/exclude patterns in configuration
3. Test custom rules on sample code
4. Ensure rule patterns match code style
5. Check if rules are disabled or have wrong severity

#### Analysis Hangs or Freezes

**Symptoms**:
- Analysis never completes
- Process hangs indefinitely

**Solutions**:
1. Set file timeout in configuration
2. Identify problematic file with `--verbose`
3. Exclude hanging file temporarily
4. Check for very large files (>10K lines)
5. Kill and restart with narrower scope

### Agent Crashes

#### Out of Memory Crashes

**Solutions**:
1. Reduce `max_parallel_files`
2. Increase system memory
3. Add swap space
4. Analyze in smaller batches

#### Segmentation Faults

**Solutions**:
1. Update agent to latest version
2. Check for corrupt configuration files
3. Verify rule syntax
4. Report bug with minimal reproduction case

## Getting Additional Help

### Before Requesting Help

Gather this information:

1. Agent version: `claude code --version`
2. Configuration file content (redact secrets)
3. Command used to invoke agent
4. Complete error message or unexpected behavior
5. Relevant section of `--verbose` output
6. Environment: OS, Python/Node version, available memory

### Debug Mode

Run with maximum verbosity:
```bash
claude code security-review --verbose --debug
```

### Log Files

Check agent logs:
```bash
tail -f security-review.log
```

### Support Channels

1. Review documentation in `docs/` directory
2. Check example configurations in `examples/`
3. Search existing GitHub issues
4. Create new issue with reproduction steps

## Quick Reference

### Performance Optimization Checklist

- [ ] Use `--quick` mode for faster analysis
- [ ] Narrow scope with specific include patterns
- [ ] Exclude test files and dependencies
- [ ] Increase `max_parallel_files` for multi-core systems
- [ ] Analyze specific paths instead of entire project
- [ ] Set appropriate timeouts

### False Positive Reduction Checklist

- [ ] Add false positive indicators to rules
- [ ] Use suppression comments for legitimate cases
- [ ] Exclude test directories from scope
- [ ] Adjust rule confidence levels
- [ ] Review and refine custom rules regularly

### Integration Debugging Checklist

- [ ] Verify agent installation in target environment
- [ ] Check configuration file is accessible
- [ ] Test command locally before CI integration
- [ ] Use appropriate timeouts for CI environment
- [ ] Set failure thresholds appropriately
- [ ] Add proper error handling

## Prevention Tips

1. **Test Changes Locally First**: Always test configuration or rule changes locally before CI
2. **Use Version Control**: Track changes to configuration and custom rules
3. **Document Suppressions**: Add comments explaining why findings are suppressed
4. **Monitor Performance**: Track analysis time and adjust settings as needed
5. **Regular Maintenance**: Periodically review and update custom rules
6. **Incremental Integration**: Start simple, add complexity gradually
7. **Team Communication**: Share configuration changes with team

---

*Still having issues? Check the documentation in `docs/` or create an issue with full details.*
