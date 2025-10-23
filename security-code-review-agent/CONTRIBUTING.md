# Contributing to Security Code Review Agent

Thank you for your interest in contributing to the Security Code Review Agent! This document provides guidelines for contributions.

## Ways to Contribute

### 1. Report Bugs

If you find a bug, please create an issue with:

- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Agent version and environment details
- Relevant configuration (redact secrets)
- Sample code that triggers the issue (if applicable)

### 2. Suggest Features

Feature requests are welcome! Please include:

- Clear description of the feature
- Use case and motivation
- Proposed implementation approach (if you have ideas)
- Impact on existing functionality

### 3. Contribute Built-in Rules

Share security rules that could benefit everyone:

- Rule must be well-tested
- Include comprehensive remediation guidance
- Provide code examples for multiple languages where applicable
- Include test cases
- Ensure rule is generally applicable, not organization-specific

### 4. Share Custom Rules

Share organization-specific rules that others might adapt:

- Document the specific security concern addressed
- Provide clear configuration examples
- Explain when the rule should be used
- Include test cases

### 5. Improve Documentation

Help make documentation clearer:

- Fix typos and grammatical errors
- Add examples and clarifications
- Improve organization and structure
- Translate documentation (if applicable)
- Add troubleshooting scenarios

### 6. Code Contributions

For code changes:

- Discuss major changes in an issue first
- Follow existing code style
- Add tests for new functionality
- Update documentation
- Ensure all tests pass

## Development Setup

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/your-username/security-code-review-agent.git
   cd security-code-review-agent
   ```

2. **Create a branch for your changes**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**:
   - Edit files as needed
   - Test thoroughly
   - Update documentation

4. **Test your changes**:
   ```bash
   # Test on sample vulnerable code
   claude code security-review --path examples/sample-vulnerable-code/
   ```

5. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Clear description of changes"
   ```

6. **Push and create pull request**:
   ```bash
   git push origin feature/your-feature-name
   ```

## Pull Request Guidelines

### Before Submitting

- [ ] Test changes thoroughly
- [ ] Update documentation
- [ ] Add examples if applicable
- [ ] Ensure no sensitive data in commits
- [ ] Write clear commit messages

### PR Description Should Include

- What: Clear description of what changed
- Why: Motivation for the change
- How: Brief explanation of the approach
- Testing: How you tested the changes
- Impact: Any breaking changes or migration needed

### Review Process

1. Maintainers will review your PR
2. Address feedback and requested changes
3. Once approved, maintainers will merge

## Code Style Guidelines

### YAML Files (Rules and Configuration)

- Use 2 spaces for indentation
- Add comments explaining complex patterns
- Use clear, descriptive field names
- Follow the established rule format

### Markdown Documentation

- Use clear headings and structure
- Include code examples
- Add links to related documentation
- Keep lines under 100 characters where practical

### Example Code

- Comment insecure code as "INSECURE" with explanation
- Comment secure code as "SECURE" with explanation
- Make examples realistic and practical
- Include multiple languages where applicable

## Rule Contribution Guidelines

### Built-in Rules

Built-in rules should be:

- **Generally Applicable**: Relevant to most codebases
- **Well-Documented**: Clear description, remediation, examples
- **Tested**: Include test cases for positive and negative scenarios
- **Standard-Mapped**: Reference CWE, OWASP, compliance frameworks
- **Low False Positives**: Tuned to minimize false positives

### Custom Rule Examples

Custom rule examples should:

- Demonstrate specific use cases
- Be well-commented and explained
- Include comprehensive remediation guidance
- Show organization-specific or advanced patterns

## Documentation Contributions

Documentation is crucial! When updating docs:

- Use clear, simple language
- Provide examples and code snippets
- Link to related documentation
- Test all commands and code examples
- Update table of contents if needed

## Commit Message Guidelines

Write clear commit messages:

```
Brief summary of change (50 chars or less)

More detailed explanation if needed:
- What changed
- Why it changed
- Any breaking changes

Closes #123 (if fixing an issue)
```

## Testing

### Testing Rules

Test rules on sample code:

```bash
# Create test file
cat > test.py << 'EOF'
# Code that should trigger rule
password = "hardcoded_password"
EOF

# Run security review
claude code security-review --path test.py --verbose

# Verify rule triggers correctly
```

### Testing Custom Rules

Include test cases in rule definitions:

```yaml
test_cases:
  - should_trigger: true
    code: |
      # Code that should trigger
    description: "Positive test case"

  - should_trigger: false
    code: |
      # Code that should not trigger
    description: "Negative test case"
```

## Issue Labels

- `bug`: Something isn't working
- `enhancement`: New feature or improvement
- `documentation`: Documentation improvements
- `good first issue`: Good for newcomers
- `help wanted`: Community help appreciated
- `question`: Question about usage
- `rule`: Related to security rules
- `compliance`: Related to compliance checking

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Welcome newcomers
- Accept constructive criticism
- Focus on what's best for the community
- Show empathy towards others

### Unacceptable Behavior

- Harassment or discriminatory language
- Personal attacks
- Publishing others' private information
- Other conduct inappropriate in a professional setting

## Questions?

- Review existing documentation
- Search existing issues
- Create a new issue with your question

## Recognition

Contributors will be recognized in:

- README.md contributors section
- Release notes for significant contributions
- Special thanks for major features

---

Thank you for contributing to making software more secure!
