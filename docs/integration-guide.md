# Integration Guide

## Overview

This guide shows how to integrate the Security Code Review Agent into your development workflows for continuous security analysis.

## Pre-Commit Hooks

### Git Pre-Commit Hook

Run quick security scans before committing:

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "🔒 Running security code review..."

# Run quick scan on changed files only
claude code security-review --quick --diff

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ Security issues found. Commit blocked."
    echo "📄 Review the findings or use --no-verify to skip (not recommended)"
    exit 1
fi

echo "✅ Security check passed"
exit 0
```

Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

### Team-Wide Hook with Husky (JavaScript/Node.js)

```bash
npm install --save-dev husky
npx husky install
npx husky add .husky/pre-commit "claude code security-review --quick --diff"
```

## Continuous Integration

### GitHub Actions

```yaml
# .github/workflows/security-review.yml
name: Security Code Review

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-review:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for better analysis

      - name: Run Security Code Review
        run: |
          claude code security-review --verbose
        continue-on-error: false

      - name: Upload Security Report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-report
          path: security-reports/latest-report.md
          retention-days: 90

      - name: Comment PR with Summary
        if: github.event_name == 'pull_request' && failure()
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('security-reports/latest-report.md', 'utf8');

            // Extract executive summary
            const summary = report.split('## Executive Summary')[1]?.split('##')[0] || 'See full report';

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🔒 Security Review Results\n\n${summary}\n\n📄 Full report available in job artifacts`
            });
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - test
  - security

security-review:
  stage: security
  script:
    - claude code security-review --verbose
  artifacts:
    when: always
    paths:
      - security-reports/
    expire_in: 90 days
  allow_failure: false  # Block pipeline on security issues
  only:
    - merge_requests
    - main
    - develop
```

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any

    triggers {
        // Run nightly
        cron('H 2 * * *')
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Security Review') {
            steps {
                sh 'claude code security-review --full --verbose'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'security-reports/**/*.md',
                            allowEmptyArchive: true
        }

        failure {
            emailext(
                subject: "🔒 Security Issues Found: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: readFile('security-reports/latest-report.md'),
                to: 'security-team@example.com',
                attachLog: true
            )
        }

        success {
            emailext(
                subject: "✅ Security Review Passed: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: "Security code review completed with no critical issues.",
                to: 'dev-team@example.com'
            )
        }
    }
}
```

### CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-review:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Run Security Code Review
          command: claude code security-review --verbose
      - store_artifacts:
          path: security-reports/
          destination: security-reports

workflows:
  security-checks:
    jobs:
      - security-review
```

## Scheduled Reviews

### Cron Job for Nightly Reviews

```bash
# Add to crontab: crontab -e
0 2 * * * cd /path/to/project && claude code security-review --full > /var/log/security-review.log 2>&1
```

### Systemd Timer (Linux)

```ini
# /etc/systemd/system/security-review.timer
[Unit]
Description=Nightly Security Code Review
Requires=security-review.service

[Timer]
OnCalendar=daily
OnCalendar=02:00
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/security-review.service
[Unit]
Description=Security Code Review Service

[Service]
Type=oneshot
User=developer
WorkingDirectory=/path/to/project
ExecStart=/usr/local/bin/claude code security-review --full
StandardOutput=append:/var/log/security-review.log
StandardError=append:/var/log/security-review.log
```

Enable:
```bash
sudo systemctl enable security-review.timer
sudo systemctl start security-review.timer
```

## Issue Tracker Integration

### GitHub Issues

```python
# scripts/create-github-issues.py
import os
import re
import requests
from github import Github

def parse_report(report_path):
    """Extract vulnerabilities from report."""
    with open(report_path) as f:
        content = f.read()

    vulnerabilities = []
    # Parse vulnerability sections
    # (Implementation depends on report format)
    return vulnerabilities

def create_issues(vulnerabilities, repo):
    """Create GitHub issues for vulnerabilities."""
    for vuln in vulnerabilities:
        if vuln['severity'] in ['CRITICAL', 'HIGH']:
            issue = repo.create_issue(
                title=f"🔒 [{vuln['severity']}] {vuln['title']}",
                body=f"""
## Vulnerability Details

**Severity**: {vuln['severity']}
**Location**: {vuln['location']}

{vuln['description']}

## Remediation

{vuln['remediation']}
                """,
                labels=['security', vuln['severity'].lower()]
            )
            print(f"Created issue #{issue.number}: {vuln['title']}")

if __name__ == '__main__':
    g = Github(os.environ['GITHUB_TOKEN'])
    repo = g.get_repo(os.environ['GITHUB_REPOSITORY'])

    vulnerabilities = parse_report('security-reports/latest-report.md')
    create_issues(vulnerabilities, repo)
```

### Jira Integration

```python
# scripts/create-jira-tickets.py
from jira import JIRA
import os

jira = JIRA(
    server=os.environ['JIRA_URL'],
    basic_auth=(os.environ['JIRA_USER'], os.environ['JIRA_API_TOKEN'])
)

def create_security_ticket(vulnerability):
    """Create Jira ticket for security vulnerability."""
    issue_dict = {
        'project': {'key': 'SEC'},
        'summary': f"[{vulnerability['severity']}] {vulnerability['title']}",
        'description': vulnerability['description'],
        'issuetype': {'name': 'Security Issue'},
        'priority': {'name': vulnerability['severity']},
        'labels': ['security', 'automated']
    }

    issue = jira.create_issue(fields=issue_dict)
    print(f"Created {issue.key}: {vulnerability['title']}")
    return issue

# Parse report and create tickets
# (Implementation depends on report format)
```

## Notification Systems

### Slack Notifications

```python
# scripts/notify-slack.py
import os
import requests
import json

def send_slack_notification(report_summary):
    """Send security report summary to Slack."""
    webhook_url = os.environ['SLACK_WEBHOOK_URL']

    severity_emoji = {
        'CRITICAL': ':rotating_light:',
        'HIGH': ':warning:',
        'MEDIUM': ':information_source:',
        'LOW': ':white_check_mark:'
    }

    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔒 Security Code Review Complete"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Critical:* {report_summary['critical']}"},
                    {"type": "mrkdwn", "text": f"*High:* {report_summary['high']}"},
                    {"type": "mrkdwn", "text": f"*Medium:* {report_summary['medium']}"},
                    {"type": "mrkdwn", "text": f"*Low:* {report_summary['low']}"}
                ]
            }
        ]
    }

    response = requests.post(webhook_url, json=message)
    return response.status_code == 200

# Parse report and send notification
```

### Microsoft Teams

```python
# scripts/notify-teams.py
import os
import requests

def send_teams_notification(report_summary):
    """Send security report summary to Microsoft Teams."""
    webhook_url = os.environ['TEAMS_WEBHOOK_URL']

    message = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": "Security Code Review Complete",
        "themeColor": "FF0000" if report_summary['critical'] > 0 else "00FF00",
        "title": "🔒 Security Code Review Results",
        "sections": [
            {
                "facts": [
                    {"name": "Critical", "value": str(report_summary['critical'])},
                    {"name": "High", "value": str(report_summary['high'])},
                    {"name": "Medium", "value": str(report_summary['medium'])},
                    {"name": "Low", "value": str(report_summary['low'])}
                ]
            }
        ]
    }

    response = requests.post(webhook_url, json=message)
    return response.status_code == 200
```

## Deployment Gates

### Block Deployments on Security Issues

```bash
# deploy.sh
#!/bin/bash

echo "Running security review before deployment..."

claude code security-review

EXIT_CODE=$?

if [ $EXIT_CODE -eq 1 ]; then
    echo "❌ DEPLOYMENT BLOCKED: Critical security issues found"
    echo "📄 Review security-reports/latest-report.md"
    exit 1
elif [ $EXIT_CODE -eq 2 ]; then
    echo "⚠️  WARNING: High severity security issues found"
    echo "Consider fixing before deploying"
    # Allow deployment but warn
fi

echo "✅ Security check passed, proceeding with deployment"
# Continue with deployment...
```

## Best Practices

1. **Start with Pre-Commit Hooks**: Catch issues early in local development

2. **Run on Every Pull Request**: Prevent insecure code from being merged

3. **Daily Comprehensive Scans**: Catch issues that develop over time

4. **Automate Issue Creation**: Ensure findings are tracked and addressed

5. **Notify Security Team**: Alert on critical findings immediately

6. **Gate Production Deployments**: Block deployments with critical issues

7. **Track Metrics Over Time**: Monitor security posture trends

8. **Customize Thresholds**: Adjust severity thresholds for your risk tolerance

9. **Maintain Exemptions**: Document and track security exceptions

10. **Regular Review**: Periodically review integration effectiveness

## Troubleshooting Integration

**Problem**: Pre-commit hook slows down commits
**Solution**: Use `--quick` mode for pre-commit, full scans in CI

**Problem**: CI pipeline times out
**Solution**: Increase timeout, use `--quick` mode, or narrow scope

**Problem**: Too many false positives
**Solution**: Tune rules, add suppression comments, adjust confidence levels

**Problem**: Notifications overwhelming team
**Solution**: Filter notifications by severity, adjust thresholds

## Next Steps

1. Choose integration points appropriate for your workflow
2. Start with pre-commit hooks for immediate feedback
3. Add CI/CD integration for team-wide enforcement
4. Implement scheduled comprehensive reviews
5. Add notification systems for critical findings
6. Monitor and refine integration based on team feedback
