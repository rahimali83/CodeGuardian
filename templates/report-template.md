# Security Code Review Report

## Report Header

**Project Name**: [Project Name]
**Review Date**: [YYYY-MM-DD HH:MM:SS UTC]
**Agent Version**: 1.0.0
**Reviewer**: Claude Code Security Agent
**Report ID**: [Unique identifier: REPORT-YYYYMMDD-HHMMSS]

---

## Executive Summary

### Scope of Analysis

- **Files Analyzed**: [Number] files
- **Lines of Code**: [Number] LOC
- **Languages**: [List of programming languages]
- **Analysis Duration**: [Time taken]

### Overall Security Rating

**Rating**: [CRITICAL | HIGH RISK | MODERATE RISK | LOW RISK | GOOD]

### Findings Summary

| Severity      | Count   | Status                   |
|---------------|---------|--------------------------|
| Critical      | [N]     | [% Change from previous] |
| High          | [N]     | [% Change from previous] |
| Medium        | [N]     | [% Change from previous] |
| Low           | [N]     | [% Change from previous] |
| Informational | [N]     | [% Change from previous] |
| **Total**     | **[N]** | **[Net change]**         |

### Compliance Status

| Framework | Status                                      | Critical Issues | Notes        |
|-----------|---------------------------------------------|-----------------|--------------|
| PCI DSS   | [COMPLIANT / NON-COMPLIANT / PARTIAL / N/A] | [N]             | [Brief note] |
| SOC 2     | [COMPLIANT / NON-COMPLIANT / PARTIAL / N/A] | [N]             | [Brief note] |
| PIPEDA    | [COMPLIANT / NON-COMPLIANT / PARTIAL / N/A] | [N]             | [Brief note] |
| CCPA      | [COMPLIANT / NON-COMPLIANT / PARTIAL / N/A] | [N]             | [Brief note] |
| HIPAA     | [COMPLIANT / NON-COMPLIANT / PARTIAL / N/A] | [N]             | [Brief note] |
| NIST CSF  | [COMPLIANT / NON-COMPLIANT / PARTIAL / N/A] | [N]             | [Brief note] |

### Top Critical Issues

1. **[Issue Title]** - [Brief description and location]
2. **[Issue Title]** - [Brief description and location]
3. **[Issue Title]** - [Brief description and location]

### Remediation Priority Roadmap

**Immediate Action Required (24-48 hours)**:

- [Critical issue requiring immediate attention]
- [Critical issue requiring immediate attention]

**Short-Term (1-2 weeks)**:

- [High priority issues]
- [High priority issues]

**Medium-Term (1 month)**:

- [Medium priority issues]

**Long-Term (3 months)**:

- [Low priority and process improvements]

---

## Previous Vulnerability Status Update

### Remediation Summary

**Previous Report**: [Path to previous report or "No previous report found - this is the first security review"]
**Previous Report Date**: [YYYY-MM-DD or N/A]
**Total Previous Vulnerabilities**: [N or N/A]

**Status Breakdown**:

| Status             | Count | Percentage |
|--------------------|-------|------------|
| ✅ Fixed            | [N]   | [XX]%      |
| 🔄 Partially Fixed | [N]   | [XX]%      |
| ❌ Not Fixed        | [N]   | [XX]%      |
| ⚠️ Regressed       | [N]   | [XX]%      |
| 🗑️ Code Removed   | [N]   | [XX]%      |

### Detailed Vulnerability Tracking

*Note: If no previous report exists, this section will state: "This is the first security review of this codebase. No
previous vulnerabilities to track."*

---

#### [VULN-001] - [Previous Vulnerability Title]

**Current Status**: [✅ FIXED | 🔄 PARTIALLY FIXED | ❌ NOT FIXED | ⚠️ REGRESSED | 🗑️ CODE REMOVED]

**Original Finding**:

- **Severity**: [Critical/High/Medium/Low]
- **Category**: [Category]
- **Location**: [File path:line numbers]
- **Description**: [Original vulnerability description]

**Status Analysis**:

- **Days Open**: [N days since first reported]
- **Current Assessment**: [Detailed explanation of current status]
- **Code Changes**: [Description of what changed or didn't change]
- **Remediation Evidence**: [Specific code changes, commit references if available]

**Updated Severity**: [If not fixed or regressed, note any severity escalation based on duration]

**Recommendation**: [Next steps for this specific vulnerability]

---

*[Repeat above section for each previous vulnerability]*

---

## New Vulnerabilities Discovered

*This section contains all security issues, compliance violations, and code quality concerns discovered in the current
review that were not present in previous reports.*

---

### [VULN-NEW-001] [Vulnerability Title]

**Severity**: [CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL]
**Category**: [Security / Compliance / API Security / Code Quality]
**CWE**: [CWE-XXX: Description] *(if applicable)*
**Status**: NEW

**Compliance Impact**:

- [Framework Name]: [Requirement violated]
- [Framework Name]: [Requirement violated]

**Location**:

- **File**: [File path]
- **Lines**: [Line numbers]
- **Function/Method**: [Function or method name if applicable]

**Description**:

[Detailed description explaining what the issue is, why it exists, and what makes it exploitable. Include relevant context about the code's purpose and how the vulnerability manifests.]

**Risk Analysis**:

**Potential Impact**:

- Data at risk: [What data could be compromised]
- Access implications: [What access could be gained]
- Compliance penalties: [What compliance violations and potential penalties]
- Business impact: [What business operations could be affected]

**Exploitability**: [HIGH | MEDIUM | LOW]
[Explanation of how easy or difficult it is to exploit this vulnerability]

**Attack Vector**:

[Step-by-step description of how an attacker would exploit this vulnerability:]

1. [Step one of attack]
2. [Step two of attack]
3. [Step three of attack]
4. [Result of successful attack]

**Vulnerable Code**:

```[language]
[Actual vulnerable code snippet with line numbers]
```

**Proof of Concept** *(if applicable)*:

```[language]
[Demonstration of exploitation if relevant and safe to include]
```

**Recommended Remediation**:

[Specific, actionable steps to fix the vulnerability:]

1. [Remediation step one with specific technical guidance]
2. [Remediation step two with specific technical guidance]
3. [Remediation step three with specific technical guidance]

**Secure Code Example**:

```[language]
[Corrected, secure implementation of the code]
```

**Additional Recommendations**:

- [Additional security enhancement related to this vulnerability]
- [Defense in depth recommendation]

**References**:

- [Link to relevant CVE if applicable]
- [Link to CWE entry]
- [Link to OWASP documentation]
- [Link to compliance requirement documentation]
- [Link to secure coding guidelines]

---

*[Repeat above section for each new vulnerability]*

---

## Compliance Analysis Details

*This section provides detailed analysis of adherence to each enabled regulatory framework.*

---

### PCI DSS Compliance Analysis

**Overall Status**: [COMPLIANT | NON-COMPLIANT | PARTIAL COMPLIANCE]

**Summary**: [Brief overview of PCI DSS compliance status]

#### Requirement 3: Protect Stored Cardholder Data

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL | N/A]

**Analysis**:
[Detailed analysis of cardholder data protection including encryption at rest, key management, masking of PANs, and storage restrictions]

**Findings**:

- [Specific finding with file reference if applicable]
- [Specific finding with file reference if applicable]

**Files Reviewed**:

-

[File path]: [Observation]
-

[File path]: [Observation]

---

#### Requirement 4: Encrypt Transmission of Cardholder Data

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL | N/A]

**Analysis**:
[Detailed analysis of cardholder data transmission security including TLS implementation, protocol versions, cipher suites]

**Findings**:

- [Specific finding with file reference]
- [Specific finding with file reference]

**Files Reviewed**:

-

[File path]: [Observation]

---

#### Requirement 6: Develop and Maintain Secure Systems

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL | N/A]

**Analysis**:
[Analysis of secure development practices, vulnerability management, and separation of environments]

**Findings**:

- [Reference to security vulnerabilities found that violate this requirement]

---

#### Requirement 7: Restrict Access to Cardholder Data

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL | N/A]

**Analysis**:
[Analysis of access control implementation, least privilege, and need-to-know principles]

**Findings**:

- [Specific finding with file reference]

---

#### Requirement 8: Identify and Authenticate Access

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL | N/A]

**Analysis**:
[Analysis of authentication mechanisms, password policies, MFA implementation, unique user IDs]

**Findings**:

- [Specific finding with file reference]

---

#### Requirement 10: Track and Monitor All Access

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL | N/A]

**Analysis**:
[Analysis of audit logging, log protection, and monitoring capabilities]

**Findings**:

- [Specific finding with file reference]

---

### SOC 2 Compliance Analysis

**Overall Status**: [COMPLIANT | NON-COMPLIANT | PARTIAL COMPLIANCE]

**Summary**: [Brief overview of SOC 2 compliance status]

#### Security (Common Criteria)

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL]

**Analysis**:
[Analysis of security controls including access control, change management, monitoring, incident response]

**Findings**:

- [Specific finding]
- [Specific finding]

**Files Reviewed**:

-

[File path]: [Observation]

---

#### Availability

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL | N/A]

**Analysis**:
[Analysis of availability controls, monitoring, redundancy, disaster recovery]

**Findings**:

- [Specific finding]

---

#### Processing Integrity

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL | N/A]

**Analysis**:
[Analysis of data validation, error handling, transaction processing]

**Findings**:

- [Specific finding]

---

#### Confidentiality

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL | N/A]

**Analysis**:
[Analysis of confidential data protection, encryption, access controls]

**Findings**:

- [Specific finding]

---

#### Privacy

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL | N/A]

**Analysis**:
[Analysis of personal information handling, consent, data subject rights]

**Findings**:

- [Specific finding]

---

### PIPEDA Compliance Analysis (Canadian Privacy Law)

**Overall Status**: [COMPLIANT | NON-COMPLIANT | PARTIAL COMPLIANCE]

**Summary**: [Brief overview of PIPEDA compliance status]

#### Principle 1: Accountability

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL]

**Analysis**:
[Analysis of organizational accountability for personal information]

**Findings**:

- [Specific finding]

---

#### Principle 2: Identifying Purpose

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL]

**Analysis**:
[Analysis of purpose identification for personal information collection]

**Findings**:

- [Specific finding]

---

#### Principle 3: Consent

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL]

**Analysis**:
[Analysis of consent mechanisms for personal information]

**Findings**:

- [Specific finding]

---

#### Principle 4: Limiting Collection

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL]

**Analysis**:
[Analysis of data minimization practices]

**Findings**:

- [Specific finding]

---

#### Principle 5: Limiting Use, Disclosure, and Retention

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL]

**Analysis**:
[Analysis of data use limitations, disclosure controls, retention policies]

**Findings**:

- [Specific finding]

---

#### Principle 6: Accuracy

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL]

**Analysis**:
[Analysis of data accuracy mechanisms]

**Findings**:

- [Specific finding]

---

#### Principle 7: Safeguards

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL]

**Analysis**:
[Analysis of security safeguards for personal information]

**Findings**:

- [Specific finding]

---

#### Principle 8: Openness

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL]

**Analysis**:
[Analysis of transparency about personal information practices]

**Findings**:

- [Specific finding]

---

#### Principle 9: Individual Access

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL]

**Analysis**:
[Analysis of data subject access capabilities]

**Findings**:

- [Specific finding]

---

#### Principle 10: Challenging Compliance

**Status**: [✅ PASS | ❌ FAIL | ⚠️ PARTIAL]

**Analysis**:
[Analysis of complaint mechanisms]

**Findings**:

- [Specific finding]

---

### US Regulatory Compliance Analysis

#### NIST Cybersecurity Framework Alignment

**Overall Status**: [ALIGNED | GAPS IDENTIFIED | NOT ALIGNED]

**Summary**: [Brief overview of NIST CSF alignment]

##### Identify Function

**Status**: [✅ STRONG | ⚠️ MODERATE | ❌ WEAK]

**Analysis**:
[Analysis of asset management, risk assessment, governance]

**Findings**:

- [Specific finding]

---

##### Protect Function

**Status**: [✅ STRONG | ⚠️ MODERATE | ❌ WEAK]

**Analysis**:
[Analysis of access control, data security, protective technology]

**Findings**:

- [Specific finding]

---

##### Detect Function

**Status**: [✅ STRONG | ⚠️ MODERATE | ❌ WEAK]

**Analysis**:
[Analysis of security monitoring, anomaly detection, continuous monitoring]

**Findings**:

- [Specific finding]

---

##### Respond Function

**Status**: [✅ STRONG | ⚠️ MODERATE | ❌ WEAK]

**Analysis**:
[Analysis of incident response capabilities]

**Findings**:

- [Specific finding]

---

##### Recover Function

**Status**: [✅ STRONG | ⚠️ MODERATE | ❌ WEAK]

**Analysis**:
[Analysis of recovery planning and procedures]

**Findings**:

- [Specific finding]

---

#### CCPA Compliance (California Consumer Privacy Act)

**Overall Status**: [COMPLIANT | NON-COMPLIANT | PARTIAL COMPLIANCE | N/A]

**Summary**: [Brief overview of CCPA compliance status]

**Analysis**:
[Analysis of consumer rights implementation: right to know, right to delete, right to opt-out]

**Findings**:

- [Specific finding]
- [Specific finding]

**Files Reviewed**:

-

[File path]: [Observation]

---

#### HIPAA Compliance (If PHI is handled)

**Overall Status**: [COMPLIANT | NON-COMPLIANT | PARTIAL COMPLIANCE | N/A]

**Summary
**: [Brief overview of HIPAA compliance status or "Not applicable - no Protected Health Information (PHI) identified"]

**Analysis**:
[If applicable: Analysis of PHI protection including encryption, access controls, audit logging, automatic logoff, integrity controls, transmission security]

**Findings**:

- [Specific finding if PHI is handled]

**Files Reviewed**:

-

[File path]: [Observation]

---

## API Security Analysis

*This section provides detailed analysis of API endpoints, integrations, and data connectivity security.*

### API Endpoints Discovered

**Total Endpoints Identified**: [N]

| Endpoint        | Method         | Authentication | Authorization     | Rate Limiting     | Issues Found |
|-----------------|----------------|----------------|-------------------|-------------------|--------------|
| [/api/endpoint] | [GET/POST/etc] | [Type or NONE] | [Present/MISSING] | [Present/MISSING] | [N]          |
| [/api/endpoint] | [GET/POST/etc] | [Type or NONE] | [Present/MISSING] | [Present/MISSING] | [N]          |

---

### Authentication Mechanisms

**Analysis**:
[Detailed analysis of authentication mechanisms used across APIs]

**Strengths**:

- [Positive observation]
- [Positive observation]

**Weaknesses**:

- [Security concern with file reference]
- [Security concern with file reference]

**Findings**:

- [Reference to specific vulnerabilities found in authentication]

---

### Authorization Controls

**Analysis**:
[Analysis of how APIs enforce access controls and authorization]

**Findings**:

- [Specific authorization issue with file reference]
- [Specific authorization issue with file reference]

---

### Data Source Connections

#### Database Connections

**Databases Identified**: [List of database types: PostgreSQL, MySQL, MongoDB, etc.]

**Connection Security Analysis**:

- [Analysis of connection string security]
- [Analysis of credential storage]
- [Analysis of connection encryption]

**Query Security Analysis**:

- [Analysis of SQL injection prevention]
- [Analysis of parameterized queries usage]
- [Analysis of ORM usage]

**Access Control Analysis**:

- [Analysis of database user privileges]
- [Analysis of least privilege implementation]

**Findings**:

- [Specific database security issue with file reference]

---

#### External API Integrations

**External APIs Identified**: [List of external services: Payment gateways, third-party APIs, etc.]

**Authentication Analysis**:

- [How external APIs are authenticated]
- [How credentials are stored]

**Error Handling Analysis**:

- [How errors from external APIs are handled]
- [Whether failures are secure]

**Data Validation Analysis**:

- [Whether data from external APIs is validated]
- [Trust assumptions]

**Findings**:

- [Specific external API security issue with file reference]

---

### Rate Limiting Analysis

**Status**: [IMPLEMENTED | PARTIALLY IMPLEMENTED | MISSING]

**Analysis**:
[Analysis of rate limiting implementation across endpoints]

**Endpoints with Rate Limiting**: [N/Total]
**Endpoints without Rate Limiting**: [N/Total]

**Findings**:

- [Specific rate limiting gap with endpoint reference]

---

### Input Validation

**Analysis**:
[Analysis of input validation comprehensiveness across APIs]

**Validation Strengths**:

- [Positive observation]

**Validation Gaps**:

- [Missing validation with file reference]
- [Missing validation with file reference]

---

### Data Exposure

**Analysis**:
[Analysis of whether APIs expose excessive data beyond client needs]

**Findings**:

- [Over-fetching issue with endpoint reference]
- [Sensitive field exposure with endpoint reference]

---

## Security Management Assessment

*This section evaluates how security is managed throughout the codebase.*

---

### Secrets Management

**Hardcoded Secrets Discovered**: [N]

**Locations**:

- [File:line]: [Type of secret: password/API key/token]
- [File:line]: [Type of secret]

**Environment Variable Usage**: [GOOD | PARTIAL | POOR]
[Assessment of whether configuration uses environment variables appropriately]

**Secret Management System Integration**: [PRESENT | ABSENT]
[Whether integration with HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, etc. is present]

**Recommendations**:

- [Specific recommendation for secrets management improvement]

---

### Dependency Security

#### Outdated Dependencies

**Total Outdated**: [N]

| Dependency     | Current Version | Latest Version | Versions Behind | Risk Level        |
|----------------|-----------------|----------------|-----------------|-------------------|
| [package-name] | [version]       | [version]      | [N]             | [HIGH/MEDIUM/LOW] |
| [package-name] | [version]       | [version]      | [N]             | [HIGH/MEDIUM/LOW] |

---

#### Dependencies with Known Vulnerabilities

**Total Vulnerable**: [N]

| Dependency | Version   | CVE              | Severity                   | CVSS Score | Fix Available |
|------------|-----------|------------------|----------------------------|------------|---------------|
| [package]  | [version] | [CVE-YYYY-NNNNN] | [CRITICAL/HIGH/MEDIUM/LOW] | [score]    | [version]     |
| [package]  | [version] | [CVE-YYYY-NNNNN] | [CRITICAL/HIGH/MEDIUM/LOW] | [score]    | [version]     |

---

#### Dependency Pinning

**Status**: [FULLY PINNED | PARTIALLY PINNED | UNPINNED]

**Analysis**:
[Assessment of dependency pinning practices and use of lock files]

**Lock Files Present**:

- [✅ / ❌] package-lock.json (npm)
- [✅ / ❌] Pipfile.lock (Python)
- [✅ / ❌] go.sum (Go)
- [✅ / ❌] Gemfile.lock (Ruby)

**Recommendations**:

- [Dependency security recommendation]

---

### Security Configuration

#### Configuration Externalization

**Status**: [GOOD | PARTIAL | POOR]

**Analysis**:
[Assessment of whether security settings are externalized vs hardcoded]

**Configuration Methods Used**:

- [✅ / ❌] Environment variables
- [✅ / ❌] Configuration files
- [✅ / ❌] Remote configuration service
- [❌] Hardcoded in source

**Findings**:

- [Hardcoded configuration issue with file reference]

---

#### Secure Defaults

**Status**: [SECURE | MIXED | INSECURE]

**Analysis**:
[Assessment of default security settings in the application]

**Findings**:

- [Insecure default with file reference]

---

#### Configuration Validation

**Status**: [IMPLEMENTED | PARTIAL | MISSING]

**Analysis**:
[Whether configuration is validated at application startup]

**Findings**:

- [Configuration validation gap]

---

### Logging and Monitoring

#### Security Event Logging

**Status**: [COMPREHENSIVE | PARTIAL | INSUFFICIENT]

**Events Logged**:

- [✅ / ❌] Authentication attempts (success and failure)
- [✅ / ❌] Authorization failures
- [✅ / ❌] Input validation failures
- [✅ / ❌] Security exceptions
- [✅ / ❌] Sensitive data access

**Analysis**:
[Assessment of security event logging comprehensiveness]

**Findings**:

- [Logging gap with file reference]

---

#### Sensitive Data in Logs

**Status**: [CLEAN | CONCERNS IDENTIFIED | VIOLATIONS FOUND]

**Analysis**:
[Analysis of whether logs contain sensitive data]

**Sensitive Data Logged**:

- [File:line]: [Type of sensitive data being logged]

**Recommendations**:

- [Logging security recommendation]

---

#### Log Protection

**Status**: [PROTECTED | PARTIALLY PROTECTED | UNPROTECTED]

**Analysis**:
[Assessment of log security: access controls, integrity protection, tampering prevention]

**Findings**:

- [Log protection issue]

---

## Code Quality and Best Practices

*This section provides overall assessment of code quality from a security perspective.*

### Code Readability and Maintainability

**Assessment**: [EXCELLENT | GOOD | MODERATE | POOR]

**Observations**:

- [Observation about code readability affecting security review]
- [Observation about code structure]

**Security Impact**:
[How code quality affects security maintainability and vulnerability remediation]

---

### Documentation

**Assessment**: [COMPREHENSIVE | ADEQUATE | INSUFFICIENT | MISSING]

**Documentation Present**:

- [✅ / ❌] Function/method docstrings
- [✅ / ❌] Security architecture documentation
- [✅ / ❌] Threat model
- [✅ / ❌] API documentation with security guidance
- [✅ / ❌] Deployment security documentation

**Gaps Identified**:

- [Documentation gap affecting security]

---

### Error Handling

**Assessment**: [ROBUST | ADEQUATE | WEAK]

**Analysis**:
[Assessment of error handling approaches and security implications]

**Findings**:

- [Error handling security issue with file reference]

**Recommendations**:

- [Error handling improvement recommendation]

---

## Recommendations and Remediation Roadmap

*This section provides a prioritized plan for addressing all findings.*

---

### Immediate Actions (24-48 hours)

**Priority**: CRITICAL - Must be addressed immediately

1. **[VULN-ID]: [Vulnerability Title]**
    - **Why Urgent**: [Explanation of critical risk]
    - **Action**: [Specific immediate action required]
    - **Owner**: [Suggested owner: Security Team / Development Team]
    - **Location**: [File:lines]

2. **[VULN-ID]: [Vulnerability Title]**
    - **Why Urgent**: [Explanation of critical risk]
    - **Action**: [Specific immediate action required]
    - **Owner**: [Suggested owner]
    - **Location**: [File:lines]

*[List all critical findings]*

---

### Short-Term Actions (1-2 weeks)

**Priority**: HIGH - Should be addressed soon to reduce significant risk

1. **[VULN-ID]: [Vulnerability Title]**
    - **Risk**: [Explanation of risk]
    - **Action**: [Remediation steps]
    - **Owner**: [Suggested owner]
    - **Location**: [File:lines]

2. **[VULN-ID]: [Vulnerability Title]**
    - **Risk**: [Explanation of risk]
    - **Action**: [Remediation steps]
    - **Owner**: [Suggested owner]
    - **Location**: [File:lines]

*[List all high priority findings]*

---

### Medium-Term Actions (1 month)

**Priority**: MEDIUM - Should be addressed to improve security posture

1. **[VULN-ID]: [Vulnerability Title]**
    - **Risk**: [Explanation of risk]
    - **Action**: [Remediation steps]
    - **Owner**: [Suggested owner]
    - **Location**: [File:lines]

*[List all medium priority findings]*

---

### Long-Term Improvements (3 months)

**Priority**: LOW - Should be addressed for defense in depth

1. **[VULN-ID]: [Vulnerability Title]**
    - **Improvement**: [Description]
    - **Action**: [Remediation steps]
    - **Owner**: [Suggested owner]

*[List all low priority and informational findings]*

---

### Security Process Improvements

**Recommended Process Changes**:

1. **Implement Security Testing in CI/CD**
    - Add this security review agent to your CI/CD pipeline
    - Run on every pull request
    - Block merges on critical findings
    - [Specific implementation guidance]

2. **Add Dependency Vulnerability Scanning**
    - Integrate tools like Snyk, Dependabot, or npm audit
    - Scan on every build
    - Monitor for new CVEs in production dependencies
    - [Specific implementation guidance]

3. **Establish Security Training Program**
    - Train developers on secure coding practices
    - Focus on top vulnerability types found: [list]
    - Provide hands-on examples and exercises
    - [Specific topics to cover]

4. **Implement Secret Management System**
    - Deploy HashiCorp Vault, AWS Secrets Manager, or equivalent
    - Migrate all hardcoded secrets to secret management
    - Implement secret rotation policies
    - [Specific implementation guidance]

5. **Establish Security Code Review Process**
    - Require security review for sensitive code changes
    - Create security champions within development team
    - Document security review checklist
    - [Specific process recommendations]

*[Additional process improvements based on findings]*

---

## Metrics and Trends

### Code Coverage

**Test Coverage**: [XX]% *(if available)*
**Security Test Coverage**: [XX]% *(if determinable)*

**Assessment**: [Evaluation of test coverage adequacy]

---

### Security Metrics

**Vulnerability Density**: [N vulnerabilities per 1,000 LOC]

**Vulnerability Distribution**:

```
Critical: [N] (XX%)
High:     [N] (XX%)
Medium:   [N] (XX%)
Low:      [N] (XX%)
Info:     [N] (XX%)
```

**Trend Analysis** *(if multiple reports available)*:

| Metric                | Current | Previous | Change     |
|-----------------------|---------|----------|------------|
| Total Vulnerabilities | [N]     | [N]      | [↑↓→] [X]% |
| Critical              | [N]     | [N]      | [↑↓→] [X]% |
| High                  | [N]     | [N]      | [↑↓→] [X]% |
| Medium                | [N]     | [N]      | [↑↓→] [X]% |
| Low                   | [N]     | [N]      | [↑↓→] [X]% |

---

### Remediation Metrics

**Mean Time to Remediation** *(if historical data available)*:

- Critical issues: [N days average]
- High issues: [N days average]
- Medium issues: [N days average]
- Low issues: [N days average]

**Repeat Vulnerability Rate**: [XX]%
*Percentage of vulnerabilities that are recurring issues or similar to previously fixed vulnerabilities*

**Top Recurring Vulnerability Types**:

1. [Vulnerability type]: [N occurrences]
2. [Vulnerability type]: [N occurrences]
3. [Vulnerability type]: [N occurrences]

---

## Appendices

### Appendix A: Custom Security Rules Applied

*List of custom security rules loaded and applied during this review:*

| Rule ID      | Title        | Severity   | Category   | Source File |
|--------------|--------------|------------|------------|-------------|
| [CUSTOM-001] | [Rule title] | [Severity] | [Category] | [File path] |
| [CUSTOM-002] | [Rule title] | [Severity] | [Category] | [File path] |

**Total Custom Rules Loaded**: [N]

---

### Appendix B: Files Analyzed

*Complete list of files included in this security review:*

| File Path      | Language   | Lines of Code | Findings |
|----------------|------------|---------------|----------|
| [path/to/file] | [Language] | [N]           | [N]      |
| [path/to/file] | [Language] | [N]           | [N]      |

**Total Files**: [N]
**Total Lines of Code**: [N]

---

### Appendix C: False Positives and Excluded Findings

*Findings that were initially flagged but determined to be false positives or excluded:*

| Finding               | Reason for Exclusion                          | Location     |
|-----------------------|-----------------------------------------------|--------------|
| [Finding description] | [Explanation of why this is a false positive] | [File:lines] |

**Total Excluded**: [N]

---

### Appendix D: Scope Exclusions

*Files or code paths explicitly excluded from this review:*

| Excluded Path  | Reason                                                        |
|----------------|---------------------------------------------------------------|
| [path/pattern] | [Reason: e.g., test files, third-party code, build artifacts] |

---

## Report Metadata

**Generated By**: Claude Code Security Agent v1.0.0
**Analysis Duration**: [Time taken to complete review]
**Rules Version**: Built-in rules v1.0.0
**Custom Rules**: [N] custom rules loaded
**Total Files Analyzed**: [N]
**Total Lines of Code**: [N]
**Report Generated**: [YYYY-MM-DD HH:MM:SS UTC]
**Report Location**: [File path where this report is saved]

---

## Confidentiality Notice

This security review report contains confidential security information about the codebase. Distribution should be
limited to authorized personnel only. Do not share this report outside the organization without proper authorization.

---

**End of Report**
