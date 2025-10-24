# Compliance Frameworks Guide

## Overview

The Security Code Review Agent checks code against multiple compliance frameworks, verifying that technical controls are
properly implemented. This guide details each supported framework, what it covers, and what the agent checks for.

## PCI DSS (Payment Card Industry Data Security Standard)

### When It Applies

PCI DSS applies when your application:

- Stores, processes, or transmits cardholder data (credit/debit card information)
- Handles Primary Account Numbers (PAN)
- Integrates with payment processors
- Manages payment card transactions

### What the Agent Checks

**Requirement 3: Protect Stored Cardholder Data**

- Encryption of stored PAN using strong cryptography (AES-256 or equivalent)
- Masking of PAN when displayed (only last 4 digits visible)
- No storage of sensitive authentication data after authorization (CVV, PIN)
- Proper encryption key management

**Requirement 4: Encrypt Transmission of Cardholder Data**

- Use of strong TLS (1.2 or higher) for cardholder data transmission
- No unencrypted transmission of cardholder data over public networks

**Requirement 6: Develop and Maintain Secure Systems**

- Common coding vulnerabilities (SQL injection, XSS, etc.)
- Security vulnerability management processes in code

**Requirement 7: Restrict Access to Cardholder Data**

- Access control mechanisms implementing need-to-know and least privilege
- Default deny access controls

**Requirement 8: Identify and Authenticate Access**

- Unique user IDs for authentication
- Multi-factor authentication for remote access
- Strong password policies (minimum 7 characters, complexity requirements)
- Account lockout after failed authentication attempts

**Requirement 10: Track and Monitor Access**

- Audit logging of all access to cardholder data
- Log records include user identification, timestamps, and actions
- Log protection mechanisms to prevent tampering

### Key Findings

Common PCI DSS violations found by the agent:

- Unencrypted storage of PAN
- Hardcoded payment credentials
- Missing encryption for cardholder data transmission
- Logging of full PANs or CVVs
- Weak access controls on payment data

## SOC 2 (Service Organization Control 2)

### When It Applies

SOC 2 applies to service providers that:

- Store customer data in the cloud
- Provide SaaS applications
- Handle sensitive customer information
- Need to demonstrate security controls to customers

### Trust Service Principles

**Security (Common Criteria - Always Required)**

- Logical and physical access controls
- System operations and change management
- Risk mitigation and threat protection

**Availability**

- System performance monitoring
- Backup and disaster recovery
- Capacity planning and scaling

**Processing Integrity**

- Data validation at system boundaries
- Error detection and correction
- Data quality controls

**Confidentiality**

- Encryption of confidential data
- Data classification and handling
- Access controls for confidential information

**Privacy**

- Notice and consent mechanisms
- Data collection limitation
- Data retention and secure disposal
- Data subject rights implementation

### What the Agent Checks

- Access control implementations (authentication, authorization, least privilege)
- Change management evidence in code deployment practices
- Encryption of data at rest and in transit
- Monitoring and logging capabilities
- Data retention and deletion functions
- Incident response capabilities in code
- Business continuity implementations

## PIPEDA (Personal Information Protection and Electronic Documents Act - Canada)

### When It Applies

PIPEDA applies to private sector organizations in Canada that:

- Collect, use, or disclose personal information in commercial activities
- Transfer personal information across Canadian provincial borders
- Operate in federally regulated industries

### The 10 Fair Information Principles

**Principle 1: Accountability**

- Organizational responsibility for personal information handling
- Privacy policies and procedures

**Principle 2: Identifying Purpose**

- Clear purposes for personal information collection
- Documented and communicated purposes

**Principle 3: Consent**

- Meaningful consent from individuals
- Consent withdrawal capabilities

**Principle 4: Limiting Collection**

- Data minimization (only necessary information collected)
- Collection limited to stated purposes

**Principle 5: Limiting Use, Disclosure, and Retention**

- Personal information used only for stated purposes
- Retention only as long as necessary
- Secure deletion after retention period

**Principle 6: Accuracy**

- Personal information kept accurate and up-to-date
- Update and correction mechanisms

**Principle 7: Safeguards**

- Security safeguards appropriate to sensitivity
- Encryption, access controls, security monitoring

**Principle 8: Openness**

- Transparency about personal information management
- Accessible privacy policies

**Principle 9: Individual Access**

- Individuals can access their personal information
- Reasonable timelines for access requests

**Principle 10: Challenging Compliance**

- Complaint mechanisms
- Investigation and response procedures

### What the Agent Checks

- Consent mechanisms in code
- Data minimization practices
- Retention and secure deletion implementations
- Encryption of personal information
- Access controls for personal information
- Data accuracy and update functions
- Cross-border transfer protections
- Breach notification capabilities

## US Regulatory Frameworks

### NIST Cybersecurity Framework

**Five Core Functions:**

**Identify**

- Asset management and data classification
- Risk assessment processes
- Governance and risk management

**Protect**

- Access control implementation (authentication, authorization)
- Data security controls (encryption, DLP)
- Protective technology

**Detect**

- Security monitoring and anomaly detection
- Continuous monitoring capabilities
- Security event detection and logging

**Respond**

- Incident response capabilities and planning
- Communication procedures
- Mitigation and analysis capabilities

**Recover**

- Recovery planning and procedures
- Improvements and lessons learned

### CCPA (California Consumer Privacy Act)

**When It Applies**:

- Businesses operating in California
- Collecting personal information from California residents
- Meeting thresholds (annual revenue, data volume, or revenue from data sales)

**What the Agent Checks**:

- Consumer rights implementation (right to know, delete, opt-out)
- Data inventory and mapping capabilities
- Disclosure mechanisms for data collection and use
- Data sale opt-out mechanisms
- Age verification for minors (under 16)
- Data security controls

### HIPAA (Health Insurance Portability and Accountability Act)

**When It Applies**:

- Healthcare providers
- Health plans
- Healthcare clearinghouses
- Business associates handling PHI (Protected Health Information)

**What the Agent Checks**:

**Technical Safeguards (164.312)**:

- Access controls with unique user identification
- Audit controls logging PHI access and modifications
- Integrity controls preventing unauthorized PHI alteration
- Transmission security for electronic PHI (encryption)
- Automatic logoff after inactivity

**PHI Handling**:

- Encryption of PHI at rest (AES-256 or equivalent)
- Encryption of PHI in transit (TLS 1.2+)
- Access controls restricting PHI access to authorized users
- Audit logging of all PHI access
- Authentication mechanisms for PHI systems

## Compliance Checking Process

### How the Agent Performs Compliance Checks

1. **Enable Frameworks**: Configure which frameworks apply in `.code-review-config.yml`

2. **Technical Control Mapping**: Agent maps code patterns to compliance requirements

3. **Violation Detection**: Identifies code that violates compliance requirements

4. **Report Generation**: Produces detailed compliance analysis section in reports

5. **Remediation Guidance**: Provides specific steps to achieve compliance

### Compliance Report Sections

Each compliance framework gets a dedicated section in security reports:

- Overall compliance status
- Detailed analysis of each requirement
- Specific findings with file references
- Remediation priorities for compliance gaps
- Evidence of compliant controls

### Interpreting Compliance Status

**COMPLIANT**: All checked requirements pass, no violations found

**NON-COMPLIANT**: Critical compliance violations found, immediate action required

**PARTIAL COMPLIANCE**: Some requirements pass, others fail or not fully implemented

**N/A**: Framework not applicable to this codebase

## Common Compliance Violations

### Across All Frameworks

- Hardcoded credentials and API keys
- Unencrypted storage of sensitive data
- Missing encryption for data transmission
- Weak password hashing
- Insufficient access controls
- Missing audit logging
- Logging of sensitive information
- Insecure session management

### Framework-Specific

**PCI DSS**:

- Storing CVV or PIN data
- Logging full PANs
- Weak encryption for cardholder data

**SOC 2**:

- Missing change management controls
- Inadequate monitoring
- No incident response capabilities

**PIPEDA/CCPA**:

- No consent mechanisms
- Missing data deletion functions
- No data access mechanisms

**HIPAA**:

- Unencrypted PHI
- Missing audit logging for PHI access
- No automatic logoff

## Best Practices

1. **Know Your Requirements**: Identify which frameworks apply to your organization

2. **Enable Relevant Frameworks**: Configure only applicable frameworks to avoid noise

3. **Review Regularly**: Run compliance checks regularly (weekly or per sprint)

4. **Prioritize Compliance Findings**: Address compliance violations with high priority

5. **Document Controls**: Maintain documentation of security controls for auditors

6. **Test Continuously**: Integrate compliance checks into CI/CD pipelines

7. **Train Development Teams**: Educate developers on compliance requirements

8. **Maintain Evidence**: Keep security review reports as evidence of due diligence

## Additional Resources

- **PCI DSS**: https://www.pcisecuritystandards.org/
- **SOC 2**: https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html
- **PIPEDA
  **: https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/
- **NIST CSF**: https://www.nist.gov/cyberframework
- **CCPA**: https://oag.ca.gov/privacy/ccpa
- **HIPAA**: https://www.hhs.gov/hipaa/index.html

---

*This guide provides technical implementation guidance. Always consult legal counsel for compliance interpretation and
requirements specific to your organization.*
