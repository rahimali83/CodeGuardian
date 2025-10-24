# CodeGuardian Security Rules Index

This document provides a complete index of all security rules available to the CodeGuardian Security Review Agent.

## Rule Organization

Rules are organized into two categories:

### 1. Core Security Rules (Level 0-1)
Foundational security principles and detection patterns from `rules/rules/codeguard-0-*.md` and `codeguard-1-*.md`

### 2. Comprehensive Detection Rules (Level 2)
Detailed vulnerability detection patterns with code examples from `rules/rules/codeguard-2-*.md`

## Complete Rules Catalog

### Authentication & Identity (codeguard-0-authentication-mfa.md)
**When to apply**: All authentication flows, login systems, password handling, MFA implementation

**Covers**:
- Password policies and validation (minimum 8 characters, breached password checking)
- Password storage (Argon2id, bcrypt, scrypt with proper parameters)
- Multi-factor authentication (WebAuthn/FIDO2, TOTP, backup codes)
- OAuth 2.0/OIDC flows (Authorization Code + PKCE, state/nonce validation)
- SAML security (signature validation, assertion encryption)
- JWT token security (algorithm pinning, expiry validation, revocation)
- Account recovery and password reset (CSPRNG tokens, single-use, time-bounded)
- Rate limiting on auth endpoints
- Session rotation on privilege changes

**Languages**: Python, JavaScript, TypeScript, Java, PHP, Ruby, Go, Kotlin, Swift

---

### Authorization & Access Control (codeguard-0-authorization-access-control.md)
**When to apply**: All data access operations, API endpoints, resource ownership checks

**Covers**:
- Deny by default principle
- RBAC/ABAC/ReBAC patterns
- IDOR (Insecure Direct Object Reference) prevention
- Mass assignment protection
- Step-up/transaction authorization
- Resource ownership verification
- Query scoping (currentUser.projects.find() pattern)
- DTO patterns to prevent mass assignment

**Languages**: Python, JavaScript, TypeScript, Java, PHP, Ruby, Go, YAML configs

---

### Input Validation & Injection Defense (codeguard-0-input-validation-injection.md)
**When to apply**: All input handling, database queries, command execution, template rendering

**Covers**:
- SQL injection prevention (100% parameterization requirement)
- LDAP injection (DN and filter escaping)
- OS command injection (structured execution, no shell invocation)
- NoSQL injection (query object validation)
- Template injection
- Prototype pollution (JavaScript object graphs)
- File upload validation (content type, size, magic numbers)

**Languages**: Python, JavaScript, TypeScript, Java, PHP, Ruby, Go, SQL, Shell, PowerShell

---

### API & Web Services Security (codeguard-0-api-web-services.md)
**When to apply**: REST APIs, GraphQL, SOAP/WS, microservices

**Covers**:
- Transport security (HTTPS, mTLS)
- Authentication patterns (OAuth2/OIDC, service tokens)
- Schema validation (OpenAPI, JSON Schema, GraphQL SDL, XSD)
- SSRF prevention (URL validation, private IP blocking, redirect disabling)
- GraphQL-specific controls (depth limiting, complexity scoring, pagination)
- Rate limiting and DoS protection
- Management endpoint isolation
- Microservices authorization patterns

**Languages**: Python, JavaScript, TypeScript, Java, PHP, Ruby, Go, XML, YAML

---

### Client-Side Web Security (codeguard-0-client-side-web-security.md)
**When to apply**: Frontend code, JavaScript, HTML templates

**Covers**:
- XSS prevention (context-aware encoding, textContent usage)
- DOM-based XSS (dangerous sinks: innerHTML, eval, document.write)
- Content Security Policy (nonce-based, hash-based, Trusted Types)
- CSRF defense (synchronizer tokens, SameSite cookies, custom headers)
- Clickjacking prevention (frame-ancestors, X-Frame-Options)
- XS-Leaks controls (SameSite, Fetch Metadata, COOP/COEP)
- Third-party JavaScript isolation (SRI, sandboxed iframes)
- WebSocket security (wss://, origin validation)
- postMessage validation (exact target origin, event.origin checks)

**Languages**: JavaScript, TypeScript, HTML, PHP (server-side rendering), C (for native components)

---

### Data Storage & Database Security (codeguard-0-data-storage.md)
**When to apply**: Database configurations, connection handling, data access

**Covers**:
- Database isolation (network restrictions, localhost binding)
- TLS for database connections (TLS 1.2+, certificate validation)
- Authentication and credential storage (no hardcoded passwords, secrets management)
- Least privilege database accounts (no admin rights for application accounts)
- Row-level security (RLS) and column-level security
- Backup security (encryption, access controls)
- Platform-specific hardening (SQL Server, MySQL, PostgreSQL, MongoDB, Redis)

**Languages**: SQL, Python, JavaScript, YAML configs, C

---

### File Handling & Upload Security (codeguard-0-file-handling-and-uploads.md)
**When to apply**: File upload endpoints, file processing, file storage

**Covers**:
- Extension validation (allowlist approach, double extension checks)
- Content type validation (magic number verification, not trusting headers)
- Filename sanitization (random generation, alphanumeric restriction)
- File content validation (image rewriting, AV scanning, CDR)
- Storage isolation (outside webroot, separate servers)
- Access control (authentication required, authorization per file)
- Size limits (upload and post-decompression)
- CSRF protection on upload endpoints

**Languages**: Python, JavaScript, TypeScript, Java, PHP, Ruby, Go

---

### Session Management & Cookies (codeguard-0-session-management-and-cookies.md)
**When to apply**: Session handling, cookie configuration, authentication flows

**Covers**:
- Session ID generation (CSPRNG, ≥128 bits entropy)
- Cookie security flags (Secure, HttpOnly, SameSite=Strict/Lax)
- Session regeneration (on auth, privilege changes)
- Session expiration (idle and absolute timeouts)
- Cookie theft detection (fingerprinting, anomaly detection)
- Client storage security (no localStorage for sessions)
- HTTPS enforcement with HSTS

**Languages**: Python, JavaScript, TypeScript, Java, PHP, Ruby, Go, HTML

---

### Logging & Monitoring (codeguard-0-logging.md)
**When to apply**: All logging implementations, security event tracking

**Covers**:
- Structured logging (JSON format, stable fields)
- Sensitive data redaction (passwords, tokens, PII)
- Log injection prevention (CR/LF stripping)
- Log integrity (append-only storage, tamper detection)
- Security event logging (auth events, failures, privilege changes)
- Correlation IDs for request tracking
- Detection patterns (credential stuffing, impossible travel, data exfil)

**Languages**: Python, JavaScript, C, YAML configs

---

### Cryptographic Algorithms (codeguard-1-crypto-algorithms.md)
**When to apply**: Always - cryptographic algorithm selection

**Covers**:
- **BANNED algorithms**: MD2, MD4, MD5, SHA-0, RC2, RC4, Blowfish, DES, 3DES
- **DEPRECATED**: SHA-1, AES-CBC, AES-ECB, RSA PKCS#1 v1.5, DHE with weak primes
- **REQUIRED**: SHA-256+, AES-GCM, ChaCha20, RSA OAEP, ECDHE
- Deprecated OpenSSL APIs (use EVP high-level APIs)
- Broccoli project requirements (no HMAC with SHA-1)

**Languages**: All (algorithm selection is language-independent), C (OpenSSL specific)

---

### Hardcoded Credentials (codeguard-1-hardcoded-credentials.md)
**When to apply**: Always - scan all files

**Covers**:
- Recognition patterns for various secret types:
  - AWS keys (AKIA, AGPA, AIDA, AROA prefixes)
  - Stripe keys (sk_live_, pk_live_)
  - Google API keys (AIza pattern)
  - GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
  - JWT tokens (eyJ pattern)
  - Private key blocks (-----BEGIN...PRIVATE KEY-----)
  - Connection strings with credentials
- Variable name patterns (password, secret, key, token, auth)
- Base64 encoded strings near authentication code

**Languages**: All

---

### Comprehensive Secrets Detection (codeguard-2-secrets-detection.md)
**When to apply**: Always - primary secrets scanning rule

**Covers**:
- **All secret types** with detailed detection patterns and confidence scoring:
  - Hardcoded passwords (connection strings, MySQL, PostgreSQL, MongoDB)
  - AWS credentials (Access Key ID, Secret Access Key, Session Tokens)
  - Third-party API keys (Stripe, Google, GitHub, generic patterns)
  - Private keys and certificates (RSA, DSA, EC, OpenSSH, PGP/GPG)
  - Bearer tokens in code
- Compliance mapping (PCI DSS 8.2.1, SOC 2 CC6.1, HIPAA 164.312)
- Detailed remediation with environment variables, secret management systems
- False positive indicators
- .gitignore recommendations

**Languages**: All files scanned

---

### Comprehensive Injection Vulnerabilities (codeguard-2-injection-vulnerabilities.md)
**When to apply**: All input handling, query construction, command execution

**Covers**:
- **SQL Injection** with language-specific patterns:
  - Python: f-strings, .format(), % formatting in execute()
  - Java: Statement with concatenation vs PreparedStatement
  - JavaScript: template literals in queries
  - PHP: mysqli with concatenation vs prepared statements
- **OS Command Injection**:
  - Python: os.system, subprocess with shell=True
  - JavaScript: exec with user input
  - Java: Runtime.exec with concatenation
  - PHP: shell_exec, system, exec with variables
- **Cross-Site Scripting (XSS)**:
  - DOM-based XSS dangerous sinks (innerHTML, outerHTML, document.write, eval)
  - React dangerouslySetInnerHTML
  - jQuery .html()
  - Server-side template XSS
- Defense-in-depth strategy with code examples

**Languages**: Python, JavaScript, TypeScript, Java, PHP, Ruby, Go

---

### Comprehensive Cryptography Security (codeguard-2-cryptography-security.md)
**When to apply**: All cryptographic operations, password hashing, random generation

**Covers**:
- **Weak hash algorithms** with specific detection:
  - Python: hashlib.md5(), hashlib.sha1()
  - Java: MessageDigest.getInstance("MD5"|"SHA-1")
  - JavaScript: crypto.createHash('md5'|'sha1')
- **Password hashing failures** (CRITICAL):
  - Fast hashes (SHA-256) used for passwords
  - Required: bcrypt (cost 12+), Argon2id, scrypt, PBKDF2 (600k+ iterations)
  - Language-specific secure implementations
- **Insecure random number generation**:
  - Python: random module vs secrets module
  - JavaScript: Math.random() vs crypto.randomBytes()
  - Java: Random vs SecureRandom
- **Deprecated OpenSSL APIs** (C/C++)

**Languages**: Python, JavaScript, TypeScript, Java, PHP, C, Go

---

### Additional Security Domains (codeguard-0-*.md files)

- **Additional Cryptography** (codeguard-0-additional-cryptography.md): Key management, certificate handling, TLS configuration
- **Cloud & Kubernetes** (codeguard-0-cloud-orchestration-kubernetes.md): Pod security, RBAC, network policies
- **DevOps & CI/CD** (codeguard-0-devops-ci-cd-containers.md): Container security, secrets in pipelines
- **Digital Certificates** (codeguard-1-digital-certificates.md): Certificate validation, pinning
- **Framework Security** (codeguard-0-framework-and-languages.md): Framework-specific patterns
- **IaC Security** (codeguard-0-iac-security.md): Terraform, CloudFormation, Ansible security
- **Mobile Apps** (codeguard-0-mobile-apps.md): iOS, Android security patterns
- **Privacy & Data Protection** (codeguard-0-privacy-data-protection.md): GDPR, CCPA compliance
- **Supply Chain** (codeguard-0-supply-chain-security.md): Dependency management, SBOMs
- **XML & Serialization** (codeguard-0-xml-and-serialization.md): XXE, insecure deserialization
- **Safe C Functions** (codeguard-1-safe-c-functions.md): Memory-safe C function alternatives

---

## How to Use These Rules

### For Security Code Review Agent

The agent should:
1. Load ALL rules at initialization
2. Apply `alwaysApply: true` rules to every file
3. Apply language-specific rules based on file extension
4. Use confidence scoring to prioritize findings
5. Include rule references in findings
6. Provide remediation from the relevant rule

### For Developers

Reference these rules when:
- Writing new code (proactive security)
- Reviewing pull requests
- Investigating security findings
- Learning secure coding practices

### Finding a Specific Rule

**By Vulnerability Type:**
- Secrets/Credentials → codeguard-1-hardcoded-credentials.md, codeguard-2-secrets-detection.md
- SQL Injection → codeguard-0-input-validation-injection.md, codeguard-2-injection-vulnerabilities.md
- Weak Crypto → codeguard-1-crypto-algorithms.md, codeguard-2-cryptography-security.md
- XSS → codeguard-0-client-side-web-security.md, codeguard-2-injection-vulnerabilities.md
- IDOR → codeguard-0-authorization-access-control.md
- SSRF → codeguard-0-api-web-services.md

**By Technology:**
- APIs → codeguard-0-api-web-services.md
- Databases → codeguard-0-data-storage.md, codeguard-2-injection-vulnerabilities.md
- Frontend → codeguard-0-client-side-web-security.md
- Containers → codeguard-0-devops-ci-cd-containers.md
- Cloud → codeguard-0-cloud-orchestration-kubernetes.md
- Mobile → codeguard-0-mobile-apps.md

**By Compliance:**
- PCI DSS → Rules with PCI_DSS tags (secrets, injection, encryption)
- SOC 2 → Rules with SOC2 tags (access control, logging)
- HIPAA → Rules with HIPAA tags (encryption, access control)
- GDPR → codeguard-0-privacy-data-protection.md

## Rule Priority

### CRITICAL (Always Flag)
- Hardcoded secrets and credentials
- SQL injection with string concatenation
- Fast hashes for password storage
- Private keys in code

### HIGH (Flag in Production Code)
- Command injection vulnerabilities
- Weak cryptographic algorithms (MD5, SHA-1)
- XSS vulnerabilities
- Missing authorization checks
- Path traversal

### MEDIUM (Flag with Context)
- Insecure random number generation
- Missing rate limiting
- Debug mode enabled
- Insecure cookie configuration

## Coverage Statistics

- **Total Rule Files**: 22
- **Languages Covered**: 15+ (Python, JavaScript, TypeScript, Java, PHP, Ruby, Go, C, Kotlin, Swift, Shell, PowerShell, SQL, HTML, YAML)
- **CWE Mappings**: 30+
- **OWASP Top 10 Coverage**: Complete (all 10 categories)
- **Compliance Frameworks**: 6 (PCI DSS, SOC 2, HIPAA, GDPR, CCPA, NIST)
- **Code Examples**: 100+ (insecure and secure variants)

## Updating Rules

To add a new rule:
1. Create `rules/rules/codeguard-X-rule-name.md`
2. Follow the existing format with frontmatter
3. Include detection patterns, code examples, remediation
4. Update this index
5. Test on sample vulnerable code

---

**Last Updated**: 2024-10-24
**Version**: 2.0.0
**Repository**: CodeGuardian Security Code Review Agent
