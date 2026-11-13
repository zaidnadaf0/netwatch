# NetWatch Security Documentation

## Threat Model

### Assets
1. **VPC Flow Logs** - Network traffic metadata
2. **Security Group Configurations** - Firewall rules
3. **Detection Results** - Threat intelligence
4. **Audit Findings** - Security posture data
5. **User Credentials** - API access tokens

### Threat Actors
- **External Attackers** - Network-based attacks
- **Malicious Insiders** - Credentialed access abuse
- **Compromised Instances** - Lateral movement
- **Misconfiguration** - Accidental exposure

### Attack Vectors
| Vector | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| SSH/RDP Brute Force | High | High | Detection rules, rate limiting |
| Data Exfiltration | Medium | Critical | Large transfer detection |
| Port Scanning | High | Medium | Scan detection rules |
| SG Misconfiguration | Medium | High | Audit analyzer |
| Credential Theft | Low | Critical | No secrets in code, RBAC |

## Security Controls

### Application Level
- **Input Validation**: Pydantic models on all API endpoints
- **Output Encoding**: JSON responses, no HTML rendering
- **Authentication**: JWT tokens (planned)
- **Authorization**: Role-based access (planned)
- **Rate Limiting**: Per-endpoint limits (planned)
- **Audit Logging**: All analysis operations logged

### Infrastructure Level
- **Network**: Private subnets, ALB with WAF
- **Database**: RDS with encryption at rest/transit
- **Secrets**: AWS Secrets Manager / Parameter Store
- **Monitoring**: CloudWatch + X-Ray tracing
- **Backup**: Automated RDS snapshots

### Data Protection
- **Encryption at Rest**: AES-256 for RDS, S3
- **Encryption in Transit**: TLS 1.2+ for all connections
- **Data Minimization**: Only store required fields
- **Retention**: Configurable retention policies
- **Disposal**: Secure deletion procedures

## Secure Development

### Code Review
- All changes via pull request
- Minimum 1 reviewer required
- Security-focused review checklist
- Automated SAST in CI (planned)

### Dependencies
- Pin versions in requirements.txt / package-lock.json
- Regular dependency scanning (Dependabot)
- License compliance checking
- No unpinned dependencies in production

### Testing
- Unit tests for all detection/audit rules
- Integration tests for API endpoints
- Contract tests for external APIs
- Penetration testing (quarterly)

## Incident Response

### Detection
- Automated alerting for CRITICAL findings
- Log aggregation for forensic analysis
- Correlation with AWS GuardDuty

### Response
1. **Identify** - Confirm finding via UI/API
2. **Contain** - Modify security groups, block IPs
3. **Eradicate** - Remove malicious resources
4. **Recover** - Restore from known good state
5. **Lessons** - Update rules, improve detection

### Communication
- Internal: Security team Slack channel
- External: Customer notification per SLA
- Regulatory: 72-hour breach notification (GDPR)

## Compliance Mapping

| Control | Standard | Implementation |
|---------|----------|----------------|
| AC-2 | NIST 800-53 | Account management via IAM |
| AC-3 | NIST 800-53 | RBAC for API access |
| AU-2 | NIST 800-53 | Audit logging for all ops |
| AU-6 | NIST 800-53 | Log review automation |
| CM-7 | NIST 800-53 | Least functionality (SG audit) |
| SC-7 | NIST 800-53 | Boundary protection (VPC) |
| SI-3 | NIST 800-53 | Malware protection (detection) |
| SI-4 | NIST 800-53 | System monitoring (flow logs) |

## Secure Configuration

### Backend (.env)
```env
NETWATCH_DEBUG=false
NETWATCH_ENV=production
NETWATCH_DATABASE_URL=postgresql+psycopg://user:pass@host:5432/netwatch
NETWATCH_CORS_ORIGINS=["https://app.example.com"]
NETWATCH_AWS_REGION=us-east-1
NETWATCH_LOG_LEVEL=INFO
```

### Frontend Build
```bash
npm run build  # Production build with minification
```

### Docker (Future)
```dockerfile
FROM python:3.12-slim
COPY --chown=app:app . /app
USER app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]
```

## Vulnerability Management

### Scanning
- **SAST**: Bandit, Semgrep (CI)
- **DAST**: OWASP ZAP (staging)
- **SCA**: Dependabot, Snyk
- **Container**: Trivy (images)

### Patch Management
- Base images updated weekly
- Dependencies updated monthly
- Emergency patches within 24h for CVSS >= 9.0

## Security Contacts

- **Security Team**: security@example.com
- **Bug Bounty**: https://hackerone.com/netwatch
- **PGP Key**: Available on keys.openpgp.org