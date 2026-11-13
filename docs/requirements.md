# NetWatch Requirements

## Functional Requirements

### FR-1: Flow Log Ingestion
- **FR-1.1**: Accept VPC Flow Logs in JSON, JSONL, and GZIP formats
- **FR-1.2**: Parse and validate flow log entries against schema
- **FR-1.3**: Report parsing errors with line numbers
- **FR-1.4**: Support streaming parsing for large files (>100MB)
- **FR-1.5**: Store ingested logs in PostgreSQL

### FR-2: Threat Detection
- **FR-2.1**: Detect SSH (port 22) exposed to internet
- **FR-2.2**: Detect RDP (port 3389) exposed to internet
- **FR-2.3**: Detect potential data exfiltration (large UDP transfers)
- **FR-2.4**: Detect port scanning (multiple rejected connections)
- **FR-2.5**: Detect brute force attacks (repeated auth failures)
- **FR-2.6**: Support custom detection rules via plugin interface
- **FR-2.7**: Return structured detection results with severity

### FR-3: Security Group Audit
- **FR-3.1**: Analyze security group rules for 0.0.0.0/0 exposure
- **FR-3.2**: Detect open SSH, RDP, FTP, Telnet ports
- **FR-3.3**: Detect open database ports (MySQL, PostgreSQL, etc.)
- **FR-3.4**: Detect all-ports-open (0-65535) rules
- **FR-3.5**: Support IPv6 (::/0) exposure detection
- **FR-3.6**: Provide remediation guidance for each finding
- **FR-3.7**: Identify unused security groups

### FR-4: API & UI
- **FR-4.1**: RESTful API with OpenAPI 3.1 specification
- **FR-4.2**: Web UI for detection, ingestion, and audit workflows
- **FR-4.3**: Real-time analysis feedback
- **FR-4.4**: Historical results viewing
- **FR-4.5**: Export findings as JSON/CSV

## Non-Functional Requirements

### NFR-1: Performance
- **NFR-1.1**: Analyze 10,000 flow log entries in <5 seconds
- **NFR-1.2**: Parse 100MB flow log file in <30 seconds
- **NFR-1.3**: Audit 1,000 security groups in <10 seconds
- **NFR-1.4**: API response time <200ms for simple queries

### NFR-2: Reliability
- **NFR-2.1**: 99.9% uptime for API service
- **NFR-2.2**: Graceful handling of malformed input
- **NFR-2.3**: Automatic retry for transient failures
- **NFR-2.4**: Data persistence with ACID guarantees

### NFR-3: Security
- **NFR-3.1**: No hardcoded secrets or credentials
- **NFR-3.2**: Input validation on all API endpoints
- **NFR-3.3**: CORS restricted to configured origins
- **NFR-3.4**: Audit logging for all analysis operations
- **NFR-3.5**: Role-based access control (future)

### NFR-4: Maintainability
- **NFR-4.1**: Test coverage >80% for core logic
- **NFR-4.2**: Type hints for all public APIs
- **NFR-4.3**: Architecture decision records for major choices
- **NFR-4.4**: Automated linting and formatting in CI

### NFR-5: Scalability
- **NFR-5.1**: Horizontal scaling via container orchestration
- **NFR-5.2**: Database connection pooling
- **NFR-5.3**: Stateless API design
- **NFR-5.4**: Async processing for long-running jobs

## Data Requirements

### DR-1: Flow Log Retention
- **DR-1.1**: Store raw flow logs for 90 days
- **DR-1.2**: Store detection results for 1 year
- **DR-1.3**: Archive to cold storage after retention

### DR-2: Security Group State
- **DR-2.1**: Track security group configuration history
- **DR-2.2**: Store audit findings with timestamps
- **DR-2.3**: Support point-in-time queries

## Integration Requirements

### IR-1: AWS Integration (Future)
- **IR-1.1**: Read VPC Flow Logs from S3
- **IR-1.2**: Read Security Groups via EC2 API
- **IR-1.3**: Support cross-account roles
- **IR-1.4**: Event-driven processing via SQS/Lambda

### IR-2: Notification (Future)
- **IR-2.1**: Webhook notifications for critical findings
- **IR-2.2**: Email alerts for new detections
- **IR-2.3**: Slack/Teams integration

## Compliance

- **C-1**: SOC 2 Type II readiness (logging, access control)
- **C-2**: GDPR compliance (data minimization, retention)
- **C-3**: AWS Well-Architected alignment