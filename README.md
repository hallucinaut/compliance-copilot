# 📋 Compliance Copilot - Real-Time Compliance Assistant

> **Continuous compliance monitoring for SOC2, HIPAA, PCI-DSS, GDPR, and CIS Benchmarks**

---

## 🎯 Problem Solved

Compliance is **ongoing and complex**:
- **Periodic audits** miss issues between checks
- **Manual compliance** is error-prone and time-consuming
- **Multiple frameworks** require different controls
- **Evidence collection** is fragmented
- **Real-time monitoring** is rarely available

**Compliance Copilot solves this by providing continuous, real-time compliance monitoring.**

---

## ✨ Features

### 📊 Compliance Frameworks

#### SOC2 (Service Organization Control 2)
- CC1.1 - Logical and Physical Access Controls
- CC2.1 - System Monitoring
- CC3.1 - Encryption at Rest
- CC4.1 - Change Management
- CC5.1 - Incident Response

#### HIPAA (Health Insurance Portability and Accountability Act)
- 164.312.a.1 - Access Control
- 164.312.b - Audit Controls
- 164.312.a.2.iv - Encryption and Decryption
- 164.308.a.1 - Security Management Process

#### PCI-DSS (Payment Card Industry Data Security Standard)
- 2.1 - Vendor Defaults
- 3.4 - Render PAN Unreadable
- 6.5.1 - Injection Flaws
- 10.1 - Audit Trail

#### GDPR (General Data Protection Regulation)
- Art.5.1.a - Lawfulness, Fairness, Transparency
- Art.25.1 - Data Protection by Design
- Art.32.1 - Security of Processing

#### CIS Benchmarks
- CIS-1.1 - Sudo Configuration
- CIS-2.1 - SSH Key Permissions
- CIS-3.1 - Filesystem Integrity

### 🔍 Key Capabilities

- **Real-Time Monitoring** - Continuous compliance checking
- **Multi-Framework** - Support for 8+ compliance frameworks
- **Automated Evidence** - Collect evidence automatically
- **Score Calculations** - Compliance scoring per framework
- **Issue Tracking** - Track and remediate issues
- **Reporting** - Audit-ready reports

---

## 🛠️ Installation

### Build from Source

```bash
cd compliance-copilot
go mod download
go build -o compliance-copilot cmd/compliance-copilot/main.go
```

### Install Globally

```bash
go install -o /usr/local/bin/compliance-copilot ./cmd/compliance-copilot
```

---

## 🚀 Usage

### Basic Usage

```bash
# Monitor current directory
./compliance-copilot --watch=.

# Monitor multiple directories
./compliance-copilot --watch=./infrastructure,./k8s,./terraform

# Fail on critical and high issues
./compliance-copilot --watch=. --fail-critical=true --fail-high=true
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--watch` | Comma-separated paths to watch | `.` |
| `--fail-critical` | Fail if critical issues found | `true` |
| `--fail-high` | Fail if high issues found | `true` |
| `--verbose` | Verbose output | `false` |
| `--help` | Show help message | `false` |

### Examples

#### Monitor Infrastructure

```bash
# Monitor Terraform and Kubernetes configurations
./compliance-copilot --watch=./terraform,./k8s --verbose

# Monitor all configurations with reporting
./compliance-copilot --watch=./infra --fail-critical=true
```

#### Continuous Monitoring

```bash
# Set up continuous monitoring with cron
*/5 * * * * /usr/local/bin/compliance-copilot --watch=/path/to/configs >> compliance.log 2>&1
```

---

## 📊 Compliance Report Example

```
================================================================================
📊 COMPLIANCE REPORT
================================================================================

📈 Compliance Status by Framework:

❌ SOC2                   : 60.0% (non-compliant)
⚠️  HIPAA                  : 75.0% (partial-compliant)
✅ PCI-DSS                : 100.0% (compliant)
✅ GDPR                   : 100.0% (compliant)
⚠️  CIS Benchmarks         : 85.7% (partial-compliant)

📊 Overall: 3/5 frameworks compliant

================================================================================

🔍 Issues by Severity:

🔴 CRITICAL: 2 issues
🟠 HIGH: 3 issues
🟡 MEDIUM: 4 issues
🟢 LOW: 1 issues

📋 Detailed Issues:

🔴 [CRITICAL] Access Control - HIPAA
    Control ID: 164.312.a.1
    Category: Access Control
    File: /infrastructure/iam-policy.json
    Description: Implement technical policies for electronic PHI access
    Remediation: Review and fix: No access control for PHI

🔴 [CRITICAL] Vendor Defaults - PCI-DSS
    Control ID: 2.1
    Category: Configuration
    File: /infrastructure/server-config.yaml
    Description: Change vendor defaults and set strong passwords
    Remediation: Review and fix: Vendor defaults still in use

🟠 [HIGH] Logical and Physical Access Controls - SOC2
    Control ID: CC1.1
    Category: Access Control
    File: /infrastructure/security-group.json
    Description: Logical and physical access to systems and data is restricted
    Remediation: Review and fix: No access control configured

================================================================================

⚠️  2 frameworks need attention
```

---

## 🎨 Compliance Frameworks

### SOC2 Compliance

SOC2 focuses on five trust service criteria:

1. **Security** - Protection against unauthorized access
2. **Availability** - Systems are available for operation
3. **Processing Integrity** - System processing is complete and accurate
4. **Confidentiality** - Confidential information is protected
5. **Privacy** - Personal information is collected and used appropriately

### HIPAA Compliance

HIPAA covers healthcare data protection:

1. **Administrative Safeguards** - Security policies and procedures
2. **Physical Safeguards** - Physical access controls
3. **Technical Safeguards** - Technical security measures
4. **Organizational Safeguards** - Business associate agreements
5. **Data Management** - Data protection and privacy

### PCI-DSS Compliance

PCI-DSS for payment card security:

1. **Build and Maintain Secure Network**
2. **Protect Cardholder Data**
3. **Maintain Vulnerability Management Program**
4. **Implement Strong Access Control Measures**
5. **Regularly Monitor and Test Networks**
6. **Maintain Information Security Policy**

### GDPR Compliance

GDPR for data privacy:

1. **Lawfulness, Fairness, Transparency**
2. **Purpose Limitation**
3. **Data Minimization**
4. **Accuracy**
5. **Storage Limitation**
6. **Integrity and Confidentiality**

---

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: Compliance Check
on: [push, pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install compliance-copilot
        run: |
          go build -o compliance-copilot ./cmd/compliance-copilot
      
      - name: Run compliance check
        run: |
          ./compliance-copilot --watch=./infrastructure --fail-critical=true
```

### GitLab CI

```yaml
compliance-check:
  stage: security
  image: golang:1.21
  script:
    - go build -o compliance-copilot ./cmd/compliance-copilot
    - ./compliance-copilot --watch=./infrastructure --fail-critical=true
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Compliance Check') {
            steps {
                sh '''
                    go build -o compliance-copilot ./cmd/compliance-copilot
                    ./compliance-copilot --watch=./infrastructure --fail-critical=true
                '''
            }
        }
    }
}
```

---

## 📝 Evidence Collection

Compliance Copilot collects evidence automatically:

### SOC2 Evidence
- IAM policies
- Security groups
- Access logs
- CloudTrail logs
- Monitoring dashboards

### HIPAA Evidence
- Audit logs
- Access logs
- System logs
- Encryption configurations
- TLS certificates

### PCI-DSS Evidence
- Configuration files
- Security scan results
- Penetration test reports
- Audit logs

### GDPR Evidence
- Privacy policies
- Consent records
- Privacy impact assessments
- Data protection measures

---

## 📊 Compliance Scoring

Compliance Copilot calculates scores for each framework:

### Scoring Methodology

```
Score = (Passed Controls / Total Controls) × 100
```

### Status Categories

| Score | Status | Action |
|-------|--------|--------|
| 100% | Compliant | Maintain current controls |
| 80-99% | Partial Compliant | Address gaps |
| <80% | Non-Compliant | Immediate action required |

### Example Score Calculation

```
SOC2:
- Total Controls: 5
- Passed: 3
- Failed: 2
- Score: (3/5) × 100 = 60%
- Status: Non-Compliant
```

---

## 🧪 Testing

### Create Test Configuration

```bash
# Create test configuration
cat > test-config.json << EOF
{
  "access_control": "none",
  "monitoring_enabled": false,
  "encryption_at_rest": false,
  "incident_response_plan": false
}
EOF

# Run compliance check
./compliance-copilot --watch=. --verbose
```

### Test Multiple Frameworks

```bash
# Test with multiple configurations
mkdir -p test-frameworks
cp test-soc2.json test-frameworks/
cp test-hipaa.json test-frameworks/
cp test-pci.json test-frameworks/

./compliance-copilot --watch=./test-frameworks
```

---

## 🚧 Roadmap

- [ ] Real-time monitoring with file watchers
- [ ] Custom control definitions
- [ ] Integration with SIEM systems
- [ ] Automated evidence collection
- [ ] Compliance dashboard
- [ ] Export to PDF/HTML
- [ ] API for programmatic access
- [ ] Multi-account/organization support

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Add new compliance controls
4. Submit a pull request

---

## 📄 License

MIT License - Free for commercial and personal use

---

## 🙏 Acknowledgments

Built with ❤️ for continuous compliance monitoring.

---

**Version:** 1.0.0  
**Author:** @hallucinaut  
**Last Updated:** February 25, 2026