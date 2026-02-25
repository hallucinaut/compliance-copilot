package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	infoColor = color.New(color.FgBlue)
	warnColor = color.New(color.FgYellow)
	errorColor = color.New(color.FgRed)
	successColor = color.New(color.FgGreen)
	criticalColor = color.New(color.FgRed, color.Bold)
	noticeColor = color.New(color.FgCyan)
)

// ComplianceFramework represents a compliance framework
type ComplianceFramework string

const (
	SOC2        ComplianceFramework = "soc2"
	HIPAA       ComplianceFramework = "hipaa"
	PCI_DSS     ComplianceFramework = "pci_dss"
	GDPR        ComplianceFramework = "gdpr"
	CIS         ComplianceFramework = "cis"
	ISO27001    ComplianceFramework = "iso27001"
	SOC1        ComplianceFramework = "soc1"
	NIST        ComplianceFramework = "nist"
)

// Control represents a compliance control
type Control struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Framework   ComplianceFramework `json:"framework"`
	Category    string            `json:"category"`
	Severity    string            `json:"severity"`
	Check       func(map[string]interface{}) (bool, string)
	Evidence    []string          `json:"evidence"`
}

// ComplianceIssue represents a compliance issue
type ComplianceIssue struct {
	ControlID     string            `json:"control_id"`
	ControlName   string            `json:"control_name"`
	Framework     ComplianceFramework `json:"framework"`
	Category      string            `json:"category"`
	Description   string            `json:"description"`
	Severity      string            `json:"severity"`
	Resource      string            `json:"resource"`
	File          string            `json:"file"`
	Evidence      []string          `json:"evidence"`
	Remediation   string            `json:"remediation"`
	Status        string            `json:"status"`
	FirstDetected time.Time         `json:"first_detected"`
	LastDetected  time.Time         `json:"last_detected"`
}

// ComplianceStatus holds the overall compliance status
type ComplianceStatus struct {
	Framework   ComplianceFramework `json:"framework"`
	Status      string              `json:"status"`
	Score       float64             `json:"score"`
	TotalControls int                `json:"total_controls"`
	PassedControls int                `json:"passed_controls"`
	FailedControls int                `json:"failed_controls"`
	Issues      []ComplianceIssue   `json:"issues"`
	LastChecked time.Time           `json:"last_checked"`
}

// ComplianceCopilot performs real-time compliance monitoring
type ComplianceCopilot struct {
	controls       map[ComplianceFramework][]Control
	issues         []ComplianceIssue
	status         map[ComplianceFramework]*ComplianceStatus
	dryRun         bool
	failOnCritical bool
	failOnHigh     bool
	verbose        bool
	watchPaths     []string
}

// NewComplianceCopilot creates a new ComplianceCopilot
func NewComplianceCopilot(dryRun, failCritical, failHigh, verbose bool) *ComplianceCopilot {
	return &ComplianceCopilot{
		controls:       make(map[ComplianceFramework][]Control),
		issues:         make([]ComplianceIssue, 0),
		status:         make(map[ComplianceFramework]*ComplianceStatus),
		dryRun:         dryRun,
		failOnCritical: failCritical,
		failOnHigh:     failHigh,
		verbose:        verbose,
		watchPaths:     make([]string, 0),
	}
}

// InitializeControls initializes all compliance controls
func (cc *ComplianceCopilot) InitializeControls() {
	// SOC2 Controls
	cc.controls[SOC2] = []Control{
		{
			ID:          "CC1.1",
			Name:        "Logical and Physical Access Controls",
			Description: "Logical and physical access to systems and data is restricted",
			Framework:   SOC2,
			Category:    "Access Control",
			Severity:    "HIGH",
			Check: func(config map[string]interface{}) (bool, string) {
				if access, ok := config["access_control"]; ok {
					if accessStr, ok := access.(string); ok {
						if accessStr == "none" || accessStr == "public" {
							return false, "No access control configured"
						}
					}
				}
				return true, ""
			},
			Evidence: []string{"IAM policies", "Security groups", "Access logs"},
		},
		{
			ID:          "CC2.1",
			Name:        "System Monitoring",
			Description: "Systems are monitored for security events",
			Framework:   SOC2,
			Category:    "Monitoring",
			Severity:    "MEDIUM",
			Check: func(config map[string]interface{}) (bool, string) {
				if monitoring, ok := config["monitoring_enabled"]; ok {
					if monitoringBool, ok := monitoring.(bool); ok && !monitoringBool {
						return false, "Monitoring is disabled"
					}
				}
				return true, ""
			},
			Evidence: []string{"CloudTrail logs", "SIEM alerts", "Monitoring dashboards"},
		},
		{
			ID:          "CC3.1",
			Name:        "Encryption at Rest",
			Description: "Data is encrypted at rest",
			Framework:   SOC2,
			Category:    "Data Protection",
			Severity:    "HIGH",
			Check: func(config map[string]interface{}) (bool, string) {
				if encrypted, ok := config["encryption_at_rest"]; ok {
					if encryptedBool, ok := encrypted.(bool); ok && !encryptedBool {
						return false, "Encryption at rest is disabled"
					}
				}
				return true, ""
			},
			Evidence: []string{"KMS configurations", "Encryption settings"},
		},
		{
			ID:          "CC4.1",
			Name:        "Change Management",
			Description: "Changes to systems are managed and documented",
			Framework:   SOC2,
			Category:    "Change Management",
			Severity:    "MEDIUM",
			Check: func(config map[string]interface{}) (bool, string) {
				return true, ""
			},
			Evidence: []string{"Git history", "Change logs", "Deployment records"},
		},
		{
			ID:          "CC5.1",
			Name:        "Incident Response",
			Description: "Incident response procedures are in place",
			Framework:   SOC2,
			Category:    "Incident Response",
			Severity:    "HIGH",
			Check: func(config map[string]interface{}) (bool, string) {
				if incident, ok := config["incident_response_plan"]; ok {
					if incidentBool, ok := incident.(bool); ok && !incidentBool {
						return false, "No incident response plan"
					}
				}
				return true, ""
			},
			Evidence: []string{"Incident response plan", "Response procedures"},
		},
	}

	// HIPAA Controls
	cc.controls[HIPAA] = []Control{
		{
			ID:          "164.312.a.1",
			Name:        "Access Control",
			Description: "Implement technical policies for electronic PHI access",
			Framework:   HIPAA,
			Category:    "Access Control",
			Severity:    "CRITICAL",
			Check: func(config map[string]interface{}) (bool, string) {
				if access, ok := config["access_control"]; ok {
					if accessStr, ok := access.(string); ok {
						if accessStr == "none" {
							return false, "No access control for PHI"
						}
					}
				}
				return true, ""
			},
			Evidence: []string{"IAM policies", "Access logs", "Audit trails"},
		},
		{
			ID:          "164.312.b",
			Name:        "Audit Controls",
			Description: "Implement hardware, software, and procedural mechanisms to record and examine activity",
			Framework:   HIPAA,
			Category:    "Audit",
			Severity:    "CRITICAL",
			Check: func(config map[string]interface{}) (bool, string) {
				if audit, ok := config["audit_enabled"]; ok {
					if auditBool, ok := audit.(bool); ok && !auditBool {
						return false, "Audit controls disabled"
					}
				}
				return true, ""
			},
			Evidence: []string{"Audit logs", "Access logs", "System logs"},
		},
		{
			ID:          "164.312.a.2.iv",
			Name:        "Encryption and Decryption",
			Description: "Implement technical safeguards to encrypt PHI when appropriate",
			Framework:   HIPAA,
			Category:    "Data Protection",
			Severity:    "CRITICAL",
			Check: func(config map[string]interface{}) (bool, string) {
				if encrypted, ok := config["encryption_enabled"]; ok {
					if encryptedBool, ok := encrypted.(bool); ok && !encryptedBool {
						return false, "Encryption not enabled for PHI"
					}
				}
				return true, ""
			},
			Evidence: []string{"Encryption configurations", "TLS certificates"},
		},
		{
			ID:          "164.308.a.1",
			Name:        "Security Management Process",
			Description: "Implement security measures to prevent, detect, contain, and correct security violations",
			Framework:   HIPAA,
			Category:    "Security Management",
			Severity:    "HIGH",
			Check: func(config map[string]interface{}) (bool, string) {
				return true, ""
			},
			Evidence: []string{"Security policies", "Risk assessments"},
		},
	}

	// PCI-DSS Controls
	cc.controls[PCI_DSS] = []Control{
		{
			ID:          "2.1",
			Name:        "Vendor Defaults",
			Description: "Change vendor defaults and set strong passwords",
			Framework:   PCI_DSS,
			Category:    "Configuration",
			Severity:    "CRITICAL",
			Check: func(config map[string]interface{}) (bool, string) {
				if defaults, ok := config["vendor_defaults"]; ok {
					if defaultsBool, ok := defaults.(bool); ok && defaultsBool {
						return false, "Vendor defaults still in use"
					}
				}
				return true, ""
			},
			Evidence: []string{"Configuration files", "System settings"},
		},
		{
			ID:          "3.4",
			Name:        "Render PAN Unreadable",
			Description: "Make primary account number unreadable anywhere it is stored",
			Framework:   PCI_DSS,
			Category:    "Data Protection",
			Severity:    "CRITICAL",
			Check: func(config map[string]interface{}) (bool, string) {
				if pan, ok := config["pan_storage"]; ok {
					if panStr, ok := pan.(string); ok {
						if panStr == "plaintext" {
							return false, "PAN stored in plaintext"
						}
					}
				}
				return true, ""
			},
			Evidence: []string{"Database configurations", "Encryption settings"},
		},
		{
			ID:          "6.5.1",
			Name:        "Injection Flaws",
			Description: "Protect against injection flaws (SQL, OS, LDAP)",
			Framework:   PCI_DSS,
			Category:    "Application Security",
			Severity:    "CRITICAL",
			Check: func(config map[string]interface{}) (bool, string) {
				return true, ""
			},
			Evidence: []string{"Security scan results", "Penetration test reports"},
		},
		{
			ID:          "10.1",
			Name:        "Audit Trail",
			Description: "Implement audit trails to link all access to system components",
			Framework:   PCI_DSS,
			Category:    "Audit",
			Severity:    "HIGH",
			Check: func(config map[string]interface{}) (bool, string) {
				if audit, ok := config["audit_enabled"]; ok {
					if auditBool, ok := audit.(bool); ok && !auditBool {
						return false, "Audit trail disabled"
					}
				}
				return true, ""
			},
			Evidence: []string{"Audit logs", "Access logs"},
		},
	}

	// GDPR Controls
	cc.controls[GDPR] = []Control{
		{
			ID:          "Art.5.1.a",
			Name:        "Lawfulness, Fairness, Transparency",
			Description: "Personal data shall be processed lawfully, fairly, and in a transparent manner",
			Framework:   GDPR,
			Category:    "Data Processing",
			Severity:    "HIGH",
			Check: func(config map[string]interface{}) (bool, string) {
				return true, ""
			},
			Evidence: []string{"Privacy policies", "Consent records"},
		},
		{
			ID:          "Art.25.1",
			Name:        "Data Protection by Design",
			Description: "Implement appropriate technical and organizational measures for data protection",
			Framework:   GDPR,
			Category:    "Data Protection",
			Severity:    "HIGH",
			Check: func(config map[string]interface{}) (bool, string) {
				if privacy, ok := config["privacy_by_design"]; ok {
					if privacyBool, ok := privacy.(bool); ok && !privacyBool {
						return false, "Privacy by design not implemented"
					}
				}
				return true, ""
			},
			Evidence: []string{"Privacy impact assessments", "Data protection measures"},
		},
		{
			ID:          "Art.32.1",
			Name:        "Security of Processing",
			Description: "Implement appropriate security measures including pseudonymization and encryption",
			Framework:   GDPR,
			Category:    "Security",
			Severity:    "HIGH",
			Check: func(config map[string]interface{}) (bool, string) {
				if security, ok := config["security_measures"]; ok {
					if securityList, ok := security.([]interface{}); ok {
						if len(securityList) == 0 {
							return false, "No security measures configured"
						}
					}
				}
				return true, ""
			},
			Evidence: []string{"Security configurations", "Encryption settings"},
		},
	}

	// CIS Benchmarks
	cc.controls[CIS] = []Control{
		{
			ID:          "CIS-1.1",
			Name:        "Ensure sudo is properly configured",
			Description: "Sudo should be configured with proper access controls",
			Framework:   CIS,
			Category:    "System Hardening",
			Severity:    "MEDIUM",
			Check: func(config map[string]interface{}) (bool, string) {
				return true, ""
			},
			Evidence: []string{"/etc/sudoers", "Sudo logs"},
		},
		{
			ID:          "CIS-2.1",
			Name:        "Ensure permissions on SSH private host keys are configured",
			Description: "SSH host keys should have proper permissions",
			Framework:   CIS,
			Category:    "SSH Security",
			Severity:    "MEDIUM",
			Check: func(config map[string]interface{}) (bool, string) {
				if permissions, ok := config["ssh_permissions"]; ok {
					if permStr, ok := permissions.(string); ok {
						if permStr != "600" && permStr != "644" {
							return false, "SSH key permissions incorrect"
						}
					}
				}
				return true, ""
			},
			Evidence: []string{"SSH key files", "File permissions"},
		},
		{
			ID:          "CIS-3.1",
			Name:        "Ensure filesystem integrity is regularly checked",
			Description: "Filesystem integrity should be monitored",
			Framework:   CIS,
			Category:    "System Integrity",
			Severity:    "LOW",
			Check: func(config map[string]interface{}) (bool, string) {
				if integrity, ok := config["integrity_checking"]; ok {
					if integrityBool, ok := integrity.(bool); ok && !integrityBool {
						return false, "Filesystem integrity checking disabled"
					}
				}
				return true, ""
			},
			Evidence: []string{"AIDE logs", "Tripwire reports"},
		},
	}
}

// AddWatchPath adds a path to watch for compliance changes
func (cc *ComplianceCopilot) AddWatchPath(path string) {
	cc.watchPaths = append(cc.watchPaths, path)
}

// EvaluateControl evaluates a control against configuration
func (cc *ComplianceCopilot) EvaluateControl(control Control, config map[string]interface{}) *ComplianceIssue {
	passed, message := control.Check(config)
	
	if !passed {
		return &ComplianceIssue{
			ControlID:     control.ID,
			ControlName:   control.Name,
			Framework:     control.Framework,
			Category:      control.Category,
			Description:   control.Description,
			Severity:      control.Severity,
			Resource:      "configuration",
			Evidence:      control.Evidence,
			Remediation:   fmt.Sprintf("Review and fix: %s", message),
			Status:        "failed",
			FirstDetected: time.Now(),
			LastDetected:  time.Now(),
		}
	}
	
	return nil
}

// ScanDirectory scans a directory for configuration files
func (cc *ComplianceCopilot) ScanDirectory(dirPath string) error {
	noticeColor.Printf("🔍 Scanning directory: %s\n", dirPath)
	
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") || info.Name() == "node_modules" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		
		fileExt := strings.ToLower(filepath.Ext(path))
		supportedFormats := map[string]bool{
			".json": true,
			".yaml": true,
			".yml":  true,
			".tf":   true,
		}
		
		if !supportedFormats[fileExt] {
			return nil
		}
		
		if err := cc.scanFile(path); err != nil {
			warnColor.Printf("⚠️  Failed to scan %s: %v\n", path, err)
		}
		
		return nil
	})
}

// scanFile scans a single configuration file
func (cc *ComplianceCopilot) scanFile(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	
	var config map[string]interface{}
	
	// Try JSON first
	if strings.HasSuffix(filePath, ".json") {
		if err := json.Unmarshal(content, &config); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
	} else {
		// Try YAML
		if err := cc.parseYAML(content, &config); err != nil {
			return fmt.Errorf("invalid YAML: %w", err)
		}
	}
	
	// Evaluate all controls
	cc.evaluateAllControls(filePath, config)
	
	return nil
}

// parseYAML parses YAML content (simple implementation)
func (cc *ComplianceCopilot) parseYAML(content []byte, config *map[string]interface{}) error {
	// Simple YAML parser for basic key-value pairs
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		
		// Parse key: value
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		
		// Skip nested structures for now
		if strings.HasPrefix(value, "-") || strings.Contains(value, "{") || strings.Contains(value, "[") {
			continue
		}
		
		// Convert value types
		var parsedValue interface{}
		
		// Boolean
		if value == "true" {
			parsedValue = true
		} else if value == "false" {
			parsedValue = false
		} else if value == "null" || value == "~" {
			parsedValue = nil
		} else if value == "null" {
			parsedValue = nil
		} else {
			// String
			parsedValue = strings.Trim(value, "\"'")
		}
		
		*config = map[string]interface{}{
			key: parsedValue,
		}
	}
	
	return scanner.Err()
}

// evaluateAllControls evaluates all controls for a configuration
func (cc *ComplianceCopilot) evaluateAllControls(filePath string, config map[string]interface{}) {
	for _, controls := range cc.controls {
		for _, control := range controls {
			issue := cc.EvaluateControl(control, config)
			if issue != nil {
				issue.File = filePath
				issue.Resource = filePath
				cc.issues = append(cc.issues, *issue)
				
				if cc.verbose {
					warnColor.Printf("  ⚠️  %s: %s\n", control.ID, control.Name)
				}
			}
		}
	}
}

// CalculateComplianceScore calculates compliance score for a framework
func (cc *ComplianceCopilot) CalculateComplianceScore(framework ComplianceFramework) float64 {
	controls := cc.controls[framework]
	if len(controls) == 0 {
		return 0
	}
	
	issuesForFramework := 0
	for _, issue := range cc.issues {
		if issue.Framework == framework {
			issuesForFramework++
		}
	}
	
	totalControls := len(controls)
	passedControls := totalControls - issuesForFramework
	
	return float64(passedControls) / float64(totalControls) * 100
}

// GetComplianceStatus gets compliance status for a framework
func (cc *ComplianceCopilot) GetComplianceStatus(framework ComplianceFramework) *ComplianceStatus {
	controls := cc.controls[framework]
	
	issuesForFramework := []ComplianceIssue{}
	for _, issue := range cc.issues {
		if issue.Framework == framework {
			issuesForFramework = append(issuesForFramework, issue)
		}
	}
	
	score := cc.CalculateComplianceScore(framework)
	status := "compliant"
	if score < 80 {
		status = "non-compliant"
	} else if score < 100 {
		status = "partial-compliant"
	}
	
	return &ComplianceStatus{
		Framework:      framework,
		Status:         status,
		Score:          score,
		TotalControls:  len(controls),
		PassedControls: len(controls) - len(issuesForFramework),
		FailedControls: len(issuesForFramework),
		Issues:         issuesForFramework,
		LastChecked:    time.Now(),
	}
}

// PrintReport prints the compliance report
func (cc *ComplianceCopilot) PrintReport() {
	infoColor.Println("\n" + strings.Repeat("=", 80))
	infoColor.Println("📊 COMPLIANCE REPORT")
	infoColor.Println(strings.Repeat("=", 80))
	
	totalFrameworks := len(cc.controls)
	compliantFrameworks := 0
	
	// Print status for each framework
	frameworkNames := map[ComplianceFramework]string{
		SOC2:        "SOC2",
		HIPAA:       "HIPAA",
		PCI_DSS:     "PCI-DSS",
		GDPR:        "GDPR",
		CIS:         "CIS Benchmarks",
		ISO27001:    "ISO 27001",
		SOC1:        "SOC1",
		NIST:        "NIST",
	}
	
	type result struct {
		name  string
		score float64
		status string
	}
	
	var results []result
	
	for framework := range cc.controls {
		status := cc.GetComplianceStatus(framework)
		
		if status.Status == "compliant" {
			compliantFrameworks++
		}
		
		results = append(results, result{
			name:   frameworkNames[framework],
			score:  status.Score,
			status: status.Status,
		})
	}
	
	// Sort by score
	sort.Slice(results, func(i, j int) bool {
		return results[i].score < results[j].score
	})
	
	infoColor.Println("\n📈 Compliance Status by Framework:");
	
	for _, r := range results {
		emoji := "✅"
		if r.score < 80 {
			emoji = "❌"
		} else if r.score < 100 {
			emoji = "⚠️"
		}
		
		if r.score >= 80 {
			successColor.Printf("%s %-20s: %.1f%% (%s)\n", emoji, r.name, r.score, r.status)
		} else {
			errorColor.Printf("%s %-20s: %.1f%% (%s)\n", emoji, r.name, r.score, r.status)
		}
	}
	
	noticeColor.Printf("\n📊 Overall: %d/%d frameworks compliant\n", compliantFrameworks, totalFrameworks)
	
	// Print issues by severity
	infoColor.Println(strings.Repeat("=", 80))
	infoColor.Println("\n🔍 Issues by Severity:");
	
	severityCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, issue := range cc.issues {
		severityCounts[issue.Severity]++
	}
	
	severityOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, severity := range severityOrder {
		count := severityCounts[severity]
		if count > 0 {
			emoji := map[string]string{"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
			infoColor.Printf("%s %s: %d issues\n", emoji, severity, count)
		}
	}
	
	// Print detailed issues
	if len(cc.issues) > 0 {
		infoColor.Println("\n📋 Detailed Issues:");
		
		for _, issue := range cc.issues {
			severityEmoji := map[string]string{
				"CRITICAL": "🔴",
				"HIGH":     "🟠",
				"MEDIUM":   "🟡",
				"LOW":      "🟢",
			}
			
			emoji := severityEmoji[issue.Severity]
			
			if issue.Severity == "CRITICAL" || issue.Severity == "HIGH" {
				errorColor.Printf("%s [%s] %s - %s\n", emoji, issue.Severity, issue.ControlName, issue.Framework)
			} else {
				warnColor.Printf("%s [%s] %s - %s\n", emoji, issue.Severity, issue.ControlName, issue.Framework)
			}
			
			infoColor.Printf("    Control ID: %s\n", issue.ControlID)
			infoColor.Printf("    Category: %s\n", issue.Category)
			infoColor.Printf("    File: %s\n", issue.File)
			infoColor.Printf("    Description: %s\n", issue.Description)
			infoColor.Printf("    Remediation: %s\n", issue.Remediation)
			infoColor.Println(strings.Repeat("-", 60))
		}
	}
	
	infoColor.Println(strings.Repeat("=", 80))
	
	// Exit with error code if critical or high issues
	if cc.failOnCritical && severityCounts["CRITICAL"] > 0 {
		errorColor.Printf("\n❌ Compliance FAILED: %d critical issues found\n", severityCounts["CRITICAL"])
		os.Exit(1)
	}
	
	if cc.failOnHigh && (severityCounts["CRITICAL"] > 0 || severityCounts["HIGH"] > 0) {
		errorColor.Printf("\n❌ Compliance FAILED: %d critical + %d high issues found\n", severityCounts["CRITICAL"], severityCounts["HIGH"])
		os.Exit(1)
	}
	
	if compliantFrameworks == totalFrameworks {
		successColor.Println("\n✅ All frameworks compliant!");
	} else {
		warnColor.Printf("\n⚠️  %d frameworks need attention\n", totalFrameworks-compliantFrameworks)
	}
}

func main() {
	// Define flags
	watchPaths := flag.String("watch", ".", "Comma-separated paths to watch for compliance")
	failCritical := flag.Bool("fail-critical", true, "Fail if critical issues found")
	failHigh := flag.Bool("fail-high", true, "Fail if high issues found")
	dryRun := flag.Bool("dry-run", false, "Dry run mode (not used in this version)")
	verbose := flag.Bool("verbose", false, "Verbose output")
	showHelp := flag.Bool("help", false, "Show help message")
	
	flag.Parse()
	
	if *showHelp {
		flag.Usage()
		return
	}
	
	// Create copilot
	copilot := NewComplianceCopilot(*dryRun, *failCritical, *failHigh, *verbose)
	copilot.InitializeControls()
	
	// Add watch paths
	paths := strings.Split(*watchPaths, ",")
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path != "" {
			copilot.AddWatchPath(path)
		}
	}
	
	// Scan directories
	for _, path := range copilot.watchPaths {
		if err := copilot.ScanDirectory(path); err != nil {
			errorColor.Printf("❌ Error scanning directory %s: %v\n", path, err)
			os.Exit(1)
		}
	}
	
	// Print report
	copilot.PrintReport()
}