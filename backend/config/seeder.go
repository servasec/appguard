package config

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"

	"github.com/casbin/casbin/v2"
	"github.com/servasec/servasec/backend/debug"
	"github.com/servasec/servasec/backend/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func generateRandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func getAdminPassword() string {
	if pwd := os.Getenv("SSC_ADMIN_PASSWORD"); pwd != "" {
		return pwd
	}
	if os.Getenv("SSC_DEBUG_ENABLED") != "true" {
		log.Fatal("SSC_ADMIN_PASSWORD must be set in production")
	}
	randomPwd, err := generateRandomHex(16)
	if err != nil {
		log.Fatalf("CRITICAL: Failed to generate random admin password: %v. refusing to fall back to hardcoded password.", err)
	}

	log.Printf("========================================")
	log.Printf("  ADMIN PASSWORD: %s", randomPwd)
	log.Printf("  Set SSC_ADMIN_PASSWORD env var to disable random generation")
	log.Printf("========================================")
	return randomPwd
}

func seedDefaultUsers() {
	adminPassword := getAdminPassword()

	users := []models.User{
		{Username: "admin", Email: "admin@servasec.local", Password: adminPassword, Role: "admin"},
	}

	for _, user := range users {
		var existing models.User
		err := DB.Where("username = ? OR email = ?", user.Username, user.Email).First(&existing).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			debug.Log("Failed to check user %s: %v\n", user.Username, err)
			continue
		}
		if err == nil {
			continue
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			debug.Log("Failed to hash password for user %s: %v\n", user.Username, err)
			continue
		}
		user.Password = string(hashedPassword)
		if err := DB.Create(&user).Error; err != nil {
			debug.Log("Failed to seed user %s: %v\n", user.Username, err)
		}
	}
	debug.Println("Seeding: users finished")
}

func SeedCasbinFromCsv(enforcer *casbin.Enforcer) {
	debug.Println("Seeding: Casbin rules from CSV..")
	csvEnforcer, err := casbin.NewEnforcer("config/casbin_model.conf", "config/casbin_policies.csv")
	if err != nil {
		debug.Println(err.Error())
		return
	}
	csvEnforcer.LoadPolicy()
	csvPolicies, err := csvEnforcer.GetPolicy()
	if err != nil {
		debug.Log("Failed to get CSV policies: %v", err)
		return
	}

	added := 0
	for _, p := range csvPolicies {
		if len(p) >= 3 {
			ok, _ := enforcer.AddPolicy(p[0], p[1], p[2])
			if ok {
				added++
			}
		}
	}

	if added > 0 {
		if err := enforcer.SavePolicy(); err != nil {
			debug.Log("Failed to save casbin policies: %v", err)
			return
		}
	}
	debug.Log("Seeding: Casbin from CSV finished (%d new policies)", added)
}

func seedScannerTypes() {
	scannerTypes := []models.ScannerType{
		{Name: "semgrep", Description: "Semgrep SAST (SARIF/JSON)", Parser: "semgrep", Enabled: true},
		{Name: "trivy", Description: "Trivy vulnerability scanner (SARIF/JSON)", Parser: "trivy", Enabled: true},
		{Name: "gitleaks", Description: "Gitleaks secret detection (JSON)", Parser: "gitleaks", Enabled: true},
		{Name: "grype", Description: "Grype vulnerability scanner (JSON)", Parser: "grype", Enabled: true},
		{Name: "snyk", Description: "Snyk (SARIF/JSON)", Parser: "snyk", Enabled: true},
		{Name: "checkov", Description: "Checkov IaC scan (SARIF)", Parser: "checkov", Enabled: true},
		{Name: "trufflehog", Description: "TruffleHog secret detection (JSON)", Parser: "trufflehog", Enabled: true},
		{Name: "nuclei", Description: "Nuclei DAST/template scanner (JSON/JSONL)", Parser: "nuclei", Enabled: true},
		{Name: "sarif", Description: "Generic SARIF v2.1.0 parser (fallback for unknown tools)", Parser: "sarif", Enabled: true},
		{Name: "gosec", Description: "Gosec Go SAST (JSON)", Parser: "gosec", Enabled: true},
		{Name: "bandit", Description: "Bandit Python SAST (JSON)", Parser: "bandit", Enabled: true},
		{Name: "osv-scanner", Description: "OSV-Scanner SCA (JSON)", Parser: "osv-scanner", Enabled: true},
		{Name: "npm-audit", Description: "NPM Audit SCA (JSON)", Parser: "npm-audit", Enabled: true},
		{Name: "tfsec", Description: "Tfsec Terraform IaC (JSON)", Parser: "tfsec", Enabled: true},
		{Name: "kubescape", Description: "Kubescape Kubernetes CSPM (JSON)", Parser: "kubescape", Enabled: true},
		{Name: "kube-bench", Description: "Kube-bench CIS Kubernetes (JSON)", Parser: "kube-bench", Enabled: true},
		{Name: "pip-audit", Description: "pip-audit Python SCA (JSON)", Parser: "pip-audit", Enabled: true},
		{Name: "govulncheck", Description: "Govulncheck Go SCA (JSON)", Parser: "govulncheck", Enabled: true},
		{Name: "terrascan", Description: "Terrascan IaC (JSON)", Parser: "terrascan", Enabled: true},
		{Name: "docker-bench-security", Description: "Docker-bench-security CIS Docker (JSON)", Parser: "docker-bench-security", Enabled: true},
		{Name: "kube-linter", Description: "Kube-linter Kubernetes lint (JSON)", Parser: "kube-linter", Enabled: true},
		{Name: "detect-secrets", Description: "Detect-secrets secret detection (JSON)", Parser: "detect-secrets", Enabled: true},
		{Name: "flawfinder", Description: "Flawfinder C/C++ SAST (JSON)", Parser: "flawfinder", Enabled: true},
		{Name: "dockle", Description: "Dockle container image lint (JSON)", Parser: "dockle", Enabled: true},
		{Name: "horusec", Description: "Horusec SAST (JSON)", Parser: "horusec", Enabled: true},
		{Name: "yarn-audit", Description: "Yarn Audit SCA (JSONL)", Parser: "yarn-audit", Enabled: true},
		{Name: "pnpm-audit", Description: "pnpm Audit SCA (JSON)", Parser: "pnpm-audit", Enabled: true},
		{Name: "cargo-audit", Description: "Cargo audit Rust SCA (JSON)", Parser: "cargo-audit", Enabled: true},
		{Name: "composer-audit", Description: "Composer audit PHP SCA (JSON)", Parser: "composer-audit", Enabled: true},
		{Name: "njsscan", Description: "njsscan Node.js SAST (JSON)", Parser: "njsscan", Enabled: true},
		{Name: "pmd", Description: "PMD Java SAST (JSON)", Parser: "pmd", Enabled: true},
		{Name: "cppcheck", Description: "Cppcheck C/C++ SAST (JSONL)", Parser: "cppcheck", Enabled: true},
		{Name: "cfn-nag", Description: "cfn-nag CloudFormation IaC (JSON)", Parser: "cfn-nag", Enabled: true},

		{Name: "nmap", Description: "Nmap network scanner (XML/JSON)", Parser: "nmap", Enabled: true},

		{Name: "nikto", Description: "Nikto web server scanner (JSON)", Parser: "nikto", Enabled: true},

		{Name: "naabu", Description: "Naabu port scanner (JSON)", Parser: "naabu", Enabled: true},

		{Name: "httpx", Description: "httpx web probing (JSONL)", Parser: "httpx", Enabled: true},

		{Name: "wpscan", Description: "WPScan WordPress scanner (JSON)", Parser: "wpscan", Enabled: true},

		{Name: "sslyze", Description: "SSLyze TLS/SSL scanner (JSON)", Parser: "sslyze", Enabled: true},

		{Name: "testssl", Description: "testssl.sh TLS/SSL scanner (JSONL)", Parser: "testssl", Enabled: true},

		{Name: "ffuf", Description: "ffuf web fuzzer (JSONL)", Parser: "ffuf", Enabled: true},

		{Name: "dirsearch", Description: "dirsearch web path scanner (JSONL)", Parser: "dirsearch", Enabled: true},

		{Name: "popeye", Description: "Popeye Kubernetes sanitizer (JSON)", Parser: "popeye", Enabled: true},

		{Name: "kubeaudit", Description: "Kubeaudit Kubernetes audit (JSON)", Parser: "kubeaudit", Enabled: true},

		{Name: "trivy-operator", Description: "Trivy Operator Kubernetes reports (JSON)", Parser: "trivy-operator", Enabled: true},

		{Name: "scoutsuite", Description: "Scout Suite cloud security audit (JSON)", Parser: "scoutsuite", Enabled: true},

		{Name: "prowler", Description: "Prowler cloud security assessment (JSON)", Parser: "prowler", Enabled: true},

		{Name: "secretlint", Description: "Secretlint secret detection (JSON)", Parser: "secretlint", Enabled: true},

		{Name: "noseyparker", Description: "Nosey Parker secret detection (JSON)", Parser: "noseyparker", Enabled: true},

		{Name: "kics", Description: "KICS IaC security scanning (JSON)", Parser: "kics", Enabled: true},
	}

	for _, st := range scannerTypes {
		var existing models.ScannerType
		err := DB.Where("name = ?", st.Name).First(&existing).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			debug.Log("Failed to check scanner type %s: %v\n", st.Name, err)
			continue
		}
		if err == nil {
			if !existing.Enabled {
				existing.Enabled = true
				DB.Save(&existing)
			}
			continue
		}
		if err := DB.Create(&st).Error; err != nil {
			debug.Log("Failed to seed scanner type %s: %v\n", st.Name, err)
		}
	}
	debug.Println("Seeding: scanner types finished")
}

func SeedDatabase() {
	debug.Println("Seeding: Database..")
	seedDefaultUsers()
	seedScannerTypes()
}
