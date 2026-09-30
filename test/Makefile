.PHONY: all build-target build-scanners scan scan-network update-fixtures clean help

TEST_TARGETS_DIR ?= ../../servasec-test-targets
PARSER_TESTDATA  := ../backend/parsers/testdata
SCAN_TARGET_HOST ?= localhost

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

all: build-target build-scanners scan ## Build everything + run all scanners
	@echo "Run 'make update-fixtures' to copy reports to parser testdata"

build-target: ## Build the vulnerable test target image
	docker build -t servasec-test-target $(TEST_TARGETS_DIR)
	@echo "Saving image as tar..."
	docker save servasec-test-target -o /tmp/servasec-test-target.tar

build-scanners: ## Build the scanner tools image
	docker build -t servasec-scanners -f Dockerfile.scanners .

scan: build-target build-scanners ## Run all scanners against the test target
	@echo "Running scanners..."
	docker run --rm \
		-v /tmp/servasec-test-target.tar:/target/image.tar:ro \
		-v $(TEST_TARGETS_DIR):/target/files:ro \
		-v $(PWD)/reports:/reports \
		servasec-scanners
	@echo ""
	@echo "Reports generated in test/reports/"

scan-network: build-scanners ## Run DAST/network scanners against a live host (SCAN_TARGET_HOST)
	@echo "Running network scanners against $(SCAN_TARGET_HOST)..."
	docker run --rm \
		-e SCAN_TARGET_HOST=$(SCAN_TARGET_HOST) \
		-e SCAN_TARGET_SSL=1 \
		-v $(PWD)/reports:/reports \
		servasec-scanners
	@echo ""
	@echo "Network reports generated in test/reports/"

update-fixtures: scan ## Copy scanner reports to parser testdata
	@mkdir -p $(PARSER_TESTDATA)
	cp reports/grype.json $(PARSER_TESTDATA)/grype_real.json
	cp reports/trivy.json $(PARSER_TESTDATA)/trivy_real.json
	cp reports/trivy-iac.json $(PARSER_TESTDATA)/trivy_iac_real.json
	cp reports/bandit.json $(PARSER_TESTDATA)/bandit_real.json
	cp reports/gosec.json $(PARSER_TESTDATA)/gosec_real.json
	cp reports/govulncheck.json $(PARSER_TESTDATA)/govulncheck_real.json
	cp reports/checkov.json $(PARSER_TESTDATA)/checkov_real.json
	cp reports/tfsec.json $(PARSER_TESTDATA)/tfsec_real.json
	cp reports/terrascan.json $(PARSER_TESTDATA)/terrascan_real.json
	cp reports/kics.json $(PARSER_TESTDATA)/kics_real.json
	cp reports/cfn-nag.json $(PARSER_TESTDATA)/cfn_nag_real.json
	cp reports/kubeaudit.json $(PARSER_TESTDATA)/kubeaudit_real.json
	cp reports/kube-linter.json $(PARSER_TESTDATA)/kube_linter_real.json
	cp reports/kubescape.json $(PARSER_TESTDATA)/kubescape_real.json
	cp reports/kube-bench.json $(PARSER_TESTDATA)/kube_bench_real.json
	cp reports/popeye.json $(PARSER_TESTDATA)/popeye_real.json
	cp reports/docker-bench-security.json $(PARSER_TESTDATA)/docker_bench_security_real.json
	cp reports/trivy-operator.json $(PARSER_TESTDATA)/trivy_operator_real.json
	cp reports/gitleaks.json $(PARSER_TESTDATA)/gitleaks_real.json
	cp reports/detect-secrets.json $(PARSER_TESTDATA)/detect_secrets_real.json
	cp reports/secretlint.json $(PARSER_TESTDATA)/secretlint_real.json
	cp reports/trufflehog.json $(PARSER_TESTDATA)/trufflehog_real.json
	cp reports/noseyparker.json $(PARSER_TESTDATA)/noseyparker_real.json
	cp reports/osv-scanner.json $(PARSER_TESTDATA)/osv-scanner_real.json
	cp reports/npm-audit.json $(PARSER_TESTDATA)/npm_audit_real.json
	cp reports/yarn-audit.json $(PARSER_TESTDATA)/yarn_audit_real.json
	cp reports/pnpm-audit.json $(PARSER_TESTDATA)/pnpm_audit_real.json
	cp reports/pip-audit.json $(PARSER_TESTDATA)/pip_audit_real.json
	cp reports/cargo-audit.json $(PARSER_TESTDATA)/cargo_audit_real.json
	cp reports/composer-audit.json $(PARSER_TESTDATA)/composer_audit_real.json
	cp reports/snyk.json $(PARSER_TESTDATA)/snyk_real.json
	cp reports/semgrep.json $(PARSER_TESTDATA)/semgrep_real.json
	cp reports/sarif.json $(PARSER_TESTDATA)/sarif_real.json
	cp reports/horusec.json $(PARSER_TESTDATA)/horusec_real.json
	cp reports/njsscan.json $(PARSER_TESTDATA)/njsscan_real.json
	cp reports/pmd.json $(PARSER_TESTDATA)/pmd_real.json
	cp reports/cppcheck.json $(PARSER_TESTDATA)/cppcheck_real.json
	cp reports/flawfinder.json $(PARSER_TESTDATA)/flawfinder_real.json
	cp reports/dockle.json $(PARSER_TESTDATA)/dockle_real.json
	cp reports/prowler.json $(PARSER_TESTDATA)/prowler_real.json
	cp reports/scoutsuite.json $(PARSER_TESTDATA)/scoutsuite_real.json
	cp reports/wpscan.json $(PARSER_TESTDATA)/wpscan_real.json
	cp reports/nmap.json $(PARSER_TESTDATA)/nmap_real.json
	cp reports/nikto.json $(PARSER_TESTDATA)/nikto_real.json
	cp reports/naabu.json $(PARSER_TESTDATA)/naabu_real.json
	cp reports/httpx.json $(PARSER_TESTDATA)/httpx_real.json
	cp reports/sslyze.json $(PARSER_TESTDATA)/sslyze_real.json
	cp reports/testssl.json $(PARSER_TESTDATA)/testssl_real.json
	cp reports/ffuf.json $(PARSER_TESTDATA)/ffuf_real.json
	cp reports/dirsearch.json $(PARSER_TESTDATA)/dirsearch_real.json
	cp reports/nuclei.json $(PARSER_TESTDATA)/nuclei_real.json
	@echo "Fixtures updated in $(PARSER_TESTDATA)/"
	@echo "Add test functions in your *_test.go files to parse these."

clean: ## Remove generated reports and temp files
	rm -f /tmp/servasec-test-target.tar
	rm -rf reports/*.json
	docker rmi servasec-test-target 2>/dev/null || true
	docker rmi servasec-scanners 2>/dev/null || true