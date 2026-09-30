#!/usr/bin/env bash
set -uo pipefail

REPORTS_DIR="/reports"
TARGET_DIR="/target/files"
TARGET_IMAGE="/target/image.tar"
TARGET_HOST="${SCAN_TARGET_HOST:-}"

mkdir -p "$REPORTS_DIR"

echo "=== servasec scanner fixture generator ==="
echo ""

# --- Container scanners ---
if [ -f "$TARGET_IMAGE" ]; then
    echo "[scanning] grype (container image)..."
    grype docker-archive:"$TARGET_IMAGE" -o json > "$REPORTS_DIR/grype.json" 2>/dev/null \
        || echo '{"matches":[]}' > "$REPORTS_DIR/grype.json"
    echo "  → OK"

    echo "[scanning] trivy (container image)..."
    trivy image --input "$TARGET_IMAGE" --format json > "$REPORTS_DIR/trivy.json" 2>/dev/null \
        || echo '{"Results":[]}' > "$REPORTS_DIR/trivy.json"
    echo "  → OK"

    echo "[scanning] dockle (container image)..."
    dockle --format json "$TARGET_IMAGE" > "$REPORTS_DIR/dockle.json" 2>/dev/null \
        || echo '{"results":[]}' > "$REPORTS_DIR/dockle.json"
    echo "  → OK"
else
    echo "[skip] grype, trivy, dockle (no image.tar)"
    echo '{"matches":[]}' > "$REPORTS_DIR/grype.json"
    echo '{"Results":[]}' > "$REPORTS_DIR/trivy.json"
    echo '{"results":[]}' > "$REPORTS_DIR/dockle.json"
fi

# --- IaC / filesystem container scan ---
echo "[scanning] trivy-iac..."
trivy config --format json "$TARGET_DIR" > "$REPORTS_DIR/trivy-iac.json" 2>/dev/null \
    || echo '{"Results":[]}' > "$REPORTS_DIR/trivy-iac.json"
echo "  → OK"

# --- Python SAST ---
# bandit exits 1 when findings exist - only treat >1 as failure
echo "[scanning] bandit..."
bandit_exit=0
bandit -r "$TARGET_DIR" -f json > "$REPORTS_DIR/bandit.json" 2>/dev/null || bandit_exit=$?
if [ "$bandit_exit" -le 1 ]; then
    echo "  → OK (exit $bandit_exit)"
else
    echo '{"results":[]}' > "$REPORTS_DIR/bandit.json"
    echo "  → fallback (exit $bandit_exit)"
fi

# --- Go SAST / vuln scanning ---
echo "[scanning] gosec..."
gosec_exit=0
if find "$TARGET_DIR" -name '*.go' -print -quit 2>/dev/null | grep -q .; then
    # gosec exits 1 when findings exist; only treat >1 as failure and keep the report
    gosec -fmt=json -out="$REPORTS_DIR/gosec.json" "$TARGET_DIR" 2>/dev/null \
        || gosec_exit=$?
    [ "$gosec_exit" -le 1 ] && [ -s "$REPORTS_DIR/gosec.json" ] \
        || echo '{"Issues":[]}' > "$REPORTS_DIR/gosec.json"
else
    echo '{"Issues":[]}' > "$REPORTS_DIR/gosec.json"
fi
echo "  → OK"

echo "[scanning] govulncheck..."
# govulncheck -json emits JSONL; parser expects {"vulns":[...]} so merge lines
govulncheck_exit=0
if [ -f "$TARGET_DIR/go.mod" ]; then
    (cd "$TARGET_DIR" && govulncheck -json ./... 2>/dev/null \
        | jq -s '{vulns: [.[] | select(.osv != null) | {osv: {id: .osv, summary: (.osv // "")}, aliases: (.aliases // []), modules: (.modules // [])}]}') \
        > "$REPORTS_DIR/govulncheck.json" || govulncheck_exit=$?
    # govulncheck exits 1 when findings exist - only treat >1 as failure
    [ "$govulncheck_exit" -le 1 ] && [ -s "$REPORTS_DIR/govulncheck.json" ] \
        || echo '{"vulns":[]}' > "$REPORTS_DIR/govulncheck.json"
else
    echo '{"vulns":[]}' > "$REPORTS_DIR/govulncheck.json"
fi
echo "  → OK"

# --- IaC scanners ---
# checkov: use --output json (not -o), --compact to reduce verbosity
echo "[scanning] checkov..."
# checkov exits 1 when findings exist. --output json emits ONE object per
# check_type; flatten them into the {"results":{"failed_checks":[...]}}
# shape the parser expects.
checkov_exit=0
checkov -d "$TARGET_DIR" --output json --compact 2>/dev/null \
    > "$REPORTS_DIR/checkov.raw.json" || checkov_exit=$?
if [ "$checkov_exit" -le 1 ] && [ -s "$REPORTS_DIR/checkov.raw.json" ]; then
    jq 'if type == "array" then . else [.] end
        | {results: {failed_checks: [.[].results.failed_checks[]? | {
            check_id: .check_id,
            file_path: .file_path,
            file_line_range: .file_line_range,
            resource: .resource,
            check: {id: .check_id, name: .check_name,
                    description: (.description // ""),
                    severity: (.severity // "")}}]}}' \
        "$REPORTS_DIR/checkov.raw.json" > "$REPORTS_DIR/checkov.json"
    rm -f "$REPORTS_DIR/checkov.raw.json"
else
    rm -f "$REPORTS_DIR/checkov.raw.json"
    echo '{"results":{"failed_checks":[]}}' > "$REPORTS_DIR/checkov.json"
fi
echo "  → OK"

# tfsec: --format json may not exist in all versions; capture stdout
echo "[scanning] tfsec..."
# tfsec 1.x exits 1 when findings exist; its JSON is {"results":[...]} (flat),
# parser expects {"results":{"failed":[...]}}.
tfsec_exit=0
tfsec "$TARGET_DIR" --format json 2>/dev/null \
    > "$REPORTS_DIR/tfsec.raw.json" || tfsec_exit=$?
if [ "$tfsec_exit" -le 1 ] && [ -s "$REPORTS_DIR/tfsec.raw.json" ]; then
    jq '{results:{failed:[.results[]? | {rule_id, severity, description,
        resolution:(.resolution // ""),
        location:{filename:.location.filename, start_line:.location.start_line,
                  end_line:.location.end_line}}]}}' \
        "$REPORTS_DIR/tfsec.raw.json" > "$REPORTS_DIR/tfsec.json"
    rm -f "$REPORTS_DIR/tfsec.raw.json"
else
    rm -f "$REPORTS_DIR/tfsec.raw.json"
    echo '{"results":{"passed":[],"failed":[]}}' > "$REPORTS_DIR/tfsec.json"
fi
echo "  → OK"

echo "[scanning] terrascan..."
# terrascan's output mode is the GLOBAL -o/--output flag (there is no --format
# on `scan`); violations yield a nonzero exit but the JSON is a valid
# {"results":{"violations":[...]}} that the parser reads natively.
terrascan scan -d "$TARGET_DIR" --output json 2>/dev/null \
    > "$REPORTS_DIR/terrascan.json" || true
[ -s "$REPORTS_DIR/terrascan.json" ] \
    || echo '{"results":{"violations":[]}}' > "$REPORTS_DIR/terrascan.json"
echo "  → OK"

echo "[scanning] kics..."
# kics v2 flags come from scan-flags.json: -p/--path, -o/--output-path,
# --output-name (default "results"), --report-formats (default json). The
# verbose shorthand -i does not exist. --ignore-on-exit results makes the
# exit 0 when results are found so the JSON is not overwritten.
rm -f "$REPORTS_DIR/kics.json" "$REPORTS_DIR/results.json"
kics scan -p "$TARGET_DIR" --output-path "$REPORTS_DIR" --output-name kics \
        --report-formats json --ignore-on-exit results \
        >/dev/null 2>&1 || true
[ -s "$REPORTS_DIR/kics.json" ] \
    || mv "$REPORTS_DIR/results.json" "$REPORTS_DIR/kics.json" 2>/dev/null
[ -s "$REPORTS_DIR/kics.json" ] \
    || echo '{"queries":[]}' > "$REPORTS_DIR/kics.json"
echo "  → OK"

echo "[scanning] cfn-nag..."
# cfn-nag emits an array of {filename, violations[]}; parser expects {"messages":[...]}
cfn_nag_scan --input-path "$TARGET_DIR" --output-format json 2>/dev/null \
    | jq '{messages: [.[] | .violations[]? | {type, level: .type, id, message, logicalResourceId: (.logical_resource_ids[0] // null), filepath: .filename, lineNumber: null}]}' \
    > "$REPORTS_DIR/cfn-nag.json" \
    || echo '{"messages":[]}' > "$REPORTS_DIR/cfn-nag.json"
echo "  → OK"

# --- Kubernetes: manifest scanning ---
echo "[scanning] kubeaudit..."
if [ -f "$TARGET_DIR/deployment.yaml" ]; then
    # kubeaudit emits one JSON object per line (JSONL) on stdout and exits
    # nonzero when findings exist. Parser expects {"kubeaudit":[{auditResult}]}.
    kubeaudit all -f "$TARGET_DIR/deployment.yaml" --format json \
        2>/dev/null > "$REPORTS_DIR/kubeaudit.raw.json" || true
    if [ -s "$REPORTS_DIR/kubeaudit.raw.json" ]; then
        jq -s '{kubeaudit: [.[] | {auditResult: {
            levelname: .level,
            msg: .msg,
            resource: {name: .ResourceName, namespace: .ResourceNamespace,
                       kind: .ResourceKind},
            metadata: {container: .Container}
        }}]}' "$REPORTS_DIR/kubeaudit.raw.json" \
            > "$REPORTS_DIR/kubeaudit.json"
    else
        echo '{"kubeaudit":[]}' > "$REPORTS_DIR/kubeaudit.json"
    fi
    rm -f "$REPORTS_DIR/kubeaudit.raw.json"
else
    echo '{"kubeaudit":[]}' > "$REPORTS_DIR/kubeaudit.json"
fi
echo "  → OK"

echo "[scanning] kube-linter..."
# kube-linter emits {"Reports":[{Check,Diagnostic:{Message},Object:{Metadata:{FilePath}}}]}
# and exits 1 when findings exist; parser expects {"results":[{diagnosticMessage,object}]}.
kube_linter_exit=0
if [ -f "$TARGET_DIR/deployment.yaml" ]; then
    kube-linter lint "$TARGET_DIR/deployment.yaml" --format json 2>/dev/null \
        > "$REPORTS_DIR/kube-linter.raw.json" || kube_linter_exit=$?
    if [ "$kube_linter_exit" -le 1 ] && [ -s "$REPORTS_DIR/kube-linter.raw.json" ]; then
        jq '{results: [.Reports[]? | {
            diagnosticMessage: ((.Check // "kube-linter") + ": " + (.Diagnostic.Message // "")),
            object: {filePath: (.Object.Metadata.FilePath // null)}
        }]}' "$REPORTS_DIR/kube-linter.raw.json" > "$REPORTS_DIR/kube-linter.json"
    else
        echo '{"results":[]}' > "$REPORTS_DIR/kube-linter.json"
    fi
    rm -f "$REPORTS_DIR/kube-linter.raw.json"
else
    echo '{"results":[]}' > "$REPORTS_DIR/kube-linter.json"
fi
echo "  → OK"

# --- Kubernetes: runtime scanners (need a live cluster) ---
echo "[skip] kubescape, kube-bench, popeye (runtime scanners; generate fixture manually)"
echo '{"results":[]}' > "$REPORTS_DIR/kubescape.json"
echo '{"controls":[]}' > "$REPORTS_DIR/kube-bench.json"
echo '{"popeye":{"sanitized":{"code":[]}}}' > "$REPORTS_DIR/popeye.json"

echo "[skip] docker-bench-security (needs docker daemon access; generate fixture manually)"
echo '[]' > "$REPORTS_DIR/docker-bench-security.json"

echo "[skip] trivy-operator (needs a cluster; fixture from a CRD/spec JSON)"
echo '{"spec":{"results":[]}}' > "$REPORTS_DIR/trivy-operator.json"

# --- Secret scanners ---
# gitleaks: dir subcommand needs --report-path for file output
echo "[scanning] gitleaks..."
gitleaks dir "$TARGET_DIR" --report-format json --report-path "$REPORTS_DIR/gitleaks.json" --no-banner 2>/dev/null \
    || [ -f "$REPORTS_DIR/gitleaks.json" ] \
    || echo '[]' > "$REPORTS_DIR/gitleaks.json"
echo "  → OK"

echo "[scanning] detect-secrets..."
detect_secrets_exit=0
(cd "$TARGET_DIR" && detect-secrets scan . 2>/dev/null) > "$REPORTS_DIR/detect-secrets.json" || detect_secrets_exit=$?
[ "$detect_secrets_exit" -le 1 ] && [ -s "$REPORTS_DIR/detect-secrets.json" ] \
    || echo '{"results":{}}' > "$REPORTS_DIR/detect-secrets.json"
echo "  → OK"

echo "[scanning] secretlint..."
# secretlint emits a per-file array [{filePath, messages:[{message,loc,ruleId,...}]}];
# parser expects {"messages":[{message,filePath,line,column,ruleId}]}. `filePath`
# lives on the outer result, not the message, so bind it before descending.
secretlint_exit=0
if [ -f "$TARGET_DIR/.secretlintrc.json" ]; then
    (cd "$TARGET_DIR" \
        && secretlint --format json "**/*" 2>/dev/null \
            | jq '{messages: [.[] | .filePath as $fp | .messages[]? | {message: .message, filePath: $fp, line: (.loc.start.line // 0), column: (.loc.start.column // 0), ruleId: .ruleId}]}') \
        > "$REPORTS_DIR/secretlint.json" || secretlint_exit=$?
    # secretlint exits 1 when findings exist - only treat >1 as failure
    [ "$secretlint_exit" -le 1 ] && [ -s "$REPORTS_DIR/secretlint.json" ] \
        || echo '{"messages":[]}' > "$REPORTS_DIR/secretlint.json"
else
    echo '{"messages":[]}' > "$REPORTS_DIR/secretlint.json"
fi
echo "  → OK"

echo "[scanning] trufflehog..."
trufflehog filesystem --json "$TARGET_DIR" 2>/dev/null \
    > "$REPORTS_DIR/trufflehog.json" \
    || echo '[]' > "$REPORTS_DIR/trufflehog.json"
# trufflehog can exit 0 with empty output; parser rejects an empty file
[ -s "$REPORTS_DIR/trufflehog.json" ] || echo '[]' > "$REPORTS_DIR/trufflehog.json"
echo "  → OK"

echo "[skip] noseyparker (release binary not bundled; generate fixture manually)"
echo '{"metadata":{},"matches":[]}' > "$REPORTS_DIR/noseyparker.json"

# --- Dependency scanners ---
echo "[scanning] osv-scanner..."
OSVArgs=()
if [ -f "$TARGET_DIR/package-lock.json" ]; then
    OSVArgs+=(--lockfile "$TARGET_DIR/package-lock.json")
fi
if [ -f "$TARGET_DIR/requirements.txt" ]; then
    OSVArgs+=(--lockfile "$TARGET_DIR/requirements.txt")
fi
if [ -f "$TARGET_DIR/Cargo.lock" ]; then
    OSVArgs+=(--lockfile "$TARGET_DIR/Cargo.lock")
fi
if [ ${#OSVArgs[@]} -gt 0 ]; then
    # osv-scanner exits 1 when vulnerabilities are found - only treat >1 as
    # failure. Its JSON (results[].packages[].vulnerabilities[]) already
    # matches the parser shape.
    osv_exit=0
    osv-scanner --json "${OSVArgs[@]}" > "$REPORTS_DIR/osv-scanner.json" 2>/dev/null \
        || osv_exit=$?
    [ "$osv_exit" -le 1 ] && [ -s "$REPORTS_DIR/osv-scanner.json" ] \
        || echo '{"results":[]}' > "$REPORTS_DIR/osv-scanner.json"
else
    echo '{"results":[]}' > "$REPORTS_DIR/osv-scanner.json"
fi
echo "  → OK"

echo "[scanning] npm-audit..."
npm_exit=0
if [ -f "$TARGET_DIR/package-lock.json" ]; then
    (cd "$TARGET_DIR" && npm audit --json 2>/dev/null) > "$REPORTS_DIR/npm-audit.json" || npm_exit=$?
    [ "$npm_exit" -le 1 ] && [ -s "$REPORTS_DIR/npm-audit.json" ] \
        || echo '{"vulnerabilities":{}}' > "$REPORTS_DIR/npm-audit.json"
else
    echo '{"vulnerabilities":{}}' > "$REPORTS_DIR/npm-audit.json"
fi
echo "  → OK"

echo "[scanning] yarn-audit..."
yarn_exit=0
if [ -f "$TARGET_DIR/yarn.lock" ]; then
    (cd "$TARGET_DIR" && yarn audit --json 2>/dev/null) > "$REPORTS_DIR/yarn-audit.json" || yarn_exit=$?
    # yarn audit 1.x can exit with values other than just 1 when findings
    # exist (vulnerability counts) - keep the JSONL report whenever it was
    # written instead of betting on the exact exit code.
    [ -s "$REPORTS_DIR/yarn-audit.json" ] \
        || echo '{"type":"auditSummary","data":{"vulnerabilities":{}}}' > "$REPORTS_DIR/yarn-audit.json"
else
    echo '{"type":"auditSummary","data":{"vulnerabilities":{}}}' > "$REPORTS_DIR/yarn-audit.json"
fi
echo "  → OK"

echo "[scanning] pnpm-audit..."
pnpm_exit=0
if [ -f "$TARGET_DIR/pnpm-lock.yaml" ]; then
    # pnpm@10 audit --json emits the npm-audit-style {advisories:{id:{module_name,...}}}
    # object; parser expects {"report":{"auditReport":{"vulnerabilities":{pkg:[...]}}}}.
    (cd "$TARGET_DIR" && pnpm audit --json 2>/dev/null \
        | jq '{report: {auditReport: {vulnerabilities: (([.advisories[]? | {module_name: (.module_name // .name // "unknown"), severity: (.severity // "medium"), title: (.title // ""), description: (.recommendation // .title // "")}] | group_by(.module_name) | map({(.[0].module_name): ([.[] | {title, description, severity}])}) | add) // {})}}}') \
        > "$REPORTS_DIR/pnpm-audit.json" || pnpm_exit=$?
    [ "$pnpm_exit" -le 1 ] && [ -s "$REPORTS_DIR/pnpm-audit.json" ] \
        || echo '{"report":{"auditReport":{"vulnerabilities":{}}}}' > "$REPORTS_DIR/pnpm-audit.json"
else
    echo '{"report":{"auditReport":{"vulnerabilities":{}}}}' > "$REPORTS_DIR/pnpm-audit.json"
fi
echo "  → OK"

echo "[scanning] pip-audit..."
pip_exit=0
if [ -f "$TARGET_DIR/requirements.txt" ]; then
    pip-audit -r "$TARGET_DIR/requirements.txt" --format json 2>/dev/null \
        > "$REPORTS_DIR/pip-audit.json" || pip_exit=$?
    # pip-audit exits 1 when findings exist
    [ "$pip_exit" -le 1 ] && [ -s "$REPORTS_DIR/pip-audit.json" ] \
        || echo '{"dependencies":[]}' > "$REPORTS_DIR/pip-audit.json"
else
    echo '{"dependencies":[]}' > "$REPORTS_DIR/pip-audit.json"
fi
echo "  → OK"

echo "[scanning] cargo-audit..."
cargo_exit=0
if [ -f "$TARGET_DIR/Cargo.lock" ]; then
    # cargo audit exits 1 when vulnerabilities are found - only treat >1 as failure
    (cd "$TARGET_DIR" && cargo audit --json 2>/dev/null) \
        > "$REPORTS_DIR/cargo-audit.json" || cargo_exit=$?
    [ "$cargo_exit" -le 1 ] && [ -s "$REPORTS_DIR/cargo-audit.json" ] \
        || echo '{"vulnerabilities":{"list":[]}}' > "$REPORTS_DIR/cargo-audit.json"
else
    echo '{"vulnerabilities":{"list":[]}}' > "$REPORTS_DIR/cargo-audit.json"
fi
echo "  → OK"

echo "[scanning] composer-audit..."
composer_exit=0
if [ -f "$TARGET_DIR/composer.lock" ]; then
    # composer audit exits 1 when vulnerabilities are found; --format=json
    # serializes an EMPTY advisories list as "[]", which JSON-unmarshals into
    # the parser's {"advisories":{pkg:[...]}} map as an error - so force it
    # back to a JSON object.
    (cd "$TARGET_DIR" && composer audit --format=json 2>/dev/null) \
        > "$REPORTS_DIR/composer-audit.json" || composer_exit=$?
    if [ "$composer_exit" -le 1 ] && [ -s "$REPORTS_DIR/composer-audit.json" ]; then
        jq '{advisories: (if (.advisories|type) == "object" then .advisories else {} end)}' \
            "$REPORTS_DIR/composer-audit.json" > "$REPORTS_DIR/composer-audit.tmp" \
            && mv "$REPORTS_DIR/composer-audit.tmp" "$REPORTS_DIR/composer-audit.json"
    else
        echo '{"advisories":{}}' > "$REPORTS_DIR/composer-audit.json"
    fi
else
    echo '{"advisories":{}}' > "$REPORTS_DIR/composer-audit.json"
fi
echo "  → OK"

echo "[skip] snyk (needs auth + network; generate fixture manually from 'snyk test --json')"
echo '{"vulnerabilities":[]}' > "$REPORTS_DIR/snyk.json"

# --- Multi-language SAST ---
echo "[scanning] semgrep..."
semgrep --config auto --json --output "$REPORTS_DIR/semgrep.json" "$TARGET_DIR" 2>/dev/null \
    || echo '{"results":[]}' > "$REPORTS_DIR/semgrep.json"
echo "  → OK"

echo "[scanning] sarif (semgrep derives SARIF)..."
semgrep --config auto --sarif --output "$REPORTS_DIR/sarif.json" "$TARGET_DIR" 2>/dev/null \
    || echo '{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"semgrep","rules":[]}},"results":[]}]}' > "$REPORTS_DIR/sarif.json"
echo "  → OK"

echo "[scanning] horusec..."
# horusec only writes a report when --output-format json is combined with
# --json-output-file; it exits 0 on success unless --return-error is passed.
horusec start -p "$TARGET_DIR" --output-format json \
    --json-output-file="$REPORTS_DIR/horusec.json" 2>/dev/null || true
[ -s "$REPORTS_DIR/horusec.json" ] \
    || echo '{"analysisVulnerabilities":[]}' > "$REPORTS_DIR/horusec.json"
echo "  → OK"

echo "[scanning] njsscan..."
njsscan_exit=0
if find "$TARGET_DIR" -name '*.js' -print -quit 2>/dev/null | grep -q .; then
    # njsscan exits 1 when findings exist; native output is
    # {"nodejs":{rule:{files:[{file_path,match_lines,metadata}]}}} and the
    # parser expects {"files":{file:[{title,description,hash,line,metadata}]}}.
    (cd "$TARGET_DIR" && njsscan --json . 2>/dev/null) \
        > "$REPORTS_DIR/njsscan.raw.json" || njsscan_exit=$?
    if [ "$njsscan_exit" -le 1 ] && [ -s "$REPORTS_DIR/njsscan.raw.json" ]; then
        # metadata (description/severity/cwe/owasp) lives on the RULE, not the file
        jq 'reduce ([(.nodejs // {}) + (.templates // {}) | to_entries[]
                    | .key as $r
                    | .value.metadata as $m
                    | .value.files[]?
                    | {file: .file_path,
                       item: {hash: $r,
                              title: ($m.description // ""),
                              description: ($m.description // ""),
                              line: (.match_lines[0] // 0),
                              metadata: {severity: ($m.severity // ""),
                                         cwe: ($m.cwe // ""),
                                         owasp: ($m["owasp-web"] // "")}}}]
              | .[]) as $i ({}; .[$i.file] += [$i.item])' \
            "$REPORTS_DIR/njsscan.raw.json" > "$REPORTS_DIR/njsscan.json"
    else
        echo '{"files":{}}' > "$REPORTS_DIR/njsscan.json"
    fi
    rm -f "$REPORTS_DIR/njsscan.raw.json"
else
    echo '{"files":{}}' > "$REPORTS_DIR/njsscan.json"
fi
echo "  → OK"

# --- Java / C static analysis ---
echo "[scanning] pmd..."
if [ -f "$TARGET_DIR/VulnerableApp.java" ]; then
    # PMD 7 exits nonzero when violations are found but still writes the JSON
    # report to -r. PMD 7 wraps findings under {"report":{"files":[...]}};
    # parser expects {"files":[...]}.
    pmd check -d "$TARGET_DIR/VulnerableApp.java" \
            -R category/java/bestpractices.xml,category/java/security.xml,category/java/errorprone.xml \
            -f json -r "$REPORTS_DIR/pmd.json" 2>/dev/null || true
    if [ -s "$REPORTS_DIR/pmd.json" ]; then
        jq '{files: (.report.files // .files // [])}' "$REPORTS_DIR/pmd.json" \
            > "$REPORTS_DIR/pmd.tmp" && mv "$REPORTS_DIR/pmd.tmp" "$REPORTS_DIR/pmd.json"
    else
        echo '{"files":[]}' > "$REPORTS_DIR/pmd.json"
    fi
else
    echo '{"files":[]}' > "$REPORTS_DIR/pmd.json"
fi
echo "  → OK"

echo "[scanning] cppcheck..."
if [ -f "$TARGET_DIR/vulnerable.c" ]; then
    # cppcheck exits 1 when findings exist; the templated JSONL still goes to stdout.
    cppcheck --enable=all --inconclusive \
        --template='{"tool":"Cppcheck","check":"{id}","file":"{file}","line":{line},"column":{column},"severity":"{severity}","message":"{message}","cwe":"{cwe}","verbose":"{verbose}"}' \
        "$TARGET_DIR/vulnerable.c" 2>/dev/null \
        > "$REPORTS_DIR/cppcheck.json" || true
    [ -s "$REPORTS_DIR/cppcheck.json" ] \
        || echo '{"tool":"Cppcheck","check":"none","file":"","line":0,"column":0,"severity":"style","message":"no findings","cwe":"","verbose":"placeholder"}' > "$REPORTS_DIR/cppcheck.json"
else
    echo '{"tool":"Cppcheck","check":"none","file":"","line":0,"column":0,"severity":"style","message":"no findings","cwe":"","verbose":"placeholder"}' > "$REPORTS_DIR/cppcheck.json"
fi
echo "  → OK"

echo "[scanning] flawfinder..."
# flawfinder 2.x has no --json flag; emit CSV and convert to the parser shape.
flawfinder --csv -m 0 "$TARGET_DIR/vulnerable.c" 2>/dev/null \
    | python3 -c '
import csv, json, sys
out = {"data": []}
for r in csv.DictReader(sys.stdin):
    try:
        level = int(float(r.get("Level") or 0))
    except ValueError:
        level = 3
    confidence = "high" if level >= 4 else "medium" if level == 3 else "low"
    out["data"].append({
        "category": r.get("Category") or "",
        "coordinates": r.get("RuleId") or r.get("Name") or "",
        "confidence": confidence,
        "file": r.get("File") or "",
        "line_number": int(float(r.get("Line") or 0) or 0),
        "message": (r.get("Warning") or r.get("Name") or "").strip(),
    })
json.dump(out, sys.stdout)
' \
    > "$REPORTS_DIR/flawfinder.json" \
    || echo '{"data":[]}' > "$REPORTS_DIR/flawfinder.json"
echo "  → OK"

# --- Cloud scanners (need AWS session; generate fixture manually) ---
echo "[skip] prowler, scoutsuite, wpscan (external sessions; generate fixture manually)"
echo '{"findings":[]}' > "$REPORTS_DIR/prowler.json"
echo '{"services":{}}' > "$REPORTS_DIR/scoutsuite.json"
echo '{"vulns":{}}' > "$REPORTS_DIR/wpscan.json"

# --- DAST / network scanners ---
# By default these need a live target; set SCAN_TARGET_HOST (and optionally
# SCAN_TARGET_SSL=1) to run them. Otherwise placeholder fixtures are written.
if [ -n "$TARGET_HOST" ]; then
    echo "[scanning] network scanners against ${TARGET_HOST}..."

    echo "[scanning] nmap..."
    nmap -oJ - "$TARGET_HOST" 2>/dev/null | jq '{nmaprun: (.nmaprun | {host: [.host[]? | {ports: {port: [.ports.port[]? | {protocol: .protocol, portid: .portid, state: {state: .state.state}, service: {name: (.service.name // ""), product: (.service.product // ""), version: (.service.version // "")}}]}}]})}' \
        > "$REPORTS_DIR/nmap.json" || echo '{"nmaprun":{"host":[]}}' > "$REPORTS_DIR/nmap.json"

    echo "[scanning] naabu..."
    naabu -host "$TARGET_HOST" -json 2>/dev/null | jq -s '.' \
        > "$REPORTS_DIR/naabu.json" || echo '[]' > "$REPORTS_DIR/naabu.json"

    echo "[scanning] httpx..."
    httpx -u "$TARGET_HOST" -json 2>/dev/null | jq -s '.' \
        > "$REPORTS_DIR/httpx.json" || echo '[]' > "$REPORTS_DIR/httpx.json"

    echo "[scanning] nikto..."
    nikto -h "$TARGET_HOST" -Format json -output "$REPORTS_DIR/nikto.json" 2>/dev/null \
        || echo '{"host":"placeholder","vulnerabilities":[]}' > "$REPORTS_DIR/nikto.json"

    echo "[scanning] ffuf..."
    printf 'admin\nconfig.php\n.git\nrobots.txt\n' > /tmp/ffuf-words.txt
    ffuf -u "https://${TARGET_HOST}/FUZZ" -w /tmp/ffuf-words.txt -mc all \
        -o "$REPORTS_DIR/ffuf.json" -of json 2>/dev/null \
        || echo '{"results":[]}' > "$REPORTS_DIR/ffuf.json"

    echo "[scanning] dirsearch..."
    dirsearch -u "https://${TARGET_HOST}/" --format=json -o - 2>/dev/null \
        | jq '{results: (.results // ((.targets // {}) | to_entries[]?.value | .content_paths // []))}' \
        > "$REPORTS_DIR/dirsearch.json" || echo '{"results":[]}' > "$REPORTS_DIR/dirsearch.json"

    if [ -n "${SCAN_TARGET_SSL:-}" ]; then
        echo "[scanning] sslyze..."
        sslyze --json_out="$REPORTS_DIR/sslyze.json" --quiet "$TARGET_HOST" 2>/dev/null \
            || echo '{"target":{"hostname":"placeholder"},"commands_results":{}}' > "$REPORTS_DIR/sslyze.json"

        echo "[scanning] testssl..."
        testssl --jsonfile "$REPORTS_DIR/testssl.json" "$TARGET_HOST" 2>/dev/null \
            && jq '{data}' "$REPORTS_DIR/testssl.json" > "$REPORTS_DIR/testssl.tmp" \
            && mv "$REPORTS_DIR/testssl.tmp" "$REPORTS_DIR/testssl.json" \
            || echo '[]' > "$REPORTS_DIR/testssl.json"
    else
        echo '{"target":{"hostname":"placeholder"},"commands_results":{}}' > "$REPORTS_DIR/sslyze.json"
        echo '[]' > "$REPORTS_DIR/testssl.json"
    fi
else
    echo "[skip] nmap, nikto, naabu, httpx, ffuf, dirsearch, sslyze, testssl (set SCAN_TARGET_HOST to run)"
    echo '{"nmaprun":{"host":[]}}' > "$REPORTS_DIR/nmap.json"
    echo '[]' > "$REPORTS_DIR/naabu.json"
    echo '[]' > "$REPORTS_DIR/httpx.json"
    echo '{"host":"placeholder","vulnerabilities":[]}' > "$REPORTS_DIR/nikto.json"
    echo '{"results":[]}' > "$REPORTS_DIR/ffuf.json"
    echo '{"results":[]}' > "$REPORTS_DIR/dirsearch.json"
    echo '{"target":{"hostname":"placeholder"},"commands_results":{}}' > "$REPORTS_DIR/sslyze.json"
    echo '[]' > "$REPORTS_DIR/testssl.json"
fi

echo "[skip] nuclei (DAST needs running targets; generate fixture manually)"
echo '[]' > "$REPORTS_DIR/nuclei.json"

echo ""
echo "=== Done ==="
ls -1 "$REPORTS_DIR"/*.json 2>/dev/null | while read f; do
    size=$(wc -c < "$f")
    echo "  $(basename "$f")  (${size} bytes)"
done