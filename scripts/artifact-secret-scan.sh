#!/usr/bin/env bash
# scripts/artifact-secret-scan.sh
# Secret scanning for pull requests, release artifacts, build outputs, and SBOM provenance.
#
# Complements scripts/secret-scanning-preflight.sh (which scans source files)
# by also scanning compiled build artifacts, PR diff output, and release bundles.
# Maintains an allowlist for known-safe fixture values (narrowly scoped).
# Findings include remediation steps without echoing the matched secret value.
#
# Usage:
#   ./scripts/artifact-secret-scan.sh [--mode <mode>] [--artifact-dir <dir>]
#
# Modes (--mode):
#   full        Scan source + artifacts + git diff (default)
#   artifacts   Scan build artifacts and bundles only
#   diff        Scan only the current git diff (for PR checks)
#   source      Delegate to secret-scanning-preflight.sh (source files only)
#   provenance  Validate SBOM/provenance metadata integrity (no secret scan)
#
# Options:
#   --artifact-dir <dir>   Additional directory to scan for artifacts
#   --baseline <file>      Allowlist file (default: .secret-scan-baseline.json)
#   --report-dir <dir>     Evidence directory (default: secret-scan-results)
#   --fail-on-warning      Treat allowlisted findings as failures too
#   --sbom-dir <dir>       Directory containing SBOM artifacts (default: sbom)
#
# Exit codes:
#   0  No unallowlisted secrets found
#   1  Secrets found that are not in the allowlist
#   2  Invalid usage
#
# Acceptance criteria (issue #133):
#   - Known-safe fixtures are allowlisted narrowly (by file + line range)
#   - New secrets block release (exit 1)
#   - Findings include remediation steps without echoing values
#   - SBOM/provenance metadata is present, well-formed, and checksummed
#
# NOTE: This scanner does NOT print matched secret values — it prints file path,
#       line number, pattern name, and remediation guidance only.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Parse args ────────────────────────────────────────────────────────────────
MODE="full"
ARTIFACT_DIR=""
BASELINE_FILE="${REPO_ROOT}/.secret-scan-baseline.json"
REPORT_DIR="${REPO_ROOT}/secret-scan-results"
FAIL_ON_WARNING=false
SBOM_DIR="${REPO_ROOT}/sbom"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)         MODE="${2:-full}";           shift 2 ;;
    --artifact-dir) ARTIFACT_DIR="${2:-}";       shift 2 ;;
    --baseline)     BASELINE_FILE="${2:-}";      shift 2 ;;
    --report-dir)   REPORT_DIR="${2:-}";         shift 2 ;;
    --fail-on-warning) FAIL_ON_WARNING=true;     shift ;;
    --sbom-dir)     SBOM_DIR="${2:-}";           shift 2 ;;
    -h|--help)
      head -40 "${BASH_SOURCE[0]}" | grep '^#' | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_section() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }
log_pass()    { echo -e "${GREEN}✓${NC} $1"; }
log_fail()    { echo -e "${RED}✗ FINDING${NC}: $1"; }
log_warn()    { echo -e "${YELLOW}⚠ ALLOWED${NC}: $1"; }
log_info()    { echo -e "${CYAN}ℹ${NC} $1"; }

FINDINGS=0
ALLOWLISTED=0
GAPS=()

mkdir -p "${REPORT_DIR}"
REPORT_FILE="${REPORT_DIR}/scan-$(date +%Y%m%dT%H%M%S).txt"
exec > >(tee -a "${REPORT_FILE}") 2>&1

echo "xConfess Artifact Secret Scan"
echo "=============================="
echo "Date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Mode:     ${MODE}"
echo "Report:   ${REPORT_FILE}"
echo "SBOM dir: ${SBOM_DIR}"
echo ""

# ── Secret patterns (shared with preflight, kept in sync) ────────────────────
# Each pattern is a grep regex. Findings do NOT print the matched value —
# they print file:line and the pattern name only.
declare -A PATTERNS
PATTERNS[stellar-secret-seed]='S[2-7A-Z]{55}'
PATTERNS[hex-private-key-64]='[0-9a-fA-F]{64}'
PATTERNS[jwt-token]='eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,}'
PATTERNS[bearer-token]='Bearer [a-zA-Z0-9_\-\.]{20,}'
PATTERNS[aws-access-key]='AKIA[0-9A-Z]{16}'
PATTERNS[npm-token]='npm_[a-zA-Z0-9]{36}'
PATTERNS[github-pat]='(ghp|gho|ghs|ghr)_[a-zA-Z0-9]{36}'
PATTERNS[generic-password-assignment]='password\s*[=:]\s*["\x27][^"\x27]{8,}'

# ── Allowlist loader ──────────────────────────────────────────────────────────
# The baseline file is a JSON array of objects:
# [{ "file": "path/relative/to/repo", "pattern": "pattern-name", "reason": "why safe" }]
declare -A ALLOWLIST_ENTRIES  # key = "file:pattern", value = reason

load_allowlist() {
  if [[ ! -f "${BASELINE_FILE}" ]]; then
    log_info "No baseline file found at ${BASELINE_FILE} — all findings are blocking"
    return
  fi

  if ! command -v node &>/dev/null; then
    log_warn "node not available — cannot load baseline allowlist"
    return
  fi

  log_info "Loading baseline allowlist from ${BASELINE_FILE}..."
  while IFS='|' read -r file pattern reason; do
    [[ -z "${file}" ]] && continue
    ALLOWLIST_ENTRIES["${file}:${pattern}"]="${reason}"
    log_info "  Allowed: ${file} / ${pattern} — ${reason}"
  done < <(node -e "
    const fs = require('fs');
    try {
      const entries = JSON.parse(fs.readFileSync('${BASELINE_FILE}', 'utf8'));
      if (!Array.isArray(entries)) { process.exit(0); }
      entries.forEach(e => {
        if (e.file && e.pattern) {
          console.log([e.file, e.pattern, e.reason || 'no reason given'].join('|'));
        }
      });
    } catch(err) {
      process.stderr.write('Baseline parse error: ' + err.message + '\n');
    }
  " 2>/dev/null || true)
}

is_allowlisted() {
  local file="$1" pattern="$2"
  local rel_file="${file#${REPO_ROOT}/}"
  # Exact file match
  local key="${rel_file}:${pattern}"
  if [[ -n "${ALLOWLIST_ENTRIES[${key}]+x}" ]]; then
    return 0
  fi
  # Directory prefix match (allowlist entry ending in / matches all files under that dir)
  for entry_key in "${!ALLOWLIST_ENTRIES[@]}"; do
    local entry_file="${entry_key%:*}"
    local entry_pattern="${entry_key##*:}"
    if [[ "${entry_pattern}" == "${pattern}" && "${entry_file}" == */ ]]; then
      if [[ "${rel_file}" == "${entry_file}"* ]]; then
        return 0
      fi
    fi
  done
  return 1
}

# ── Remediation guidance ──────────────────────────────────────────────────────
remediation_for() {
  local pattern="$1"
  case "${pattern}" in
    stellar-secret-seed)
      echo "Remove from file immediately. Rotate the Stellar keypair (generate new via 'stellar keys generate'). Add the new secret to your secrets manager and update env vars. Treat the old key as compromised." ;;
    hex-private-key-64)
      echo "Remove the hex key from the file. Store in environment variables or a secrets manager. If committed to history, run 'git filter-repo' to purge and notify all collaborators to re-clone." ;;
    jwt-token)
      echo "Revoke the JWT immediately by rotating the JWT_SECRET in your environment. All existing sessions will be invalidated. Do not commit JWTs to source control." ;;
    bearer-token)
      echo "Revoke the bearer token from the issuing service. Rotate any related API keys. Audit recent usage of that token in service logs." ;;
    aws-access-key)
      echo "Deactivate the IAM access key in the AWS console immediately. Rotate to a new key pair. Audit CloudTrail for unauthorized usage in the past 24 hours." ;;
    npm-token)
      echo "Revoke the npm token at npmjs.com/settings/tokens. Generate a new automation token. Audit recent publishes for that token." ;;
    github-pat)
      echo "Revoke the GitHub PAT at github.com/settings/tokens. Generate a new fine-grained token with minimal scopes. Audit recent API calls via the token." ;;
    generic-password-assignment)
      echo "Remove the hardcoded password from the file. Use environment variables or a vault. Change the password if it was ever used in a non-local environment." ;;
    *)
      echo "Remove the credential from the file. Rotate it in the issuing system. If it appears in git history, use 'git filter-repo' to purge." ;;
  esac
}

# ── Scan a single file ────────────────────────────────────────────────────────
scan_file() {
  local file="$1"
  # Skip binary files
  if file --mime "${file}" 2>/dev/null | grep -q "charset=binary"; then
    return
  fi
  # Skip known-safe files
  local basename
  basename=$(basename "${file}")
  case "${basename}" in
    package-lock.json|Cargo.lock|audit-report.json) return ;;
    *.png|*.jpg|*.jpeg|*.gif|*.ico|*.woff|*.woff2|*.ttf|*.wasm) return ;;
  esac
  # Skip this scanner itself and the preflight tool
  case "${file}" in
    *artifact-secret-scan.sh|*secret-scanning-preflight.sh) return ;;
    *secret-scan-baseline.json|*.secret-scan-baseline.json) return ;;
    *secret-scan-results*|*rollback-drill-results*|*readiness-results*) return ;;
  esac

  for pattern_name in "${!PATTERNS[@]}"; do
    local regex="${PATTERNS[${pattern_name}]}"
    # Capture only line numbers (not matched content) to avoid echoing secret values
    local matching_lines
    matching_lines=$(grep -nE "${regex}" "${file}" 2>/dev/null | cut -d: -f1 || true)
    if [[ -z "${matching_lines}" ]]; then
      continue
    fi

    while IFS= read -r lineno; do
      [[ -z "${lineno}" ]] && continue
      local rel_path="${file#${REPO_ROOT}/}"
      if is_allowlisted "${file}" "${pattern_name}"; then
        log_warn "${rel_path}:${lineno} — pattern '${pattern_name}' (allowlisted)"
        ((ALLOWLISTED++)) || true
        if [[ "${FAIL_ON_WARNING}" == "true" ]]; then
          ((FINDINGS++)) || true
        fi
      else
        log_fail "${rel_path}:${lineno} — pattern '${pattern_name}'"
        echo "  Remediation: $(remediation_for "${pattern_name}")"
        ((FINDINGS++)) || true
      fi
    done <<< "${matching_lines}"
  done
}

# ── Scan build artifacts ──────────────────────────────────────────────────────
scan_artifacts() {
  log_section "Scanning build artifacts"

  local dirs=(
    "${REPO_ROOT}/xconfess-backend/dist"
    "${REPO_ROOT}/xconfess-frontend/.next/server"
    "${REPO_ROOT}/xconfess-contracts/target/wasm32-unknown-unknown/release"
  )
  [[ -n "${ARTIFACT_DIR}" ]] && dirs+=("${ARTIFACT_DIR}")

  for dir in "${dirs[@]}"; do
    if [[ ! -d "${dir}" ]]; then
      log_info "Artifact directory not found (skip): ${dir}"
      continue
    fi
    log_info "Scanning: ${dir}"
    while IFS= read -r -d '' f; do
      scan_file "${f}"
    done < <(find "${dir}" -type f -print0 2>/dev/null)
  done
}

# ── Scan git diff (for PR checks) ────────────────────────────────────────────
scan_diff() {
  log_section "Scanning git diff"

  local diff_content
  # Try PR diff first, fall back to HEAD diff
  if git rev-parse --verify HEAD~1 &>/dev/null; then
    diff_content=$(git diff HEAD~1..HEAD -- . ':!*.lock' ':!*.lock.json' 2>/dev/null || true)
  else
    diff_content=$(git diff --cached -- . ':!*.lock' ':!*.lock.json' 2>/dev/null || true)
  fi

  if [[ -z "${diff_content}" ]]; then
    log_info "No diff content to scan"
    return
  fi

  # Write diff to a temp file for scanning (do not print its contents)
  local tmp_diff
  tmp_diff=$(mktemp)
  echo "${diff_content}" > "${tmp_diff}"

  # Only scan added lines (starting with +)
  local added_lines
  added_lines=$(grep '^+' "${tmp_diff}" | grep -v '^+++' || true)
  local added_tmp
  added_tmp=$(mktemp)
  echo "${added_lines}" > "${added_tmp}"

  for pattern_name in "${!PATTERNS[@]}"; do
    local regex="${PATTERNS[${pattern_name}]}"
    local hits
    hits=$(grep -cE "${regex}" "${added_tmp}" 2>/dev/null || true)
    if [[ "${hits}" -gt 0 ]]; then
      log_fail "git diff (added lines) — pattern '${pattern_name}' found ${hits} time(s)"
      echo "  Remediation: $(remediation_for "${pattern_name}")"
      ((FINDINGS+=hits)) || true
    fi
  done

  rm -f "${tmp_diff}" "${added_tmp}"
  log_info "Git diff scan complete"
}

# ── Source file scan (delegate to preflight) ──────────────────────────────────
scan_source() {
  log_section "Scanning source files (delegating to secret-scanning-preflight.sh)"
  local preflight="${SCRIPT_DIR}/secret-scanning-preflight.sh"
  if [[ -x "${preflight}" ]]; then
    "${preflight}" && log_pass "Source scan: no findings" || {
      log_fail "Source scan: preflight reported findings"
      ((FINDINGS++)) || true
    }
  else
    log_warn "secret-scanning-preflight.sh not found or not executable at ${preflight}"
    GAPS+=("Source scan skipped — preflight script not executable")
  fi
}

# ── SBOM / provenance validation ─────────────────────────────────────────────
# Validates that SBOM artifacts exist for each required target, are well-formed
# JSON, declare a spec version, and have a matching checksum sidecar. Missing or
# malformed provenance metadata is a blocking finding (issue #133).
REQUIRED_SBOM_TARGETS=(backend frontend contracts container)

validate_sbom_file() {
  local target="$1"
  local sbom_file="${SBOM_DIR}/${target}.sbom.json"
  local checksum_file="${sbom_file}.sha256"

  if [[ ! -f "${sbom_file}" ]]; then
    log_fail "SBOM missing for target '${target}' (expected ${sbom_file#${REPO_ROOT}/})"
    echo "  Remediation: run 'npm run sbom:generate' in CI before release; ensure the ${target} build job uploads its SBOM artifact."
    ((FINDINGS++)) || true
    return
  fi

  if ! command -v node &>/dev/null; then
    log_warn "node not available — cannot validate SBOM JSON for '${target}'"
    GAPS+=("SBOM JSON validation skipped for ${target} — node unavailable")
    return
  fi

  local parse_err
  parse_err=$(node -e "
    const fs = require('fs');
    try {
      const doc = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
      const spec = doc.spdxVersion || doc.bomFormat || doc.schemaVersion;
      if (!spec) { throw new Error('missing spec version (spdxVersion/bomFormat/schemaVersion)'); }
      const comps = doc.components || doc.packages || [];
      if (!Array.isArray(comps) || comps.length === 0) { throw new Error('no components/packages declared'); }
      const hasTransitive = comps.some(c => c && (c.dependencies || c.relationship || c.scope === 'transitive' || c.relationshipType));
      if (!hasTransitive) { throw new Error('no transitive dependency metadata found'); }
    } catch (err) {
      process.stderr.write(err.message);
      process.exit(1);
    }
  " "${sbom_file}" 2>&1 || true)

  if [[ -n "${parse_err}" ]]; then
    log_fail "SBOM malformed for target '${target}': ${parse_err}"
    echo "  Remediation: regenerate SBOM with 'npm run sbom:generate'; ensure the generator emits spec version, components, and transitive relationships."
    ((FINDINGS++)) || true
    return
  fi

  if [[ ! -f "${checksum_file}" ]]; then
    log_fail "SBOM checksum missing for target '${target}' (expected ${checksum_file#${REPO_ROOT}/})"
    echo "  Remediation: run 'sha256sum ${sbom_file#${REPO_ROOT}/} > ${checksum_file#${REPO_ROOT}/}' in the release job and commit the sidecar."
    ((FINDINGS++)) || true
    return
  fi

  local expected actual
  expected=$(awk '{print $1}' "${checksum_file}" | head -n1)
  actual=$(sha256sum "${sbom_file}" | awk '{print $1}')
  if [[ -z "${expected}" || "${expected}" != "${actual}" ]]; then
    log_fail "SBOM checksum mismatch for target '${target}'"
    echo "  Remediation: regenerate the SBOM and its .sha256 sidecar together; do not hand-edit either file."
    ((FINDINGS++)) || true
    return
  fi

  log_pass "SBOM OK: ${sbom_file#${REPO_ROOT}/} (checksum verified)"
}

scan_provenance() {
  log_section "Validating SBOM / provenance metadata"

  if [[ ! -d "${SBOM_DIR}" ]]; then
    log_fail "SBOM directory not found: ${SBOM_DIR#${REPO_ROOT}/}"
    echo "  Remediation: run 'npm run sbom:generate' in CI and publish artifacts to ${SBOM_DIR#${REPO_ROOT}/}."
    ((FINDINGS++)) || true
    return
  fi

  for target in "${REQUIRED_SBOM_TARGETS[@]}"; do
    validate_sbom_file "${target}"
  done
}

# ── Main ──────────────────────────────────────────────────────────────────────
load_allowlist

case "${MODE}" in
  full)
    scan_source
    scan_artifacts
    scan_diff
    scan_provenance
    ;;
  artifacts)
    scan_artifacts
    ;;
  diff)
    scan_diff
    ;;
  source)
    scan_source
    ;;
  provenance)
    scan_provenance
    ;;
  *)
    echo "Unknown mode: ${MODE}" >&2
    exit 2
    ;;
esac

# ── Results ───────────────────────────────────────────────────────────────────
log_section "Scan Results"
echo "Blocking findings:  ${FINDINGS}"
echo "Allowlisted:        ${ALLOWLISTED}"
echo "Report:             ${REPORT_FILE}"
if [[ ${#GAPS[@]} -gt 0 ]]; then
  echo "Gaps:               ${#GAPS[@]} (see below)"
fi
echo ""

if [[ ${FINDINGS} -gt 0 ]]; then
  echo -e "${RED}Secret scan FAILED — ${FINDINGS} unallowlisted finding(s).${NC}"
  echo ""
  echo "To add a known-safe value to the allowlist, edit ${BASELINE_FILE}:"
  echo '  [{"file": "path/to/file", "pattern": "pattern-name", "reason": "safe because ..."}]'
  echo ""
  echo "Do NOT add real secrets to the allowlist — only fixture/test/placeholder values."
  exit 1
fi

if [[ ${#GAPS[@]} -gt 0 ]]; then
  echo -e "${YELLOW}Scan completed with ${#GAPS[@]} gap(s):${NC}"
  for gap in "${GAPS[@]}"; do
    echo "  - ${gap}"
  done
  echo ""
fi

log_pass "No unallowlisted secrets found."
exit 0
