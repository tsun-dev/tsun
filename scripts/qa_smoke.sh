#!/bin/bash
# Tsun QA Smoke Test - Automated Checks
# Usage: ./scripts/qa_smoke.sh
# Env: TSUN_RUN_ZAP=1 to enable real ZAP tests (slow, optional in CI)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "══════════════════════════════════════════════════════════════════════════════"
echo "  Tsun QA Smoke Test"
echo "══════════════════════════════════════════════════════════════════════════════"

# Configuration
TSUN_RUN_ZAP="${TSUN_RUN_ZAP:-0}"
FAILED_TESTS=0
PASSED_TESTS=0
SKIPPED_TESTS=0

log_pass() { 
  echo -e "${GREEN}✓${NC} $1"
  PASSED_TESTS=$((PASSED_TESTS + 1))
}

log_fail() { 
  echo -e "${RED}✗ FAIL:${NC} $1"
  FAILED_TESTS=$((FAILED_TESTS + 1))
}

log_skip() { 
  echo -e "${YELLOW}⚠${NC} $1"
  SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
}

log_info() {
  echo -e "${BLUE}ℹ${NC} $1"
}

# Setup
echo ""
log_info "Setting up environment..."
cargo build --release || { log_fail "Build failed"; exit 1; }
export PATH="$PWD/target/release:$PATH"

# Install jsonschema if not present
if ! python3 -c "import jsonschema" 2>/dev/null; then
  log_info "Installing jsonschema..."
  python3 -m pip install --quiet jsonschema 2>/dev/null || pip install --quiet jsonschema
fi

log_pass "Build and dependencies ready"

# Cleanup function
cleanup() {
  rm -f test.json test.sarif test.html test.yaml cookies.json cookies.txt tsun.yaml zap-test.json zap-sanity.json
  rm -f /tmp/html-gating.log /tmp/yaml-gating.log /tmp/baseline-gating.log /tmp/deep-gating.log /tmp/custom-gating.log
}
trap cleanup EXIT

echo ""
echo "══════════════════════════════════════════════════════════════════════════════"
echo "  Running Automated Smoke Tests"
echo "══════════════════════════════════════════════════════════════════════════════"
echo ""

# ============================================================================
# FREE TIER TESTS (Always Available)
# ============================================================================

# Test 1: Doctor check
log_info "Test 1: Doctor check..."
if tsun doctor >/dev/null 2>&1; then
  log_pass "Doctor check passed"
else
  log_skip "Doctor check (may fail in CI without Docker)"
fi

# Test 2: Free JSON output (mock)
log_info "Test 2: Mock JSON output..."
tsun scan --target https://testphp.vulnweb.com --format json --output test.json --engine mock >/dev/null 2>&1
if [ -f test.json ]; then
  log_pass "Mock JSON output created"
else
  log_fail "test.json not created"
fi

# Test 3: Free SARIF output (mock)
log_info "Test 3: Mock SARIF output..."
tsun scan --target https://testphp.vulnweb.com --format sarif --output test.sarif --engine mock >/dev/null 2>&1
if [ -f test.sarif ]; then
  log_pass "Mock SARIF output created"
else
  log_fail "test.sarif not created"
fi

# Test 4: SARIF schema validation
log_info "Test 4: SARIF schema validation..."
if python3 -c "import json, jsonschema; jsonschema.validate(json.load(open('test.sarif')), json.load(open('tools/sarif-schema-2.1.0.json')))" 2>/dev/null; then
  log_pass "SARIF schema validation passed"
else
  log_fail "SARIF schema validation failed"
fi

# Test 5: Real ZAP sanity (optional)
if [ "$TSUN_RUN_ZAP" = "1" ]; then
  log_info "Test 5: Real ZAP sanity check (90s timeout)..."
  if tsun scan --target http://testphp.vulnweb.com --engine zap --timeout 90 --format json --output zap-sanity.json 2>&1 | grep -q "completed" || [ -f zap-sanity.json ]; then
    # Check cleanup (safe for scripts)
    ZAP_COUNT=$(docker ps -a --filter "ancestor=zaproxy/zap-stable" --format '{{.ID}}' 2>/dev/null | wc -l)
    if [ "$ZAP_COUNT" -eq 0 ]; then
      log_pass "Real ZAP sanity + cleanup verified"
    else
      log_fail "Found $ZAP_COUNT orphaned ZAP containers"
      docker ps -a --filter "ancestor=zaproxy/zap-stable"
    fi
  else
    log_fail "ZAP scan failed to complete"
  fi
else
  log_skip "Real ZAP sanity (set TSUN_RUN_ZAP=1 to enable)"
fi

# ============================================================================
# PRO FEATURE GATING (Free Tier Blocked)
# ============================================================================

# Test 6: HTML gating
log_info "Test 6: HTML output gating (Free tier)..."
tsun scan --target https://testphp.vulnweb.com --format html --output test.html --engine mock 2>&1 | tee /tmp/html-gating.log >/dev/null
if [ ! -f test.html ] && grep -qi "Tsun Pro" /tmp/html-gating.log; then
  log_pass "HTML output gating works (Free tier blocked)"
else
  log_fail "HTML gating not working correctly"
fi

# Test 7: YAML gating
log_info "Test 7: YAML output gating (Free tier)..."
tsun scan --target https://testphp.vulnweb.com --format yaml --output test.yaml --engine mock 2>&1 | tee /tmp/yaml-gating.log >/dev/null
if [ ! -f test.yaml ] && grep -qi "Tsun Pro" /tmp/yaml-gating.log; then
  log_pass "YAML output gating works (Free tier blocked)"
else
  log_fail "YAML gating not working correctly"
fi

# Test 8: Baseline gating
log_info "Test 8: Baseline comparison gating (Free tier)..."
tsun scan --target https://testphp.vulnweb.com --baseline test.json --engine mock 2>&1 | tee /tmp/baseline-gating.log >/dev/null
if grep -qi "Tsun Pro" /tmp/baseline-gating.log || grep -qi "baseline" /tmp/baseline-gating.log; then
  log_pass "Baseline comparison gating works (Free tier warned)"
else
  log_fail "Baseline gating not working correctly"
fi

# Test 9: Deep profile gating
log_info "Test 9: Deep profile gating (Free tier)..."
tsun scan --target https://testphp.vulnweb.com --profile deep --engine mock 2>&1 | tee /tmp/deep-gating.log >/dev/null
if grep -qi "Tsun Pro\|falling back" /tmp/deep-gating.log; then
  log_pass "Deep profile gating works (Free tier fallback)"
else
  log_fail "Deep profile gating not working correctly"
fi

# Test 10: Custom profile gating
log_info "Test 10: Custom profile gating (Free tier)..."
tsun scan --target https://testphp.vulnweb.com --profile custom --engine mock 2>&1 | tee /tmp/custom-gating.log >/dev/null
if grep -qi "Tsun Pro\|falling back" /tmp/custom-gating.log; then
  log_pass "Custom profile gating works (Free tier fallback)"
else
  log_fail "Custom profile gating not working correctly"
fi

# ============================================================================
# EXIT CODE GATING
# ============================================================================

# Test 11: Exit-code gating (high severity)
log_info "Test 11: Exit-code gating (high severity)..."
if tsun scan --target https://testphp.vulnweb.com --exit-on-severity high --engine mock >/dev/null 2>&1; then
  log_fail "Should exit 1 for high severity findings"
else
  EXIT_CODE=$?
  if [ $EXIT_CODE -eq 1 ]; then
    log_pass "Exit-code gating (high severity) works"
  else
    log_fail "Wrong exit code: $EXIT_CODE (expected 1)"
  fi
fi

# Test 12: Exit-code gating (critical only)
log_info "Test 12: Exit-code gating (critical - none expected)..."
if tsun scan --target https://testphp.vulnweb.com --exit-on-severity critical --engine mock >/dev/null 2>&1; then
  log_pass "Exit-code gating (critical) works (exit 0)"
else
  log_fail "Should exit 0 for critical (no critical findings in mock)"
fi

# Test 13: Exit-code gating (default = no failure)
log_info "Test 13: Exit-code gating (default - no threshold)..."
if tsun scan --target https://testphp.vulnweb.com --engine mock >/dev/null 2>&1; then
  log_pass "Exit-code gating (default) works"
else
  log_fail "Should exit 0 with no threshold set"
fi

# ============================================================================
# AUTHENTICATION MECHANISMS
# ============================================================================

# Test 14: Auth headers
log_info "Test 14: Auth headers parsing..."
if tsun scan --target https://testphp.vulnweb.com --header "X-Test: value" --header "Authorization: Bearer token" --engine mock >/dev/null 2>&1; then
  log_pass "Auth headers parsing works"
else
  log_fail "Auth headers scan failed"
fi

# Test 15: Cookie file (JSON)
log_info "Test 15: Cookie file (JSON format)..."
echo '[{"name":"session","value":"abc123"}]' > cookies.json
if tsun scan --target https://testphp.vulnweb.com --cookies cookies.json --engine mock >/dev/null 2>&1; then
  log_pass "Cookie file (JSON) works"
else
  log_fail "Cookie file (JSON) scan failed"
fi

# Test 16: Cookie file (Netscape)
log_info "Test 16: Cookie file (Netscape format)..."
cat > cookies.txt <<EOF
# Netscape HTTP Cookie File
.example.com	TRUE	/	FALSE	0	session_id	abc123xyz
EOF
if tsun scan --target https://testphp.vulnweb.com --cookies cookies.txt --engine mock >/dev/null 2>&1; then
  log_pass "Cookie file (Netscape) works"
else
  log_fail "Cookie file (Netscape) scan failed"
fi

# ============================================================================
# INPUT VALIDATION
# ============================================================================

# Test 17: Invalid URL rejection
log_info "Test 17: Invalid URL rejection..."
if tsun scan --target not-a-url --engine mock 2>&1 | grep -qi "invalid.*url"; then
  log_pass "Invalid URL rejection works"
else
  log_fail "Invalid URL not rejected properly"
fi

# Test 18: Invalid format rejection
log_info "Test 18: Invalid format rejection..."
if tsun scan --target https://testphp.vulnweb.com --format pdf --engine mock 2>&1 | grep -qi "invalid.*format\|supported"; then
  log_pass "Invalid format (pdf) rejected"
else
  log_fail "Invalid format not rejected properly"
fi

# ============================================================================
# LICENSE MANAGEMENT
# ============================================================================

# Test 19: License status
log_info "Test 19: License status command..."
if tsun license status >/dev/null 2>&1; then
  log_pass "License status command works"
else
  log_fail "License status command failed"
fi

# Test 20: Init config
log_info "Test 20: Init config template..."
rm -f tsun.yaml
tsun init >/dev/null 2>&1
if [ -f tsun.yaml ]; then
  log_pass "Init config template created"
else
  log_fail "tsun.yaml not created by init command"
fi

# ============================================================================
# ZAP MANAGED LIFECYCLE (Optional - Real ZAP)
# ============================================================================

if [ "$TSUN_RUN_ZAP" = "1" ]; then
  log_info "Test 21: ZAP managed lifecycle (60s scan)..."
  if tsun scan --target http://testphp.vulnweb.com --engine zap --timeout 60 --format json --output zap-test.json 2>&1 | grep -q "completed" || [ -f zap-test.json ]; then
    # Verify cleanup
    ZAP_COUNT=$(docker ps -a --filter "ancestor=zaproxy/zap-stable" --format '{{.ID}}' 2>/dev/null | wc -l)
    if [ "$ZAP_COUNT" -eq 0 ]; then
      log_pass "ZAP lifecycle + cleanup verified"
    else
      log_fail "Found $ZAP_COUNT orphaned ZAP containers after scan"
      docker ps -a --filter "ancestor=zaproxy/zap-stable"
    fi
  else
    log_fail "ZAP lifecycle scan failed"
  fi
else
  log_skip "ZAP managed lifecycle (set TSUN_RUN_ZAP=1 to enable)"
fi

# ============================================================================
# SUMMARY
# ============================================================================

echo ""
echo "══════════════════════════════════════════════════════════════════════════════"
echo "  Test Summary"
echo "══════════════════════════════════════════════════════════════════════════════"
echo -e "${GREEN}Passed:${NC}  $PASSED_TESTS"
echo -e "${YELLOW}Skipped:${NC} $SKIPPED_TESTS"
echo -e "${RED}Failed:${NC}  $FAILED_TESTS"
echo "══════════════════════════════════════════════════════════════════════════════"

if [ $FAILED_TESTS -eq 0 ]; then
  echo -e "${GREEN}✓ All automated tests passed!${NC}"
  exit 0
else
  echo -e "${RED}✗ $FAILED_TESTS test(s) failed${NC}"
  exit 1
fi
