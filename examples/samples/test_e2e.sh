#!/bin/bash
# End-to-end test for detonate using safe test samples
# Verifies full CLI command coverage, HTTP health check, export formats, and timezone-aware datetimes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DB="${SCRIPT_DIR}/data/test_e2e.db"
TEST_OUTPUT_DIR="${SCRIPT_DIR}/data/e2e_output"
PASSED=0
FAILED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED=$((FAILED + 1))
}

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

cleanup() {
    log_info "Cleaning up..."
    rm -rf "${TEST_OUTPUT_DIR}"
    rm -f "${TEST_DB}"
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Setup
log_info "Setting up test environment..."
mkdir -p "${TEST_OUTPUT_DIR}"
export DETONATE_DATABASE="${TEST_DB}"

# =============================================================================
# Test 1: Database Initialization
# =============================================================================
log_info "Test 1: Database initialization (detonate db init)"
if python3 -m detonate.cli db init 2>&1 | grep -q "Database initialized"; then
    log_pass "Database initialized successfully"
else
    log_fail "Database initialization failed"
fi

# =============================================================================
# Test 2: Analyze Command
# =============================================================================
log_info "Test 2: Analyze command (detonate analyze)"
SAMPLE="${SCRIPT_DIR}/minimal_x8664"
ANALYSIS_OUTPUT_DIR="${TEST_OUTPUT_DIR}/analysis"
mkdir -p "${ANALYSIS_OUTPUT_DIR}"

if python3 -m detonate.cli analyze "${SAMPLE}" \
    --platform linux \
    --arch x86_64 \
    --output "${ANALYSIS_OUTPUT_DIR}" \
    2>&1 | grep -q "Analysis complete"; then
    log_pass "Analysis completed successfully"
else
    log_fail "Analysis failed"
fi

# Verify output files were created (they have format: report_*.md, navigator_*.json, etc.)
if ls "${ANALYSIS_OUTPUT_DIR}"/log_*.jsonl 1>/dev/null 2>&1; then
    log_pass "JSON log output file created"
else
    log_fail "JSON log output file missing"
fi

# =============================================================================
# Test 3: List Analyses (Database Round-Trip)
# =============================================================================
log_info "Test 3: List analyses (detonate list-analyses)"
LIST_OUTPUT=$(python3 -m detonate.cli list-analyses 2>&1)
if echo "${LIST_OUTPUT}" | grep -q "minimal_x8664"; then
    log_pass "Analysis found in database"
else
    log_fail "Analysis not found in database"
fi

# Extract session ID for export tests
SESSION_ID=$(python3 -m detonate.cli list-analyses --format json 2>&1 | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')" 2>/dev/null || echo "")
if [ -n "${SESSION_ID}" ]; then
    log_pass "Session ID extracted: ${SESSION_ID}"
else
    log_fail "Could not extract session ID"
    SESSION_ID="1"  # Fallback to first session
fi

# =============================================================================
# Test 4: Export - Navigator Format
# =============================================================================
log_info "Test 4: Export Navigator format (detonate export --format navigator)"
NAVIGATOR_OUTPUT="${TEST_OUTPUT_DIR}/navigator.json"
if python3 -m detonate.cli export "${SESSION_ID}" --format navigator --output "${NAVIGATOR_OUTPUT}" 2>&1 | grep -q "Exported"; then
    log_pass "Navigator export completed"
    # Validate Navigator JSON structure
    if python3 -c "import json; d=json.load(open('${NAVIGATOR_OUTPUT}')); assert 'layerName' in d or 'techniques' in d or 'name' in d" 2>/dev/null; then
        log_pass "Navigator JSON structure valid"
    else
        log_fail "Navigator JSON structure invalid"
    fi
else
    log_fail "Navigator export failed"
fi

# =============================================================================
# Test 5: Export - STIX Format
# =============================================================================
log_info "Test 5: Export STIX format (detonate export --format stix)"
STIX_OUTPUT="${TEST_OUTPUT_DIR}/stix.json"
if python3 -m detonate.cli export "${SESSION_ID}" --format stix --output "${STIX_OUTPUT}" 2>&1 | grep -q "Exported"; then
    log_pass "STIX export completed"
    # Validate STIX bundle structure
    if python3 -c "import json; d=json.load(open('${STIX_OUTPUT}')); assert 'type' in d and d['type']=='bundle'" 2>/dev/null; then
        log_pass "STIX bundle structure valid"
    else
        log_fail "STIX bundle structure invalid"
    fi
else
    log_fail "STIX export failed"
fi

# =============================================================================
# Test 6: Export - Report Format (Markdown)
# =============================================================================
log_info "Test 6: Export Report format (detonate export --format report)"
REPORT_OUTPUT="${TEST_OUTPUT_DIR}/report.md"
if python3 -m detonate.cli export "${SESSION_ID}" --format report --output "${REPORT_OUTPUT}" 2>&1 | grep -q "Exported"; then
    log_pass "Report export completed"
    # Validate markdown has content
    if [ -s "${REPORT_OUTPUT}" ] && grep -q "ATT&CK" "${REPORT_OUTPUT}"; then
        log_pass "Report markdown contains ATT&CK mapping"
    else
        log_fail "Report markdown invalid or empty"
    fi
else
    log_fail "Report export failed"
fi

# =============================================================================
# Test 7: Export - Log Format (JSONL)
# =============================================================================
log_info "Test 7: Export Log format (detonate export --format log)"
LOG_OUTPUT="${TEST_OUTPUT_DIR}/log.jsonl"
if python3 -m detonate.cli export "${SESSION_ID}" --format log --output "${LOG_OUTPUT}" 2>&1 | grep -q "Exported"; then
    log_pass "Log export completed"
    # Validate JSONL structure (each line is valid JSON)
    if python3 -c "
import json
with open('${LOG_OUTPUT}') as f:
    for line in f:
        if line.strip():
            json.loads(line)
" 2>/dev/null; then
        log_pass "Log JSONL structure valid"
    else
        log_fail "Log JSONL structure invalid"
    fi
else
    log_fail "Log export failed"
fi

# =============================================================================
# Test 8: Timezone-Aware Datetime Verification
# =============================================================================
log_info "Test 8: Timezone-aware datetime verification"

# Check that exported data contains timezone-aware timestamps
# The database stores UTC timestamps, exports should preserve or convert properly
TIMEZONE_CHECK=$(python3 -c "
import json
import sys
from pathlib import Path
import glob

output_dir = Path('${TEST_OUTPUT_DIR}')
errors = []

# Find navigator file
nav_files = glob.glob(str(output_dir / 'navigator_*.json'))
if nav_files:
    try:
        nav_data = json.loads(Path(nav_files[0]).read_text())
        # Navigator layers should have a timestamp
        if 'metadata' in nav_data and 'timestamp' in nav_data['metadata']:
            ts = nav_data['metadata']['timestamp']
            if '+00:00' in ts or 'Z' in ts:
                pass  # Timezone-aware
            else:
                errors.append(f'Navigator timestamp not timezone-aware: {ts}')
    except Exception as e:
        errors.append(f'Navigator check failed: {e}')
else:
    errors.append('Navigator file not found')

# Find STIX file
stix_files = glob.glob(str(output_dir / 'stix_*.json'))
if stix_files:
    try:
        stix_data = json.loads(Path(stix_files[0]).read_text())
        for obj in stix_data.get('objects', []):
            if 'created' in obj:
                ts = obj['created']
                if '+00:00' in ts or 'Z' in ts:
                    pass  # Timezone-aware
                else:
                    errors.append(f'STIX created timestamp not timezone-aware: {ts}')
                break
    except Exception as e:
        errors.append(f'STIX check failed: {e}')
else:
    errors.append('STIX file not found')

# Find log file
log_files = glob.glob(str(output_dir / 'log_*.jsonl'))
if log_files:
    try:
        with open(log_files[0]) as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    if 'timestamp' in entry:
                        ts = entry['timestamp']
                        if '+00:00' in ts or 'Z' in ts:
                            pass  # Timezone-aware
                        else:
                            errors.append(f'Log timestamp not timezone-aware: {ts}')
                        break
    except Exception as e:
        errors.append(f'Log check failed: {e}')
else:
    errors.append('Log file not found')

if errors:
    print('FAIL:' + ';'.join(errors))
else:
    print('PASS')
"
)

if [[ "${TIMEZONE_CHECK}" == "PASS" ]]; then
    log_pass "All timestamps are timezone-aware"
else
    log_fail "Timezone verification failed: ${TIMEZONE_CHECK#FAIL:}"
fi

# =============================================================================
# Test 9: Server Health Check
# =============================================================================
log_info "Test 9: Server health check (detonate serve + curl)"

# Start server in background
python3 -m detonate.cli serve -h 127.0.0.1 -p 8765 &
SERVER_PID=$!
sleep 3

# Check if server is running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    log_fail "Server failed to start"
else
    # Health check via curl
    HEALTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8765/health" 2>/dev/null || echo "000")
    if [ "${HEALTH_RESPONSE}" = "200" ]; then
        log_pass "Health check returned 200 OK"

        # Verify health response body contains expected fields
        HEALTH_BODY=$(curl -s "http://127.0.0.1:8765/health" 2>/dev/null)
        if echo "${HEALTH_BODY}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='healthy' and 'database' in d" 2>/dev/null; then
            log_pass "Health response structure valid (status=healthy, database connected)"
        else
            log_fail "Health response structure invalid"
        fi
    else
        log_fail "Health check returned HTTP ${HEALTH_RESPONSE}"
    fi

    # Stop server
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
fi

# =============================================================================
# Test 10: Show Command
# =============================================================================
log_info "Test 10: Show command (detonate show)"
SHOW_OUTPUT=$(python3 -m detonate.cli show "${SESSION_ID}" 2>&1)
if echo "${SHOW_OUTPUT}" | grep -q "Analysis ID"; then
    log_pass "Show command returned analysis details"
else
    log_fail "Show command failed"
fi

# =============================================================================
# Test 11: C Sample Analysis (trigger_syscalls_c)
# =============================================================================
test_c_syscalls() {
    log_info "=== Test 11: Testing C sample (trigger_syscalls_c) ==="
    
    C_OUTPUT_DIR="${TEST_OUTPUT_DIR}/c_analysis"
    mkdir -p "${C_OUTPUT_DIR}"
    
    # Verify C sample exists
    if [ ! -f "${SCRIPT_DIR}/trigger_syscalls_c" ]; then
        log_info "Building C sample..."
        cd "${SCRIPT_DIR}"
        if ! gcc -static -o trigger_syscalls_c trigger_syscalls.c 2>&1; then
            log_fail "C sample build failed"
            return 1
        fi
        log_pass "C sample built successfully"
    fi
    
    # Verify static linking
    if ldd trigger_syscalls_c 2>&1 | grep -q "not a dynamic executable"; then
        log_pass "C sample is statically linked"
    else
        log_fail "C sample has dynamic dependencies"
    fi
    
    # Analyze with detonate
    log_info "Analyzing C sample with detonate..."
    cd "${SCRIPT_DIR}"
    if ! python3 -m detonate.cli analyze trigger_syscalls_c \
        --platform linux \
        --arch x86_64 \
        --output "${C_OUTPUT_DIR}" \
        2>&1 | grep -q "Analysis complete\|analysis_completed"; then
        log_fail "C sample analysis failed"
        return 1
    fi
    log_pass "C sample analysis completed"
    
    # Find log file
    LOG_FILE=$(ls "${C_OUTPUT_DIR}"/log_*.jsonl 2>/dev/null | head -1)
    if [ -z "$LOG_FILE" ]; then
        log_fail "C analysis log file not created"
        return 1
    fi
    
    # Count unique techniques
    TECH_COUNT=$(grep -o '"technique_id":"T[0-9.]*"' "$LOG_FILE" | sort -u | wc -l)
    log_info "Unique techniques detected: ${TECH_COUNT}"
    
    # Verify exact count (expect 10+ techniques for C sample)
    if [ "$TECH_COUNT" -ge 10 ]; then
        log_pass "Technique count meets expectation (≥10): ${TECH_COUNT}"
    else
        log_fail "Technique count below expectation (≥10): ${TECH_COUNT}"
    fi
    
    # Verify key high-confidence techniques
    log_info "Verifying key technique detections..."
    
    # T1003.008 - Credential Access
    if grep -q '"technique_id":"T1003.008"' "$LOG_FILE"; then
        log_pass "T1003.008 (Credential Access) detected"
    else
        log_fail "T1003.008 (Credential Access) NOT detected"
    fi
    
    # T1548.001 - Setuid/Setgid
    if grep -q '"technique_id":"T1548.001"' "$LOG_FILE"; then
        log_pass "T1548.001 (Setuid/Setgid) detected"
    else
        log_fail "T1548.001 (Setuid/Setgid) NOT detected"
    fi
    
    # T1055 - Process Injection (mmap/mprotect)
    if grep -q '"technique_id":"T1055"' "$LOG_FILE"; then
        log_pass "T1055 (Process Injection) detected"
    else
        log_fail "T1055 (Process Injection) NOT detected"
    fi
    
    # T1071 - Application Layer Protocol
    if grep -q '"technique_id":"T1071"' "$LOG_FILE"; then
        log_pass "T1071 (Application Layer Protocol) detected"
    else
        log_fail "T1071 (Application Layer Protocol) NOT detected"
    fi
    
    # T1070.004 - File Deletion
    if grep -q '"technique_id":"T1070.004"' "$LOG_FILE"; then
        log_pass "T1070.004 (File Deletion) detected"
    else
        log_fail "T1070.004 (File Deletion) NOT detected"
    fi
    
    # T1082 - System Information Discovery
    if grep -q '"technique_id":"T1082"' "$LOG_FILE"; then
        log_pass "T1082 (System Information Discovery) detected"
    else
        log_fail "T1082 (System Information Discovery) NOT detected"
    fi
    
    # T1083 - File and Directory Discovery
    if grep -q '"technique_id":"T1083"' "$LOG_FILE"; then
        log_pass "T1083 (File and Directory Discovery) detected"
    else
        log_fail "T1083 (File and Directory Discovery) NOT detected"
    fi
    
    # T1053.003 - Cron (persistence)
    if grep -q '"technique_id":"T1053.003"' "$LOG_FILE"; then
        log_pass "T1053.003 (Cron) detected"
    else
        log_fail "T1053.003 (Cron) NOT detected"
    fi
    
    # T1543.002 - Systemd Service (persistence)
    if grep -q '"technique_id":"T1543.002"' "$LOG_FILE"; then
        log_pass "T1543.002 (Systemd Service) detected"
    else
        log_fail "T1543.002 (Systemd Service) NOT detected"
    fi
    
    # T1611 - Escape to Host
    if grep -q '"technique_id":"T1611"' "$LOG_FILE"; then
        log_pass "T1611 (Escape to Host) detected"
    else
        log_fail "T1611 (Escape to Host) NOT detected"
    fi
    
    # T1005 - Data from Local System
    if grep -q '"technique_id":"T1005"' "$LOG_FILE"; then
        log_pass "T1005 (Data from Local System) detected"
    else
        log_fail "T1005 (Data from Local System) NOT detected"
    fi
    
    # Verify output files
    if ls "${C_OUTPUT_DIR}"/navigator_*.json 1>/dev/null 2>&1; then
        log_pass "C Navigator layer created"
    else
        log_fail "C Navigator layer missing"
    fi
    
    if ls "${C_OUTPUT_DIR}"/report_*.md 1>/dev/null 2>&1; then
        log_pass "C Markdown report created"
    else
        log_fail "C Markdown report missing"
    fi
    
    log_info "=== C sample tests complete ==="
}

# Run C sample test
test_c_syscalls

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=============================================="
echo "E2E Test Summary"
echo "=============================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo ""

if [ "${FAILED}" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
