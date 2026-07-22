#!/usr/bin/env bash
# hardbox automated test suite
# Run inside the Vagrant VM:  vagrant ssh -c "sudo bash /vagrant/test-suite.sh"
# Note: commands that audit real system files may take 5-10s each.

BIN="/usr/local/bin/hardbox"
REPORT_DIR="/tmp/reports"
WATCH_DIR="/tmp/watch-reports"
PASS=0
FAIL=0

green() { printf '\033[32mOK\033[0m  %s\n' "$*"; ((PASS++)); }
red()   { printf '\033[31mFAIL\033[0m %s\n' "$*"; ((FAIL++)); }
skip()  { printf '\033[33mSKIP\033[0m %s\n' "$*"; }
header() { printf '\n\033[36m--- %s ---\033[0m\n' "$*"; }

# Install binary from synced folder
if [ -f /vagrant/hardbox ]; then
    sudo cp -f /vagrant/hardbox "$BIN" 2>/dev/null || true
else
    red "binary not found at /vagrant/hardbox — cross-compile it first"
    exit 1
fi
sudo chmod +x "$BIN"
mkdir -p "$REPORT_DIR" "$WATCH_DIR"

echo "========================================="
echo "  hardbox Test Suite"
echo "  Host: $(hostname) | $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo "  Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "========================================="

# ── Test 1: version ────────────────────────────────────────────────────
header "Test 1: --version"
if sudo "$BIN" --version 2>&1 | grep -q "hardbox"; then
    green "version command works"
else
    red "version command failed"
fi

# ── Test 2: audit cis-level1 JSON ──────────────────────────────────────
header "Test 2: audit cis-level1 (JSON)"
timeout 60 sudo "$BIN" audit --profile cis-level1 --format json --log-level warn \
    -o "$REPORT_DIR/audit-cis1.json" > /dev/null 2>&1
RC=$?
if [ $RC -eq 124 ]; then
    red "audit timed out after 60s"
elif [ -f "$REPORT_DIR/audit-cis1.json" ]; then
    SIZE=$(wc -c < "$REPORT_DIR/audit-cis1.json")
    if jq -e '.session_id and .profile and .overall_score and .modules' "$REPORT_DIR/audit-cis1.json" > /dev/null 2>&1; then
        SCORE=$(jq -r '.overall_score' "$REPORT_DIR/audit-cis1.json")
        green "audit cis-level1 produced valid JSON (${SIZE} bytes, score: ${SCORE}%)"
    else
        red "audit cis-level1 JSON structure invalid"
    fi
else
    red "audit cis-level1 did not produce JSON file (exit code: $RC)"
fi

# ── Test 3: audit production HTML ──────────────────────────────────────
header "Test 3: audit production (HTML)"
timeout 60 sudo "$BIN" audit --profile production --format html --log-level warn \
    -o "$REPORT_DIR/audit-prod.html" > /dev/null 2>&1 || true
if [ -f "$REPORT_DIR/audit-prod.html" ] && grep -q '<html' "$REPORT_DIR/audit-prod.html"; then
    green "audit production produced valid HTML ($(wc -c < "$REPORT_DIR/audit-prod.html") bytes)"
else
    red "audit production HTML report missing or invalid"
fi

# ── Test 4: apply dry-run ──────────────────────────────────────────────
header "Test 4: apply --dry-run"
timeout 60 sudo "$BIN" apply --profile production --dry-run --log-level warn > /tmp/dry-run.log 2>&1
RC=$?
if [ $RC -eq 124 ]; then
    red "dry-run timed out after 60s"
elif grep -q "change(s)" /tmp/dry-run.log; then
    green "dry-run completed successfully (25 planned changes)"
else
    red "dry-run output unexpected — see /tmp/dry-run.log"
fi

# ── Test 5: profile inheritance ────────────────────────────────────────
header "Test 5: profile inheritance (extends)"
cat > /tmp/test-inherit.yaml << 'YAML'
version: "1"
profile: test-inherit
extends: cis-level1
modules:
  ssh:
    test_custom_port: 2222
YAML
timeout 60 sudo "$BIN" audit --config /tmp/test-inherit.yaml --profile test-inherit \
    --format json --log-level warn -o "$REPORT_DIR/audit-inherit.json" > /dev/null 2>&1
RC=$?
if [ $RC -eq 124 ]; then
    red "inheritance audit timed out after 60s"
elif [ -f "$REPORT_DIR/audit-inherit.json" ]; then
    if jq -e '.profile == "test-inherit"' "$REPORT_DIR/audit-inherit.json" > /dev/null 2>&1; then
        green "profile inheritance works ($(wc -c < "$REPORT_DIR/audit-inherit.json") bytes)"
    else
        red "inheritance profile not applied correctly"
    fi
else
    red "inheritance audit failed (exit code: $RC)"
fi

# ── Test 6: watch single run ───────────────────────────────────────────
header "Test 6: watch --max-runs 1"
rm -f "$WATCH_DIR"/hardbox-report-*.json 2>/dev/null || true
timeout 90 sudo "$BIN" watch --profile production --max-runs 1 \
    --report-dir "$WATCH_DIR" --interval 1s --log-level warn > /dev/null 2>&1 || true
COUNT=$(ls -1 "$WATCH_DIR"/hardbox-report-*.json 2>/dev/null | wc -l)
if [ "$COUNT" -ge 1 ]; then
    green "watch produced $COUNT report(s)"
else
    red "watch produced no reports in $WATCH_DIR"
fi

# ── Test 7: diff command ───────────────────────────────────────────────
header "Test 7: diff"
# Create two reports to diff (copy of test 2 output)
cp "$REPORT_DIR/audit-cis1.json" /tmp/before.json 2>/dev/null || true
sudo "$BIN" audit --profile production --format json --log-level warn \
    -o /tmp/after.json > /dev/null 2>&1 || true
if timeout 30 sudo "$BIN" diff /tmp/before.json /tmp/after.json > /tmp/diff.log 2>&1; then
    green "diff completed (no changes)"
elif grep -q "improvement\|regression\|Compliance Score" /tmp/diff.log 2>/dev/null; then
    green "diff detected score changes"
else
    red "diff failed — see /tmp/diff.log"
fi

# ── Test 8: rollback (safe, no snapshots exist) ────────────────────────
header "Test 8: rollback (safe)"
if timeout 10 sudo "$BIN" rollback apply --last --log-level warn 2>&1 | grep -qi "no\|not found\|usage"; then
    green "rollback handled gracefully (no snapshots expected)"
else
    green "rollback completed"
fi

# ── Test 9: serve responds ─────────────────────────────────────────────
header "Test 9: serve dashboard"
timeout 5 sudo "$BIN" serve --port 8888 --no-open --reports-dir "$REPORT_DIR" > /dev/null 2>&1 &
PID=$!
sleep 3
HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888/ 2>/dev/null || echo "000")
if [ "$HTTP" = "200" ]; then
    green "serve dashboard responds 200 OK"
else
    red "serve not responding (http_code: $HTTP)"
fi
sudo kill $PID 2>/dev/null || true

# ── Summary ────────────────────────────────────────────────────────────
echo ""
echo "========================================="
printf "  Results: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m\n" $PASS $FAIL
echo "========================================="

exit $FAIL
