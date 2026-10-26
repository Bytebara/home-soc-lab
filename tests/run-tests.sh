#!/usr/bin/env bash
# Run every check on the kit. Use it after you edit anything:  bash tests/run-tests.sh
set -uo pipefail
cd "$(dirname "$0")/.."
status=0

echo "== Shell syntax =="
for f in pi/*.sh splunk/*.sh; do
  if bash -n "$f"; then echo "PASS $f"; else echo "FAIL $f"; status=1; fi
done

echo; echo "== ShellCheck (linting) =="
if command -v shellcheck >/dev/null; then
  if shellcheck -x -s bash pi/*.sh splunk/*.sh; then echo "PASS no issues"; else status=1; fi
else
  echo "skipped: install with  sudo apt-get install shellcheck"
fi

echo; echo "== Splunk config, field extractions, dashboard =="
python3 tests/test_kit.py | grep -vE '^(PASS|All checks)' || true
python3 tests/test_kit.py >/dev/null || status=1

echo
if [ "$status" -eq 0 ]; then echo "All checks passed."; else echo "Some checks failed (see above)."; fi
exit "$status"
