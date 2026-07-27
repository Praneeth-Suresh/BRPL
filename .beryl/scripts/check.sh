#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=paths.sh
source "${SCRIPT_DIR}/paths.sh"

fail() {
  printf "ERROR: %s\n" "$*" >&2
  exit 1
}

if [[ ! -x "${BERYL_ROOT}/scripts/check-md.sh" ]]; then
  fail "Missing .beryl/scripts/check-md.sh (or not executable)."
fi

if [[ ! -x "${BERYL_ROOT}/scripts/check-tests-unchanged.sh" ]]; then
  fail "Missing .beryl/scripts/check-tests-unchanged.sh (or not executable)."
fi

if [[ ! -x "${BERYL_ROOT}/scripts/check-project.sh" ]]; then
  fail "Missing .beryl/scripts/check-project.sh (or not executable)."
fi

if [[ ! -x "${BERYL_ROOT}/scripts/validate-components.sh" ]]; then
  fail "Missing .beryl/scripts/validate-components.sh (or not executable)."
fi

if [[ ! -x "${BERYL_ROOT}/scripts/check-install-surface.sh" ]]; then
  fail "Missing .beryl/scripts/check-install-surface.sh (or not executable)."
fi

if [[ ! -x "${BERYL_ROOT}/scripts/check-secrets.sh" ]]; then
  fail "Missing .beryl/scripts/check-secrets.sh (or not executable)."
fi

if [[ ! -x "${BERYL_ROOT}/scripts/check-brpl.sh" ]]; then
  fail "Missing .beryl/scripts/check-brpl.sh (or not executable)."
fi

printf "Running deterministic checks...\n"

brpl_status=0
"${BERYL_ROOT}/scripts/check-brpl.sh" || brpl_status=$?

"${BERYL_ROOT}/scripts/check-md.sh"
"${BERYL_ROOT}/scripts/validate-components.sh"
"${BERYL_ROOT}/scripts/check-install-surface.sh"
"${BERYL_ROOT}/scripts/check-secrets.sh" --selftest
if [[ "${CHECK_AFFECTED_MODE:-worktree}" == "staged" ]]; then
  "${BERYL_ROOT}/scripts/check-secrets.sh" --staged
else
  "${BERYL_ROOT}/scripts/check-secrets.sh" --worktree
fi
if [[ "${BERYL_SELF_TEST:-}" == "1" || -f "${BERYL_ROOT}/agent/adr/0008-add-brpl-policy-gate.md" ]]; then
  python_bin="python3"
  if ! command -v "${python_bin}" >/dev/null 2>&1; then
    python_bin="python"
  fi
  BRPL_ENFORCEMENT=off PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${BERYL_ROOT}${PYTHONPATH:+:${PYTHONPATH}}" \
    "${python_bin}" -m unittest discover "${BERYL_ROOT}/brpl/tests" -p '*_test.py'
fi
"${BERYL_ROOT}/scripts/check-tests-unchanged.sh"
"${BERYL_ROOT}/scripts/check-project.sh"

if ((brpl_status != 0)); then
  exit "${brpl_status}"
fi
printf "OK\n"
