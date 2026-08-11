#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=paths.sh
source "${SCRIPT_DIR}/paths.sh"

policy_args=()
policy_specs=()
enforcement="auto"
policy_version="${BRPL_POLICY_VERSION:-v2}"
python_bin=""
if [[ -n "${BRPL_ENFORCEMENT+x}" ]]; then
  enforcement="${BRPL_ENFORCEMENT}"
fi

case "${enforcement}" in
  auto)
    if [[ -n "${BRPL_ENFORCEMENT+x}" ]]; then
      printf "ERROR: BRPL_ENFORCEMENT must be off or enforce when set\n" >&2
      exit 2
    fi
    ;;
  off|enforce)
    ;;
  *)
    printf "ERROR: BRPL_ENFORCEMENT must be off or enforce when set\n" >&2
    exit 2
    ;;
esac

if [[ "${policy_version}" != "v2" && "${policy_version}" != "v3" && "${policy_version}" != "v4" ]]; then
  printf "ERROR: BRPL_POLICY_VERSION must be v2, v3, or v4 when set\n" >&2
  exit 2
fi

if [[ "${enforcement}" == "off" ]]; then
  printf "check-brpl: BRPL_ENFORCEMENT=off (skipping)\n"
  exit 0
fi

select_python() {
  local candidate
  for candidate in python3 python; do
    if command -v "${candidate}" >/dev/null 2>&1 && "${candidate}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
      python_bin="${candidate}"
      return 0
    fi
  done
  printf "ERROR: BRPL policy evaluation requires Python >= 3.11\n" >&2
  exit 2
}

add_policy_arg() {
  local label="$1"
  local path="$2"
  if [[ ! -f "${path}" || ! -r "${path}" ]]; then
    printf "ERROR: configured %s policy is missing or unreadable: %s\n" "${label}" "${path}" >&2
    exit 2
  fi
  policy_args+=(--policy "${path}")
  expected_kind="RepositoryPolicy"
  if [[ "${label}" == "task" ]]; then expected_kind="TaskPolicy"; fi
  policy_specs+=("${label}" "${path}" "${expected_kind}")
}

validate_policy_kind() {
  local label="$1"
  local path="$2"
  local expected_kind="$3"
  if [[ "${policy_version}" == "v3" ]]; then
    PYTHONPATH="${BERYL_ROOT}${PYTHONPATH:+:${PYTHONPATH}}" \
      "${python_bin}" -c '
import sys
from pathlib import Path
from brpl.v3 import parse_contract
label, path_text, expected_kind = sys.argv[1:]
try:
    actual = parse_contract(Path(path_text).read_text(encoding="utf-8"), path_text).policy_kind
except Exception as exc:
    print(f"ERROR: {exc}", file=sys.stderr); raise SystemExit(2)
if actual != expected_kind.lower().replace("policy", ""):
    print(f"ERROR: configured {label} v3 policy has kind {actual!r}", file=sys.stderr); raise SystemExit(2)
' "${label}" "${path}" "${expected_kind}"
    return
  fi
  PYTHONPATH="${BERYL_ROOT}${PYTHONPATH:+:${PYTHONPATH}}" \
    "${python_bin}" -c '
import sys
from pathlib import Path
from brpl.v2 import load_policy_file

label, path_text, expected_kind, repo_root_text, enforcement = sys.argv[1:]
try:
    policy_path = Path(path_text).resolve(strict=True)
    if enforcement == "enforce" and policy_path.is_relative_to(Path(repo_root_text).resolve()):
        raise RuntimeError(f"configured {label} policy must be outside the evaluated repository in enforce mode: {path_text}")
    policy = load_policy_file(policy_path)
except Exception as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    raise SystemExit(2) from exc
actual_kind = policy.get("kind")
if actual_kind != expected_kind:
    print(f"ERROR: configured {label} policy has kind {actual_kind!r}, expected {expected_kind!r}: {path_text}", file=sys.stderr)
    raise SystemExit(2)
' "${label}" "${path}" "${expected_kind}" "${REPO_ROOT}" "${enforcement}"
}

resolve_external_file() {
  local label="$1"
  local path="$2"
  if [[ ! -f "${path}" || ! -r "${path}" ]]; then
    printf "ERROR: configured %s is missing, not a regular file, or unreadable: %s\n" "${label}" "${path}" >&2
    exit 2
  fi
  PYTHONPATH="${BERYL_ROOT}${PYTHONPATH:+:${PYTHONPATH}}" \
    "${python_bin}" -c '
import sys
from pathlib import Path

label, path_text, repo_root_text = sys.argv[1:]
try:
    resolved = Path(path_text).resolve(strict=True)
    repo_root = Path(repo_root_text).resolve()
    if not resolved.is_file():
        raise RuntimeError(f"configured {label} must be a regular file: {path_text}")
    if resolved.is_relative_to(repo_root):
        raise RuntimeError(f"configured {label} must be outside the evaluated repository in enforce mode: {path_text}")
except Exception as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    raise SystemExit(2) from exc
print(resolved)
' "${label}" "${path}" "${REPO_ROOT}"
}

if [[ "${policy_version}" == "v4" ]]; then
  if [[ "${enforcement}" != "enforce" ]]; then
    printf "ERROR: BRPL_POLICY_VERSION=v4 requires BRPL_ENFORCEMENT=enforce\n" >&2
    exit 2
  fi
  select_python
  for required in BRPL_REPOSITORY_POLICY BRPL_TASK_POLICY BRPL_CATALOG BRPL_EVIDENCE BRPL_LAUNCH_MANIFEST; do
    if [[ -z "${!required:-}" ]]; then
      printf "ERROR: BRPL_POLICY_VERSION=v4 requires explicit %s\n" "${required}" >&2
      exit 2
    fi
  done
  repo_policy="$(resolve_external_file "repository policy" "${BRPL_REPOSITORY_POLICY}")"
  task_policy="$(resolve_external_file "task policy" "${BRPL_TASK_POLICY}")"
  catalog="$(resolve_external_file "catalog" "${BRPL_CATALOG}")"
  evidence="$(resolve_external_file "evidence" "${BRPL_EVIDENCE}")"
  launch="$(resolve_external_file "launch manifest" "${BRPL_LAUNCH_MANIFEST}")"
  json_args=()
  if [[ -n "${BRPL_JSON_REPORT:-}" ]]; then json_args+=(--json-report "${BRPL_JSON_REPORT}"); fi
  printf "check-brpl: evaluating explicit BRPL v4 policies\n"
  PYTHONPATH="${BERYL_ROOT}${PYTHONPATH:+:${PYTHONPATH}}" "${python_bin}" -m brpl.v4 --repo-root "${REPO_ROOT}" --policy "${repo_policy}" --policy "${task_policy}" --catalog "${catalog}" --evidence "${evidence}" --launch-manifest "${launch}" --enforce "${json_args[@]}"
  exit $?
fi

if [[ "${enforcement}" == "enforce" ]]; then
  if [[ -z "${BRPL_REPOSITORY_POLICY:-}" || -z "${BRPL_TASK_POLICY:-}" ]]; then
    printf "ERROR: BRPL_ENFORCEMENT=enforce requires explicit BRPL_REPOSITORY_POLICY and BRPL_TASK_POLICY paths\n" >&2
    exit 2
  fi
  add_policy_arg "repository" "${BRPL_REPOSITORY_POLICY}"
  add_policy_arg "task" "${BRPL_TASK_POLICY}"
elif [[ -n "${BRPL_REPOSITORY_POLICY:-}" ]]; then
  add_policy_arg "repository" "${BRPL_REPOSITORY_POLICY}"
elif [[ -f "${BERYL_ROOT}/policy/brpl.repository.yml" ]]; then
  add_policy_arg "repository" "${BERYL_ROOT}/policy/brpl.repository.yml"
fi

if [[ "${enforcement}" != "enforce" && -n "${BRPL_TASK_POLICY:-}" ]]; then
  add_policy_arg "task" "${BRPL_TASK_POLICY}"
elif [[ "${enforcement}" != "enforce" && -f "${BERYL_ROOT}/policy/brpl.task.yml" ]]; then
  add_policy_arg "task" "${BERYL_ROOT}/policy/brpl.task.yml"
fi

if ((${#policy_args[@]} == 0)); then
  printf "check-brpl: no BRPL policy configured (OK)\n"
  exit 0
fi

select_python
index=0
while ((index < ${#policy_specs[@]})); do
  validate_policy_kind "${policy_specs[index]}" "${policy_specs[index + 1]}" "${policy_specs[index + 2]}"
  index=$((index + 3))
done

if [[ -z "${BRPL_BASE_REF:-}" ]]; then
  printf "ERROR: BRPL_BASE_REF is required when BRPL policy is configured\n" >&2
  exit 2
fi

registry_args=()
if [[ "${enforcement}" == "enforce" ]]; then
  if [[ -z "${BRPL_CHECK_REGISTRY:-}" ]]; then
    printf "ERROR: BRPL_ENFORCEMENT=enforce requires explicit BRPL_CHECK_REGISTRY path\n" >&2
    exit 2
  fi
  registry_args+=(--check-registry "$(resolve_external_file "check registry" "${BRPL_CHECK_REGISTRY}")")
elif [[ -n "${BRPL_CHECK_REGISTRY:-}" ]]; then
  registry_args+=(--check-registry "${BRPL_CHECK_REGISTRY}")
elif [[ -f "${BERYL_ROOT}/policy/check-registry.json" ]]; then
  registry_args+=(--check-registry "${BERYL_ROOT}/policy/check-registry.json")
fi

capability_args=()
if [[ "${policy_version}" == "v3" ]]; then
  if [[ -z "${BRPL_CAPABILITIES:-}" ]]; then
    printf "ERROR: BRPL_POLICY_VERSION=v3 requires BRPL_CAPABILITIES\n" >&2
    exit 2
  fi
  if [[ "${enforcement}" == "enforce" ]]; then
    capability_args+=(--capabilities "$(resolve_external_file "capabilities" "${BRPL_CAPABILITIES}")")
  else
    capability_args+=(--capabilities "${BRPL_CAPABILITIES}")
  fi
fi

json_args=()
if [[ -n "${BRPL_JSON_REPORT:-}" ]]; then
  json_args+=(--json-report "${BRPL_JSON_REPORT}")
fi

printf "check-brpl: evaluating BRPL policies against %s\n" "${BRPL_BASE_REF}"

runtime_module="brpl.v2"
if [[ "${policy_version}" == "v3" ]]; then runtime_module="brpl.v3.cli"; fi
PYTHONPATH="${BERYL_ROOT}${PYTHONPATH:+:${PYTHONPATH}}" \
  "${python_bin}" -m "${runtime_module}" \
    --repo-root "${REPO_ROOT}" \
    --base "${BRPL_BASE_REF}" \
    "${policy_args[@]}" \
    "${registry_args[@]}" \
    "${capability_args[@]}" \
    "${json_args[@]}"
