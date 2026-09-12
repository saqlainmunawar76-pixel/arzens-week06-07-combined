#!/usr/bin/env bash
# =============================================================================
# validate.sh — bonus helper: fmt, validate, and (if tflint is installed) lint
# the whole module tree before every apply. Wire this into CI as a pre-merge
# gate for drift/policy checks.
# =============================================================================
set -euo pipefail

echo "==> terraform fmt (check only)"
terraform fmt -recursive -check

echo "==> terraform init (backend=false, just to validate config)"
terraform init -backend=false -input=false

echo "==> terraform validate"
terraform validate

if command -v tflint >/dev/null 2>&1; then
  echo "==> tflint"
  tflint --recursive
else
  echo "==> tflint not installed, skipping (see https://github.com/terraform-linters/tflint)"
fi

if command -v checkov >/dev/null 2>&1; then
  echo "==> checkov (policy/security scan)"
  checkov -d . --quiet
else
  echo "==> checkov not installed, skipping (pip install checkov for CIS/security posture scanning)"
fi

echo "==> All checks passed."
