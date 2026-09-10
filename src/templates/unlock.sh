#!/usr/bin/env bash
set +x
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "${EASY_SSHCA_BIN:-easy-sshca}" --config "$script_dir/admin.yaml" \
    server unlock --secret-stdin "$@" < "$script_dir/ca.bootstrap-secret"
