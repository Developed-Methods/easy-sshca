#!/usr/bin/env bash
set -euo pipefail
rsa_dependencies=$(cargo tree --locked --target all --invert rsa 2>/dev/null)
if [[ -n "$rsa_dependencies" ]]; then
  echo 'RSA is enabled; remove the audit exception before continuing' >&2
  exit 1
fi
cargo audit
cargo deny check licenses bans sources
