#!/usr/bin/env bash
set -euo pipefail
url=${1:?usage: install-trust.sh HTTPS_URL EXPECTED_SHA256_FINGERPRINT DESTINATION [TLS_CA]}
expected=${2:?expected fingerprint required}
destination=${3:?destination required}
case "$url" in https://*) ;; *) echo 'HTTPS is required' >&2; exit 2;; esac
candidate=$(mktemp "$(dirname "$destination")/.easy-sshca-trust.XXXXXX")
trap 'rm "$candidate" 2>/dev/null || true' EXIT
options=()
if [[ $# -ge 4 ]]; then options+=(--cacert "$4"); fi
curl --proto '=https' --fail --silent --show-error --max-time 10 "${options[@]}" "$url" -o "$candidate"
fingerprint=$(ssh-keygen -lf "$candidate" -E sha256 | awk '{print $2}')
[[ "$fingerprint" == "$expected" ]] || { echo 'CA fingerprint mismatch' >&2; exit 1; }
chmod 644 "$candidate"
mv "$candidate" "$destination"
