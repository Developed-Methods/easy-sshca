#!/usr/bin/env bash
set -euo pipefail
binary=${1:?usage: package.sh BINARY TARGET OUTPUT_DIRECTORY}
target=${2:?target required}
output=${3:?output directory required}
mkdir -p "$output"
stage=$(mktemp -d)
trap 'rm -r "$stage"' EXIT
install -Dm755 "$binary" "$stage/easy-sshca/bin/easy-sshca"
install -Dm644 packaging/server.yaml "$stage/easy-sshca/packaging/server.yaml"
install -Dm644 packaging/easy-sshca.service "$stage/easy-sshca/packaging/easy-sshca.service"
install -Dm644 README.md "$stage/easy-sshca/README.md"
install -Dm644 docs/operator-guide.md "$stage/easy-sshca/docs/operator-guide.md"
install -Dm644 docs/verification.md "$stage/easy-sshca/docs/verification.md"
install -Dm644 docs/implementation-plan.html "$stage/easy-sshca/docs/implementation-plan.html"
install -Dm644 proto/easysshca/v1/ca.proto "$stage/easy-sshca/proto/easysshca/v1/ca.proto"
install -Dm755 scripts/install-trust.sh "$stage/easy-sshca/scripts/install-trust.sh"
archive="easy-sshca-${target}.tar.gz"
tar -C "$stage" -czf "$output/$archive" easy-sshca
(cd "$output" && sha256sum "$archive" > "$archive.sha256")
