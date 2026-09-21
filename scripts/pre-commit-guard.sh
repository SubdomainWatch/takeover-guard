#!/usr/bin/env bash
# SubdomainWatch Takeover Guard - Pre-Commit Hook Runner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Check if binary is installed in PATH
if command -v subdomainwatch-guard >/dev/null 2>&1; then
    BIN="subdomainwatch-guard"
elif [ -f "${REPO_ROOT}/guard/bin/subdomainwatch-guard" ]; then
    BIN="${REPO_ROOT}/guard/bin/subdomainwatch-guard"
elif command -v go >/dev/null 2>&1; then
    CACHE_BIN="${HOME}/.cache/subdomainwatch/bin/subdomainwatch-guard"
    mkdir -p "$(dirname "${CACHE_BIN}")"
    if [ ! -f "${CACHE_BIN}" ] || [ "${REPO_ROOT}/guard/cmd/subdomainwatch-guard/main.go" -nt "${CACHE_BIN}" ]; then
        echo "⚙ Building subdomainwatch-guard local binary..." >&2
        (cd "${REPO_ROOT}/guard" && go build -o "${CACHE_BIN}" ./cmd/subdomainwatch-guard)
    fi
    BIN="${CACHE_BIN}"
else
    echo "❌ Error: Neither 'subdomainwatch-guard' nor 'go' found in PATH." >&2
    echo "Please install Go or download subdomainwatch-guard to enable local pre-commit checks." >&2
    exit 1
fi

exec "${BIN}" -local -mode pre-commit -tf-dir . "$@"
