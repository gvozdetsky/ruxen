#!/usr/bin/env bash
# Generates the htpasswd fixture used by the auth_basic bench scenario.
# Format: user:{SHA}<base64(sha1("hello"))>
# Pre-computed so the script has no openssl/htpasswd dependency.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HTPASSWD="${SCRIPT_DIR}/htpasswd"

EXPECTED='user:{SHA}qvTGHdzF6KLavt4PO0gs2a6pQ00='

if [[ -f "${HTPASSWD}" ]] && [[ "$(cat "${HTPASSWD}")" == "${EXPECTED}" ]]; then
    exit 0
fi

printf '%s\n' "${EXPECTED}" >"${HTPASSWD}"
chmod 0644 "${HTPASSWD}"
