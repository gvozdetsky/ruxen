#!/usr/bin/env bash
# Generate a self-signed cert for the TLS bench. Used by both nginx and
# ruxen so the cipher / cert-path comparison is exact. Files land in
# /tmp/ruxen-bench-tls/ — outside the repo, regenerated when missing.
set -euo pipefail

CERT_DIR="/tmp/ruxen-bench-tls"
CERT_PATH="${CERT_DIR}/cert.pem"
KEY_PATH="${CERT_DIR}/key.pem"

mkdir -p "${CERT_DIR}"

if [[ -s "${CERT_PATH}" && -s "${KEY_PATH}" ]]; then
    exit 0
fi

# ECDSA P-256 leaf, valid 365 days, SAN=localhost. Same key shared
# between both servers — no CA chain needed for a localhost bench.
openssl req -x509 -nodes \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "${KEY_PATH}" \
    -out "${CERT_PATH}" \
    -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1

ls -lh "${CERT_PATH}" "${KEY_PATH}"
