#!/bin/bash
set -e
export MSYS_NO_PATHCONV=1

if [[ -z "${PASS_ROOT:-}" ]]; then
    read -rsp "Passphrase de la CA Raíz: " PASS_ROOT; echo
    export PASS_ROOT
fi

if [[ -z "${INTER_PASS:-}" ]]; then
    read -rsp "Passphrase de la CA Intermedia: " INTER_PASS; echo
    export INTER_PASS
fi

openssl ca -config openssl-root.cnf -gencrl \
    -passin env:PASS_ROOT \
    -out root/crl/ca-root.crl.pem 2>/dev/null

openssl ca -config openssl-inter.cnf -gencrl \
    -passin env:INTER_PASS \
    -out intermediate/crl/ca-inter.crl.pem 2>/dev/null

cat intermediate/crl/ca-inter.crl.pem root/crl/ca-root.crl.pem > intermediate/crl/crl-chain.pem
echo "[OK] CRLs regeneradas y unificadas en intermediate/crl/crl-chain.pem"
