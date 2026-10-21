#!/bin/bash
set -e
export MSYS_NO_PATHCONV=1

if [[ -d "root" || -d "intermediate" || -d "issued" ]]; then
    if [[ "${1:-}" != "--force" ]]; then
        echo "ERROR: Ya existe una PKI activa. Usa './init_ca.sh --force' para borrar root/, intermediate/ e issued/ juntos." >&2
        exit 1
    fi
fi

if [[ -z "${PASS_ROOT:-}" ]]; then
    read -rsp "Passphrase para la CA Raíz: " PASS_ROOT; echo
    export PASS_ROOT
fi

if [[ -z "${INTER_PASS:-}" ]]; then
    read -rsp "Passphrase para la CA Intermedia: " INTER_PASS; echo
    export INTER_PASS
fi

echo "[1/7] Limpiando root/, intermediate/ e issued/ al completo..."
rm -rf root intermediate issued
mkdir -p root/{certs,crl,newcerts,private}
mkdir -p intermediate/{certs,crl,csr,newcerts,private}

chmod 700 root/private intermediate/private
touch root/index.txt intermediate/index.txt

echo 1000 > root/serial
echo 1000 > intermediate/serial
echo 1000 > root/crlnumber
echo 1000 > intermediate/crlnumber

echo "[2/7] Generando clave privada y certificado autofirmado de la CA Raíz..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -aes256 -pass env:PASS_ROOT -out root/private/ca-root.key 2>/dev/null
chmod 400 root/private/ca-root.key

openssl req -config openssl-root.cnf -new -x509 \
    -key root/private/ca-root.key -passin env:PASS_ROOT \
    -days 3650 -extensions v3_ca \
    -subj "/C=ES/O=U-Secure/CN=U-Secure Root CA" \
    -out root/certs/ca-root.crt

echo "[3/7] Generando clave privada y solicitud (CSR) de la CA Intermedia..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -aes256 -pass env:INTER_PASS -out intermediate/private/ca-inter.key 2>/dev/null
chmod 400 intermediate/private/ca-inter.key

openssl req -config openssl-root.cnf -new \
    -key intermediate/private/ca-inter.key -passin env:INTER_PASS \
    -subj "/C=ES/O=U-Secure/CN=U-Secure Issuing CA" \
    -out intermediate/csr/ca-inter.csr

echo "[4/7] Firmando el certificado de la CA Intermedia con la CA Raíz..."
openssl ca -batch -config openssl-root.cnf \
    -passin env:PASS_ROOT \
    -extensions v3_intermediate_ca -days 1825 -notext \
    -in intermediate/csr/ca-inter.csr \
    -out intermediate/certs/ca-inter.crt 2>/dev/null

echo "[5/7] Creando el fichero de cadena (ca-chain.crt)..."
cat intermediate/certs/ca-inter.crt root/certs/ca-root.crt > intermediate/certs/ca-chain.crt

echo "[6/7] Verificando la cadena de certificados..."
openssl verify -CAfile root/certs/ca-root.crt intermediate/certs/ca-inter.crt

echo "[7/7] Generando CRLs iniciales y certificado del Servidor VPN..."
./gen_crl.sh
./issue_server.sh
