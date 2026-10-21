#!/bin/bash
set -e
export MSYS_NO_PATHCONV=1

CLAVE="issued/server/server.key"
CERT="issued/server/server.crt"
INVENTARIO="issued/inventario.csv"

if [[ -e "$CLAVE" || -e "$CERT" ]]; then
    echo "ERROR: ya existe un certificado para el servidor VPN" >&2
    exit 1
fi

mkdir -p issued/server

if [[ -n "$INTER_PASS" ]]; then
    PASSIN=(-passin env:INTER_PASS)
else
    PASSIN=()
fi

echo "[1/4] Generando clave privada del Servidor VPN..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$CLAVE" 2>/dev/null
chmod 400 "$CLAVE"

openssl req -config openssl-inter.cnf -new \
    -key "$CLAVE" \
    -subj "/C=ES/O=U-Secure/OU=Servicios/CN=vpn.usecure.es" \
    -out intermediate/csr/server.csr

echo "[3/4] Firmando certificado del Servidor con la CA Intermedia..."
openssl ca -config openssl-inter.cnf -batch \
    "${PASSIN[@]}" \
    -extensions server_cert -days 365 -notext \
    -subj "/C=ES/O=U-Secure/OU=Servicios/CN=vpn.usecure.es" \
    -in intermediate/csr/server.csr \
    -out "$CERT" 2>/dev/null

echo "[4/4] Creando server-fullchain.crt, verificando y registrando en inventario..."
cat "$CERT" intermediate/certs/ca-inter.crt > issued/server/server-fullchain.crt
openssl verify -CAfile root/certs/ca-root.crt -untrusted intermediate/certs/ca-inter.crt "$CERT"

if [[ ! -f "$INVENTARIO" ]]; then
    echo "serial,usuario,rol,dispositivo,fecha" > "$INVENTARIO"
fi
SERIAL=$(openssl x509 -in "$CERT" -noout -serial | cut -d= -f2)
echo "$SERIAL,vpn.usecure.es,SERVICIOS,servidor,$(date -u +%FT%TZ)" >> "$INVENTARIO"

echo "[OK] Emitido serie $SERIAL -> vpn.usecure.es (SERVICIOS) [servidor]"
