#!/bin/bash
set -e
export MSYS_NO_PATHCONV=1

if [[ $# -lt 3 ]]; then
    echo "Uso: $0 <usuario> <rol: PDI|PAS|INVESTIGADOR> <dispositivo>" >&2
    exit 1
fi

# Paso 1: Normalizar y validar entradas con lista blanca
USUARIO="${1,,}"
if [[ ! "$USUARIO" =~ ^[a-z][a-z0-9._-]{2,31}$ ]]; then
    echo "ERROR: usuario no válido: '$1'" >&2
    exit 1
fi

ROL="${2^^}"
case "$ROL" in
    PDI|PAS|INVESTIGADOR) ;;
    *) echo "ERROR: rol no válido: '$2'" >&2; exit 1 ;;
esac

DISPOSITIVO="${3,,}"
if [[ ! "$DISPOSITIVO" =~ ^[a-z][a-z0-9._-]{2,31}$ ]]; then
    echo "ERROR: dispositivo no válido: '$3'" >&2
    exit 1
fi

mkdir -p issued/clients

NOMBRE_BASE="${USUARIO}-${DISPOSITIVO}"
CLAVE="issued/clients/${NOMBRE_BASE}.key"
CSR="intermediate/csr/${NOMBRE_BASE}.csr"
CERT="issued/clients/${NOMBRE_BASE}.crt"
FULLCHAIN="issued/clients/${NOMBRE_BASE}-fullchain.crt"
INVENTARIO="issued/inventario.csv"

# Paso 2: Inmutabilidad (RF1) - prohibir sobrescribir si ya existe
if [[ -e "$CLAVE" || -e "$CERT" ]]; then
    echo "ERROR: ya existe un certificado para $USUARIO/$DISPOSITIVO" >&2
    exit 1
fi

# Paso 4: Proteger passphrase por variable de entorno
if [[ -n "$INTER_PASS" ]]; then
    PASSIN=(-passin env:INTER_PASS)
else
    PASSIN=()
fi

trap 'rm -f "$CLAVE" "$CSR" "$CERT" "$FULLCHAIN"' ERR

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$CLAVE" 2>/dev/null
chmod 400 "$CLAVE"

openssl req -config openssl-inter.cnf -new \
    -key "$CLAVE" \
    -subj "/C=ES/O=U-Secure/CN=${USUARIO}" \
    -out "$CSR"

openssl ca -config openssl-inter.cnf -batch \
    "${PASSIN[@]}" \
    -extensions client_cert -days 180 -notext \
    -subj "/C=ES/O=U-Secure/OU=${ROL}/CN=${USUARIO}" \
    -in "$CSR" \
    -out "$CERT" 2>/dev/null

cat "$CERT" intermediate/certs/ca-inter.crt > "$FULLCHAIN"
openssl verify -CAfile root/certs/ca-root.crt -untrusted intermediate/certs/ca-inter.crt "$CERT" >/dev/null

# Paso 3: El inventario de la CA
if [[ ! -f "$INVENTARIO" ]]; then
    echo "serial,usuario,rol,dispositivo,fecha" > "$INVENTARIO"
fi
SERIAL=$(openssl x509 -in "$CERT" -noout -serial | cut -d= -f2)
echo "$SERIAL,$USUARIO,$ROL,$DISPOSITIVO,$(date -u +%FT%TZ)" >> "$INVENTARIO"

trap - ERR
echo "[OK] Emitido serie $SERIAL -> $USUARIO ($ROL) [$DISPOSITIVO]"
