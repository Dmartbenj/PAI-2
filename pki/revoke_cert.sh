#!/bin/bash
set -e
export MSYS_NO_PATHCONV=1

if [[ $# -lt 3 ]]; then
    echo "Uso: $0 <usuario> <dispositivo> <motivo: keyCompromise|superseded|affiliationChanged|cessationOfOperation>" >&2
    exit 1
fi

# 4.1 Validar entradas
USUARIO="${1,,}"
if [[ ! "$USUARIO" =~ ^[a-z][a-z0-9._-]{2,31}$ ]]; then
    echo "ERROR: usuario no válido: '$1'" >&2
    exit 1
fi

DISPOSITIVO="${2,,}"
if [[ ! "$DISPOSITIVO" =~ ^[a-z][a-z0-9._-]{2,31}$ ]]; then
    echo "ERROR: dispositivo no válido: '$2'" >&2
    exit 1
fi

MOTIVO="$3"
case "$MOTIVO" in
    keyCompromise|superseded|affiliationChanged|cessationOfOperation) ;;
    *) echo "ERROR: motivo no válido: '$MOTIVO'" >&2; exit 1 ;;
esac

INVENTARIO="issued/inventario.csv"
if [[ ! -f "$INVENTARIO" ]]; then
    echo "ERROR: no existe el fichero de inventario $INVENTARIO" >&2
    exit 1
fi

# 4.2 Buscar el último serial emitido para ese usuario y dispositivo
SERIAL=$(awk -F, -v u="$USUARIO" -v d="$DISPOSITIVO" \
    '$2==u && $4==d {s=$1} END {print s}' "$INVENTARIO")

if [[ -z "$SERIAL" ]]; then
    echo "ERROR: no existe ningún certificado registrado para $USUARIO/$DISPOSITIVO" >&2
    exit 1
fi

# 4.3 Comprobar que está vigente (V) en intermediate/index.txt
ESTADO=$(awk -F'\t' -v s="$SERIAL" '$4==s {print $1}' intermediate/index.txt)
if [[ "$ESTADO" != "V" ]]; then
    echo "ERROR: el certificado serie $SERIAL de $USUARIO/$DISPOSITIVO no está vigente (estado actual: '$ESTADO')" >&2
    exit 1
fi

if [[ -n "${INTER_PASS:-}" ]]; then
    PASSIN=(-passin env:INTER_PASS)
else
    PASSIN=()
fi

# 4.4 Revocar usando la copia oficial de la CA en newcerts/
openssl ca -config openssl-inter.cnf "${PASSIN[@]}" \
    -revoke "intermediate/newcerts/${SERIAL}.pem" \
    -crl_reason "$MOTIVO" 2>/dev/null

# 4.5 Regenerar CRL de la intermedia y el crl-chain.pem
openssl ca -config openssl-inter.cnf "${PASSIN[@]}" \
    -gencrl -out intermediate/crl/ca-inter.crl.pem 2>/dev/null
cat intermediate/crl/ca-inter.crl.pem root/crl/ca-root.crl.pem > intermediate/crl/crl-chain.pem

# 4.6 Archivar los ficheros del dispositivo en issued/revoked/
mkdir -p issued/revoked
NOMBRE_BASE="${USUARIO}-${DISPOSITIVO}"
for ext in key crt; do
    if [[ -f "issued/clients/${NOMBRE_BASE}.${ext}" ]]; then
        mv "issued/clients/${NOMBRE_BASE}.${ext}" "issued/revoked/${NOMBRE_BASE}-${SERIAL}.${ext}"
    fi
done
if [[ -f "issued/clients/${NOMBRE_BASE}-fullchain.crt" ]]; then
    mv "issued/clients/${NOMBRE_BASE}-fullchain.crt" "issued/revoked/${NOMBRE_BASE}-${SERIAL}-fullchain.crt"
fi

# 4.7 Registrar la revocación en issued/revocaciones.csv
REVOCACIONES="issued/revocaciones.csv"
if [[ ! -f "$REVOCACIONES" ]]; then
    echo "serial,usuario,dispositivo,motivo,fecha" > "$REVOCACIONES"
fi
echo "$SERIAL,$USUARIO,$DISPOSITIVO,$MOTIVO,$(date -u +%FT%TZ)" >> "$REVOCACIONES"

echo "[OK] Revocado serie $SERIAL -> $USUARIO [$DISPOSITIVO] por motivo: $MOTIVO"
