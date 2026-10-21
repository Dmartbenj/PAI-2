#!/bin/bash
set -e
export MSYS_NO_PATHCONV=1

if [[ $# -lt 3 ]]; then
    echo "Uso: $0 <usuario> <rol> <dispositivo>" >&2
    exit 1
fi

USUARIO="$1"
ROL="$2"
DISPOSITIVO="$3"

echo "Iniciando re-emisión para $USUARIO ($ROL) [$DISPOSITIVO]..."
./revoke_cert.sh "$USUARIO" "$DISPOSITIVO" superseded
./issue_client.sh "$USUARIO" "$ROL" "$DISPOSITIVO"
echo "[OK] Re-emisión completada con éxito para $USUARIO [$DISPOSITIVO]"
