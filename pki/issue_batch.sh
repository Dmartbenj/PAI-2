#!/bin/bash
set -u
export MSYS_NO_PATHCONV=1

CSV_FILE="${1:-users.csv}"

if [[ ! -f "$CSV_FILE" ]]; then
    echo "ERROR: No existe el fichero $CSV_FILE" >&2
    exit 1
fi

if [[ -z "${INTER_PASS:-}" ]]; then
    read -rsp "Passphrase de la CA intermedia: " INTER_PASS
    echo
    export INTER_PASS
fi

OK_COUNT=0
FAIL_COUNT=0

while IFS=, read -r usuario rol dispositivo; do
    dispositivo="${dispositivo%$'\r'}"
    if ./issue_client.sh "$usuario" "$rol" "$dispositivo"; then
        OK_COUNT=$((OK_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done < <(tail -n +2 "$CSV_FILE")

unset INTER_PASS
echo "Resumen del lote -> Emitidos: $OK_COUNT | Rechazados/Fallidos: $FAIL_COUNT"
