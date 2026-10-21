#!/bin/bash
# Ejecuta las pruebas del servidor y el cliente y guarda la salida en
# evidencias/aplicacion_evidencias.txt y el log del servidor en evidencias/aplicacion_audit.log
#
# Necesita la PKI generada y los usuarios precargados (python3 app/registrar.py precarga).
# Pide la passphrase de la CA intermedia para dar de alta, re-emitir y revocar un usuario de prueba.
cd "$(dirname "$0")/.."
SALIDA=evidencias/aplicacion_evidencias.txt
LOG=evidencias/aplicacion_audit.log
PUERTO=8444
NUEVO="prueba$(date +%H%M%S)"
PASS_NUEVO="contraseña-de-$NUEVO"

if [ -z "$INTER_PASS" ]; then
    read -rsp "Passphrase de la CA intermedia: " INTER_PASS; echo
fi
export INTER_PASS

password() {
    case $1 in
        mala) echo "contraseña-incorrecta" ;;
        $NUEVO) echo "$PASS_NUEVO" ;;
        *) grep "^$1," app/data/credenciales.csv | cut -d, -f3 ;;
    esac
}

# cliente <certificado> <usuario> <comandos...>
# Abre el cliente con el certificado del dispositivo y le escribe los comandos.
# "login" va seguido automáticamente de la contraseña del usuario (o de una mala si usuario=mala).
cliente() {
    local cert=$1 usuario=$2 entrada=""
    shift 2
    echo "\$ python3 app/vpn_client.py --cert $cert-fullchain.crt --key $cert.key"
    for c in "$@"; do
        echo "> $c"
        entrada+="$c"$'\n'
        [[ $c == login* ]] && entrada+="$(password $usuario)"$'\n'
    done
    echo "--- respuesta del cliente ---"
    printf '%s' "$entrada" | python3 app/vpn_client.py --puerto $PUERTO --cert $cert-fullchain.crt --key $cert.key 2>/dev/null
    sleep 0.3
    echo "--- log del servidor ---"
    tail -n +$((LINEAS + 1)) $LOG
    LINEAS=$(wc -l < $LOG)
}

prueba() {
    echo
    echo "=== PRUEBA $1 ==="
}

: > $LOG
LINEAS=0
python3 app/vpn_server.py --puerto $PUERTO --log $LOG > /dev/null &
SERVIDOR=$!
sleep 1
C=pki/issued/clients

{
echo "Evidencias del servidor VPN, el cliente y el registro de usuarios ($(date '+%Y-%m-%d %H:%M'))"

prueba "1: tests automáticos"
python3 -m unittest discover -s tests -v 2>&1

prueba "2: login correcto, mensaje y logout (RF2, RF4)"
cliente $C/ana-portatil ana "login ana" "msg hola desde el portatil de ana" "logout"

prueba "3: contraseña incorrecta tres veces"
cliente $C/ana-portatil mala "login ana" "login ana" "login ana" "msg hola"

prueba "4: credenciales correctas de josema desde el portátil de ana"
cliente $C/ana-portatil josema "login josema"

prueba "5: mensaje sin haber hecho login"
cliente $C/ana-portatil ana "msg hola"

prueba "6: cliente sin certificado"
echo "\$ python3 app/vpn_client.py"
printf 'login ana\n%s\n' "$(password ana)" | python3 app/vpn_client.py --puerto $PUERTO 2>/dev/null
sleep 0.3; echo "--- log del servidor ---"; tail -n +$((LINEAS + 1)) $LOG; LINEAS=$(wc -l < $LOG)

prueba "7: las contraseñas se guardan como hash scrypt con sal"
echo "\$ sqlite3 app/data/usuarios.db \"SELECT usuario, rol, hex(sal), hex(hash) FROM usuarios LIMIT 3\""
sqlite3 app/data/usuarios.db "SELECT usuario, rol, hex(sal), hex(hash) FROM usuarios LIMIT 3"

prueba "8: la identidad registrada no se puede modificar ni borrar (RF1)"
echo "\$ sqlite3 app/data/usuarios.db \"UPDATE usuarios SET rol = 'PAS' WHERE usuario = 'ana'\""
sqlite3 app/data/usuarios.db "UPDATE usuarios SET rol = 'PAS' WHERE usuario = 'ana'" 2>&1
echo "\$ sqlite3 app/data/usuarios.db \"DELETE FROM usuarios WHERE usuario = 'ana'\""
sqlite3 app/data/usuarios.db "DELETE FROM usuarios WHERE usuario = 'ana'" 2>&1

prueba "9: alta de un usuario nuevo con emisión de su certificado (RF1)"
echo "\$ python3 app/registrar.py alta $NUEVO PAS portatil"
printf '%s\n%s\n' "$PASS_NUEVO" "$PASS_NUEVO" | python3 app/registrar.py alta $NUEVO PAS portatil 2>&1 | grep -v -i -e warning -e getpass
cliente $C/$NUEVO-portatil $NUEVO "login $NUEVO" "logout"

prueba "10: re-emisión del certificado; el antiguo deja de funcionar y el nuevo sí"
echo "\$ (cd pki && ./reissue_cert.sh $NUEVO PAS portatil)"
(cd pki && ./reissue_cert.sh $NUEVO PAS portatil)
ANTIGUO=$(ls pki/issued/revoked/$NUEVO-portatil-*-fullchain.crt)
cliente ${ANTIGUO%-fullchain.crt} $NUEVO "login $NUEVO"
cliente $C/$NUEVO-portatil $NUEVO "login $NUEVO" "logout"

prueba "11: revocación del certificado; el servidor recarga la CRL y lo rechaza"
echo "\$ (cd pki && ./revoke_cert.sh $NUEVO portatil keyCompromise)"
(cd pki && ./revoke_cert.sh $NUEVO portatil keyCompromise)
REVOCADO=$(ls -t pki/issued/revoked/$NUEVO-portatil-*-fullchain.crt | head -1)
cliente ${REVOCADO%-fullchain.crt} $NUEVO "login $NUEVO"

prueba "12: benchmark con 300 sesiones simultáneas (bench/results/resumen.md)"
cat bench/results/resumen.md
} > $SALIDA

kill $SERVIDOR
echo "Evidencias guardadas en $SALIDA y $LOG"
