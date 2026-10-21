import common
import csv
import getpass
import os
import secrets
import sqlite3
import subprocess
import sys

from common import auditar, ficheros_cert
from db import BaseDatos


def alta(db, usuario, rol, dispositivo, password):
    if db.rol(usuario):
        raise ValueError(f"{usuario} ya está registrado")
    # el registro va unido a la emisión del certificado del dispositivo (CN = usuario, OU = rol)
    if not os.path.exists(ficheros_cert(usuario, dispositivo)[0]):
        subprocess.run(["bash", "issue_client.sh", usuario, rol, dispositivo], cwd=common.PKI, check=True)
    db.registrar(usuario, rol, password)
    auditar("ALTA", usuario=usuario, rol=rol, dispositivo=dispositivo)
    print(f"{usuario} ({rol}) registrado")


def precarga(db, fichero):
    nuevas = []
    for fila in csv.DictReader(open(fichero)):
        usuario, rol, dispositivo = fila["usuario"].lower(), fila["rol"].upper(), fila["dispositivo"].lower()
        if not db.rol(usuario):
            password = secrets.token_urlsafe(12)
            alta(db, usuario, rol, dispositivo, password)
            nuevas.append([usuario, dispositivo, password])

    existia = common.CREDENCIALES.exists()
    with open(common.CREDENCIALES, "a", newline="") as f:
        os.chmod(common.CREDENCIALES, 0o600)
        if not existia:
            f.write("usuario,dispositivo,password\n")
        csv.writer(f, lineterminator="\n").writerows(nuevas)
    print(f"{len(nuevas)} cuentas nuevas, contraseñas en {common.CREDENCIALES}")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] not in ("alta", "precarga"):
        sys.exit(__doc__)

    common.iniciar_log()
    db = BaseDatos()
    if "INTER_PASS" not in os.environ:
        os.environ["INTER_PASS"] = getpass.getpass("Passphrase de la CA intermedia: ")
    try:
        if args[0] == "alta" and len(args) == 4:
            password = getpass.getpass("Contraseña: ")
            if password != getpass.getpass("Repite la contraseña: "):
                sys.exit("Las contraseñas no coinciden")
            alta(db, args[1].lower(), args[2].upper(), args[3].lower(), password)
        elif args[0] == "precarga":
            precarga(db, args[1] if len(args) > 1 else common.PKI / "users.csv")
        else:
            sys.exit(__doc__)
    except (ValueError, sqlite3.Error, subprocess.CalledProcessError) as e:
        sys.exit(f"Error: {e}")
