import os
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent

os.environ.setdefault("OPENSSL_CONF", str(RAIZ / "tls" / "openssl-tls.cnf"))
sys.path.insert(0, str(RAIZ / "tls"))

import json
import logging
from datetime import datetime

PKI = RAIZ / "pki"
BD = RAIZ / "app" / "data" / "usuarios.db"
CREDENCIALES = RAIZ / "app" / "data" / "credenciales.csv"
LOG = RAIZ / "logs" / "audit.log"
PUERTO = 8443


# Protocolo: cada mensaje es un objeto JSON en una línea
def enviar(sock, msg):
    sock.sendall(json.dumps(msg).encode() + b"\n")


def recibir(f):
    linea = f.readline(65536)
    if not linea:
        return None
    if not linea.endswith(b"\n"):
        raise ValueError("mensaje demasiado largo")
    msg = json.loads(linea)
    if not isinstance(msg, dict):
        raise ValueError("mensaje no válido")
    return msg


def ficheros_cert(usuario, dispositivo):
    base = PKI / "issued" / "clients" / f"{usuario}-{dispositivo}"
    return f"{base}-fullchain.crt", f"{base}.key"


log = logging.getLogger("auditoria")


def iniciar_log(fichero=LOG):
    Path(fichero).parent.mkdir(exist_ok=True)
    log.addHandler(logging.FileHandler(fichero))
    log.setLevel(logging.INFO)


def auditar(evento, **datos):
    datos = {k: v for k, v in datos.items() if v is not None}
    log.info(json.dumps({"fecha": datetime.now().isoformat(timespec="seconds"), "evento": evento, **datos},
                        ensure_ascii=False))
