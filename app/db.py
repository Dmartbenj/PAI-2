import common
import hashlib
import hmac
import os
import sqlite3
import threading
from pathlib import Path

ESQUEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    usuario TEXT PRIMARY KEY,
    rol     TEXT NOT NULL CHECK (rol IN ('PDI', 'PAS', 'INVESTIGADOR')),
    hash    BLOB NOT NULL,
    sal     BLOB NOT NULL
);

-- RF1: una vez registrado, el usuario y su rol no se pueden modificar ni borrar.
-- Su certificado (y su clave pública) solo cambia revocándolo y re-emitiéndolo con pki/.
CREATE TRIGGER IF NOT EXISTS identidad_inmutable BEFORE UPDATE OF usuario, rol ON usuarios
BEGIN SELECT RAISE(ABORT, 'identidad inmutable'); END;

CREATE TRIGGER IF NOT EXISTS usuarios_sin_borrado BEFORE DELETE ON usuarios
BEGIN SELECT RAISE(ABORT, 'identidad inmutable'); END;
"""

limite_scrypt = threading.Semaphore(os.cpu_count())


def hash_password(password, sal):
    with limite_scrypt:
        return hashlib.scrypt(password.encode(), salt=sal, n=2**14, r=8, p=1)


class BaseDatos:
    def __init__(self, ruta=common.BD):
        self.ruta = Path(ruta)
        self.ruta.parent.mkdir(exist_ok=True)
        con = sqlite3.connect(self.ruta)
        con.executescript(ESQUEMA)
        con.close()

    def consulta(self, sql, *args):
        con = sqlite3.connect(self.ruta, timeout=30)
        try:
            with con:
                return con.execute(sql, args).fetchall()
        finally:
            con.close()

    def registrar(self, usuario, rol, password):
        if len(password) < 10:
            raise ValueError("la contraseña debe tener al menos 10 caracteres")
        sal = os.urandom(16)
        self.consulta("INSERT INTO usuarios VALUES (?, ?, ?, ?)", usuario, rol, hash_password(password, sal), sal)

    def comprobar_password(self, usuario, password):
        fila = self.consulta("SELECT hash, sal FROM usuarios WHERE usuario = ?", usuario)
        if not fila:
            return False
        hash_guardado, sal = fila[0]
        return hmac.compare_digest(hash_password(password, sal), hash_guardado)

    def rol(self, usuario):
        fila = self.consulta("SELECT rol FROM usuarios WHERE usuario = ?", usuario)
        return fila[0][0] if fila else None
