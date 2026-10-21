"""Pruebas contra un servidor real. Necesitan la PKI generada (pki/init_ca.sh y
pki/issue_batch.sh users.csv)."""
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
import common
from db import BaseDatos
from vpn_client import Cliente
from vpn_server import Servidor

ANA = common.ficheros_cert("ana", "portatil")


@unittest.skipUnless(Path(ANA[0]).exists(), "falta generar la PKI")
class TestServidor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.log = Path(cls.tmp.name) / "audit.log"
        common.iniciar_log(cls.log)
        db = BaseDatos(Path(cls.tmp.name) / "test.db")
        db.registrar("ana", "PDI", "password-de-ana")
        db.registrar("josema", "PDI", "password-de-josema")
        cls.servidor = Servidor(db, puerto=0)
        cls.sin_tls = Servidor(db, puerto=0, tls=False)
        threading.Thread(target=cls.servidor.servir, daemon=True).start()
        threading.Thread(target=cls.sin_tls.servir, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.servidor.cerrar()
        cls.sin_tls.cerrar()
        cls.tmp.cleanup()

    def conectar(self, cert=ANA):
        cliente = Cliente(self.servidor.puerto, *cert)
        self.addCleanup(cliente.cerrar)
        cliente.conectar()
        return cliente

    def test_login_mensaje_logout(self):
        c = self.conectar()
        self.assertEqual(c.sock.version(), "TLSv1.3")
        self.assertIn(c.sock.cipher()[0], ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"])
        self.assertTrue(c.login("ana", "password-de-ana")["ok"])
        self.assertEqual(c.msg("hola")["eco"], "hola")
        self.assertTrue(c.logout()["ok"])
        self.assertIn('"LOGOUT"', self.log.read_text())

    def test_bloqueo_tras_tres_fallos(self):
        c = self.conectar()
        for _ in range(3):
            respuesta = c.login("ana", "password-incorrecta")
        self.assertEqual(respuesta["msg"], "demasiados intentos")
        with self.assertRaises(OSError):
            c.msg("hola")
        self.assertIn("LOGIN_BLOQUEADO", self.log.read_text())

    def test_usuario_distinto_del_certificado(self):
        # credenciales correctas de josema desde el dispositivo de ana
        self.assertFalse(self.conectar().login("josema", "password-de-josema")["ok"])
        self.assertIn("el usuario no coincide con el certificado", self.log.read_text())

    def test_mensaje_sin_login(self):
        self.assertFalse(self.conectar().msg("hola")["ok"])

    def test_sin_certificado(self):
        with self.assertRaises(OSError):
            self.conectar((None, None)).login("ana", "password-de-ana")
        time.sleep(0.2)  # el servidor escribe el log en su hilo
        self.assertIn("HANDSHAKE_FAIL", self.log.read_text())

    def test_tls12_rechazado(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(("127.0.0.1", self.servidor.puerto)) as s:
            with self.assertRaises(ssl.SSLError):
                ctx.wrap_socket(s)

    def test_sin_tls(self):
        c = Cliente(self.sin_tls.puerto, tls=False)
        c.conectar()
        self.assertTrue(c.login("ana", "password-de-ana")["ok"])
        c.logout()


if __name__ == "__main__":
    unittest.main()
