import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
from db import BaseDatos

PASSWORD = "contraseña-de-prueba"


class TestBaseDatos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = BaseDatos(Path(self.tmp.name) / "test.db")
        self.db.registrar("ana", "PDI", PASSWORD)

    def tearDown(self):
        self.tmp.cleanup()

    def test_password_no_se_guarda_en_claro(self):
        self.assertNotIn(PASSWORD.encode(), self.db.ruta.read_bytes())

    def test_comprobar_password(self):
        self.assertTrue(self.db.comprobar_password("ana", PASSWORD))
        self.assertFalse(self.db.comprobar_password("ana", "otra-contraseña"))
        self.assertFalse(self.db.comprobar_password("nadie", PASSWORD))

    def test_password_corta(self):
        with self.assertRaises(ValueError):
            self.db.registrar("luis", "PAS", "corta")

    def test_usuario_duplicado(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.registrar("ana", "PDI", PASSWORD)

    def test_identidad_inmutable(self):
        for sql in ["UPDATE usuarios SET rol = 'PAS'", "UPDATE usuarios SET usuario = 'eva'", "DELETE FROM usuarios"]:
            with self.subTest(sql), self.assertRaises(sqlite3.IntegrityError):
                self.db.consulta(sql)


if __name__ == "__main__":
    unittest.main()
