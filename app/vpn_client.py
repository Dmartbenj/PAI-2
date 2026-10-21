#python app/vpn_client.py --cert <fullchain.crt> --key <clave.key>
#Comandos: login <usuario>, msg <texto>, logout

import common
import argparse
import getpass
import socket
import ssl

from common import enviar, recibir
from tls_config import crear_contexto_cliente


class Cliente:
    def __init__(self, puerto=common.PUERTO, cert=None, clave=None, tls=True, host="127.0.0.1"):
        self.host = host
        self.puerto = puerto
        self.ctx = crear_contexto_cliente(cert, clave) if tls else None
        self.sock = None

    def conectar(self):
        self.sock = socket.create_connection((self.host, self.puerto), timeout=60)
        if self.ctx:
            # el cliente también comprueba que el servidor es el de la universidad
            self.sock = self.ctx.wrap_socket(self.sock, server_hostname="vpn.usecure.es")
        self.f = self.sock.makefile("rb")

    def pedir(self, msg):
        enviar(self.sock, msg)
        respuesta = recibir(self.f)
        if respuesta is None:
            raise ConnectionError("el servidor ha cerrado la conexión")
        return respuesta

    def login(self, usuario, password):
        return self.pedir({"op": "LOGIN", "usuario": usuario, "password": password})

    def msg(self, texto):
        return self.pedir({"op": "MSG", "data": texto})

    def logout(self):
        respuesta = self.pedir({"op": "LOGOUT"})
        self.f.close()
        if self.ctx:
            self.sock.unwrap()
        self.cerrar()
        return respuesta

    def cerrar(self):
        if self.sock:
            self.sock.close()
            self.sock = None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--puerto", type=int, default=common.PUERTO)
    args = parser.parse_args()

    cliente = Cliente(args.puerto, args.cert, args.key, host=args.host)
    try:
        cliente.conectar()
        print(f"Túnel establecido: {cliente.sock.version()} {cliente.sock.cipher()[0]}")
        while cliente.sock:
            comando, _, texto = input("> ").partition(" ")
            if comando == "login":
                print(cliente.login(texto, getpass.getpass("Contraseña: ")))
            elif comando == "msg":
                print(cliente.msg(texto))
            elif comando == "logout":
                print(cliente.logout())
            else:
                print("Comandos: login <usuario>, msg <texto>, logout")
    except ssl.SSLError as e:
        print("Conexión rechazada:", e)
    except (OSError, EOFError, KeyboardInterrupt) as e:
        print("Conexión cerrada", e)
    finally:
        cliente.cerrar()
