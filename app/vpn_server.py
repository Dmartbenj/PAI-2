#python app/vpn_server.py
#python app/vpn_server.py --sin-tls --puerto 8080    (solo para el benchmark)

import common
import argparse
import os
import socket
import ssl
import threading

from common import auditar, enviar, recibir
from db import BaseDatos
from tls_config import DEFAULT_CRL_CHAIN, crear_contexto_servidor, identidad_par

MAX_INTENTOS = 3


class Servidor:
    def __init__(self, db, host="127.0.0.1", puerto=common.PUERTO, tls=True):
        self.db = db
        self.tls = tls
        self.ctx = None
        self.fecha_crl = None
        self.sock = socket.create_server((host, puerto), backlog=512)
        self.puerto = self.sock.getsockname()[1]

    def contexto_tls(self):
        # Si se ha revocado algún certificado la CRL cambia y hay que volver a cargarla
        fecha = os.path.getmtime(DEFAULT_CRL_CHAIN)
        if fecha != self.fecha_crl:
            try:
                ctx = crear_contexto_servidor()
            except ssl.SSLError:
                return self.ctx  
            ctx.num_tickets = 0
            self.ctx, self.fecha_crl = ctx, fecha
        return self.ctx

    def servir(self):
        while True:
            try:
                conn, (ip, puerto) = self.sock.accept()
            except OSError:
                return
            ctx = self.contexto_tls() if self.tls else None
            # un hilo por cliente el handshake también se hace dentro del hilo
            threading.Thread(target=self.atender, args=(conn, ctx, f"{ip}:{puerto}"), daemon=True).start()

    def cerrar(self):
        self.sock.close()

    def atender(self, conn, ctx, ip):
        cn = None
        try:
            conn.settimeout(10)
            if ctx:
                try:
                    conn = ctx.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError) as e:
                    auditar("HANDSHAKE_FAIL", ip=ip, motivo=str(e))
                    return
                cert = identidad_par(conn)
                cn = cert["cn"]
                auditar("HANDSHAKE_OK", ip=ip, cn=cn, ou=cert["ou"], version=conn.version(), suite=conn.cipher()[0])
            conn.settimeout(300)
            self.sesion(conn, ip, cn)
        except (OSError, ValueError) as e:
            auditar("DESCONEXION", ip=ip, cn=cn, motivo=str(e))
        finally:
            conn.close()

    def sesion(self, conn, ip, cn):
        f = conn.makefile("rb")
        usuario = None
        fallos = 0
        while True:
            msg = recibir(f)
            if msg is None:
                auditar("DESCONEXION", ip=ip, usuario=usuario, motivo="conexión cerrada sin logout")
                return
            op = msg.get("op")

            if op == "LOGIN" and not usuario:
                nombre = str(msg.get("usuario", "")).lower()
                password = str(msg.get("password", ""))
                # capa 2 de RF2: el usuario debe ser el del certificado y la contraseña correcta
                if self.tls and nombre != cn:
                    error = "el usuario no coincide con el certificado"
                elif not self.db.comprobar_password(nombre, password):
                    error = "usuario o contraseña incorrectos"
                else:
                    usuario = nombre
                    rol = self.db.rol(usuario)
                    auditar("LOGIN_OK", ip=ip, usuario=usuario, rol=rol)
                    enviar(conn, {"ok": True, "rol": rol})
                    continue
                fallos += 1
                auditar("LOGIN_FAIL", ip=ip, cn=cn, usuario=nombre, motivo=error)
                if fallos == MAX_INTENTOS:
                    auditar("LOGIN_BLOQUEADO", ip=ip, cn=cn)
                    enviar(conn, {"ok": False, "msg": "demasiados intentos"})
                    return
                enviar(conn, {"ok": False, "msg": "credenciales no válidas"})

            elif op == "MSG" and usuario:
                # simula el acceso a un recurso de la universidad: devuelve el mensaje
                enviar(conn, {"ok": True, "eco": msg.get("data")})

            elif op == "LOGOUT":
                # RF4: close_notify en los dos sentidos y se cierra el socket
                enviar(conn, {"ok": True})
                auditar("LOGOUT", ip=ip, usuario=usuario)
                f.close()
                if self.tls:
                    conn.settimeout(5)
                    try:
                        conn.unwrap()
                    except OSError:
                        pass
                return

            else:
                enviar(conn, {"ok": False, "msg": "operación no permitida"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--puerto", type=int, default=common.PUERTO)
    parser.add_argument("--sin-tls", action="store_true")
    parser.add_argument("--log", default=common.LOG)
    args = parser.parse_args()

    if args.sin_tls and args.host != "127.0.0.1":
        raise SystemExit("El modo sin TLS solo puede escuchar en 127.0.0.1")
    common.iniciar_log(args.log)
    servidor = Servidor(BaseDatos(), args.host, args.puerto, tls=not args.sin_tls)
    print(f"Escuchando en {args.host}:{servidor.puerto}", flush=True)
    try:
        servidor.servir()
    except KeyboardInterrupt:
        servidor.cerrar()
