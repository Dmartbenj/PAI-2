import socket
import ssl
from tls_config import crear_contexto_servidor, identidad_par, suites_tls13_activas

HOST = "127.0.0.1"
PORT = 8443

def main():
    ctx = crear_contexto_servidor()
    print(f"[SERVER] Suites TLS 1.3 activas: {suites_tls13_activas(ctx)}", flush=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock_escucha:
        sock_escucha.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_escucha.bind((HOST, PORT))
        sock_escucha.listen(5)
        print(f"[SERVER] Escuchando en {HOST}:{PORT}", flush=True)
        with ctx.wrap_socket(sock_escucha, server_side=True) as tls_server:
            while True:
                try:
                    conn, addr = tls_server.accept()
                except ssl.SSLError as e:
                    print(f"[SERVER] Handshake RECHAZADO: {e}", flush=True)
                    continue
                except KeyboardInterrupt:
                    break
                with conn:
                    try:
                        identidad = identidad_par(conn)
                        print(f"[SERVER] ACEPTADA {addr} | Versión: {conn.version()} | Suite: {conn.cipher()[0]} | CN={identidad['cn']}, OU={identidad['ou']}", flush=True)
                        datos = conn.recv(1024)
                        if datos:
                            conn.sendall(b"ECO_OK: " + datos)
                    except ssl.SSLError as e:
                        print(f"[SERVER] Error SSL sesión: {e}", flush=True)

if __name__ == "__main__":
    main()
