import argparse
import socket
import ssl
from tls_config import crear_contexto_cliente, identidad_par

HOST = "127.0.0.1"
PORT = 8443

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--hostname", default="localhost")
    args = parser.parse_args()

    ctx = crear_contexto_cliente(fullchain_cliente=args.cert, clave_cliente=args.key)
    try:
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=args.hostname) as tls_sock:
                tls_sock.sendall(b"Hola U-Secure VPN")
                respuesta = tls_sock.recv(1024)
                srv_id = identidad_par(tls_sock)
                print(f"[CLIENT] CONECTADO OK | Versión: {tls_sock.version()} | Suite: {tls_sock.cipher()[0]} | Servidor CN={srv_id['cn']} | Respuesta: {respuesta.decode('utf-8', errors='ignore')}")
    except ssl.SSLError as e:
        print(f"[CLIENT] RECHAZADO (SSLError): {e}")
    except Exception as e:
        print(f"[CLIENT] ERROR: {type(e).__name__}: {e}")

if __name__ == "__main__":
    main()
