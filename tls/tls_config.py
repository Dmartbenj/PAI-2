import ssl
from pathlib import Path
from typing import Dict, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent
PKI_DIR = BASE_DIR / "pki"

DEFAULT_CA_ROOT = str(PKI_DIR / "root" / "certs" / "ca-root.crt")
DEFAULT_CRL_CHAIN = str(PKI_DIR / "intermediate" / "crl" / "crl-chain.pem")
DEFAULT_SERVER_FULLCHAIN = str(PKI_DIR / "issued" / "server" / "server-fullchain.crt")
DEFAULT_SERVER_KEY = str(PKI_DIR / "issued" / "server" / "server.key")


def crear_contexto_servidor(
    fullchain_servidor: str = DEFAULT_SERVER_FULLCHAIN,
    clave_servidor: str = DEFAULT_SERVER_KEY,
    ca_raiz: str = DEFAULT_CA_ROOT,
    crl_chain: str = DEFAULT_CRL_CHAIN,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.load_cert_chain(certfile=fullchain_servidor, keyfile=clave_servidor)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=ca_raiz)
    ctx.load_verify_locations(cafile=crl_chain)
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    return ctx


def crear_contexto_cliente(
    fullchain_cliente: Optional[str] = None,
    clave_cliente: Optional[str] = None,
    ca_raiz: str = DEFAULT_CA_ROOT,
    crl_chain: str = DEFAULT_CRL_CHAIN,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.load_verify_locations(cafile=ca_raiz)
    ctx.load_verify_locations(cafile=crl_chain)
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    if fullchain_cliente and clave_cliente:
        ctx.load_cert_chain(certfile=fullchain_cliente, keyfile=clave_cliente)
    return ctx


def identidad_par(conn: ssl.SSLSocket) -> Dict[str, Optional[str]]:
    cert = conn.getpeercert()
    if not cert:
        return {"cn": None, "ou": None}
    cn, ou = None, None
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                cn = value
            elif key == "organizationalUnitName":
                ou = value
    return {"cn": cn, "ou": ou}


def suites_tls13_activas(ctx: ssl.SSLContext) -> list:
    return [c["name"] for c in ctx.get_ciphers() if c.get("protocol") == "TLSv1.3"]
