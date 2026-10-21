"""Prueba de carga con N clientes simultáneos, con TLS o sin TLS (RS3).

    python bench/load_test.py --modo tls --clientes 300

Cada cliente conecta, hace login, envía --mensajes mensajes y hace logout.
Ningún cliente empieza a enviar mensajes hasta que los N han hecho login, así
que en ese momento hay N sesiones abiertas a la vez en el servidor.
El resultado se añade a bench/results/resultados.csv.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
import common

import argparse
import csv
import statistics
import subprocess
import threading
import time

import psutil

from vpn_client import Cliente

RESULTADOS = common.RAIZ / "bench" / "results" / "resultados.csv"

parser = argparse.ArgumentParser()
parser.add_argument("--modo", choices=["tls", "sin_tls"], required=True)
parser.add_argument("--clientes", type=int, default=300)
parser.add_argument("--mensajes", type=int, default=50)
parser.add_argument("--tam", type=int, default=1024, help="bytes por mensaje")
parser.add_argument("--puerto", type=int, default=9443)
args = parser.parse_args()
n = args.clientes
tls = args.modo == "tls"

usuarios = [u for u in csv.DictReader(open(common.CREDENCIALES)) if u["usuario"].startswith("bench")][:n]
if len(usuarios) < n:
    sys.exit("Faltan usuarios de prueba: python app/registrar.py precarga bench/bench_users.csv")
clientes = [Cliente(args.puerto, *common.ficheros_cert(u["usuario"], u["dispositivo"]), tls=tls) for u in usuarios]

comando = [sys.executable, common.RAIZ / "app" / "vpn_server.py", "--puerto", str(args.puerto),
           "--log", common.RAIZ / "logs" / f"bench_{args.modo}.log"]
servidor = subprocess.Popen(comando + ([] if tls else ["--sin-tls"]), stdout=subprocess.PIPE)
servidor.stdout.readline()  # espera a que escriba "Escuchando en ..."
proceso = psutil.Process(servidor.pid)

tiempos, finales, conexion, login, rtt, errores = [], [], [], [], [], []
inicio = threading.Barrier(n + 1)
todos_dentro = threading.Barrier(n, action=lambda: tiempos.append(time.perf_counter()))
payload = "x" * args.tam


def cliente(c, u):
    try:
        inicio.wait()
        t0 = time.perf_counter()
        c.conectar()
        t1 = time.perf_counter()
        if not c.login(u["usuario"], u["password"])["ok"]:
            raise RuntimeError("login rechazado")
        conexion.append((t1 - t0) * 1000)
        login.append((time.perf_counter() - t1) * 1000)
        todos_dentro.wait(timeout=120)
        for _ in range(args.mensajes):
            t = time.perf_counter()
            c.msg(payload)
            rtt.append((time.perf_counter() - t) * 1000)
        finales.append(time.perf_counter())
        c.logout()
    except Exception as e:
        errores.append(repr(e))
        todos_dentro.abort()
        c.cerrar()


hilos = [threading.Thread(target=cliente, args=(c, u)) for c, u in zip(clientes, usuarios)]
for h in hilos:
    h.start()
cpu_inicial = sum(proceso.cpu_times()[:2])
inicio.wait()
ram_max = 0
while any(h.is_alive() for h in hilos):
    ram_max = max(ram_max, proceso.memory_info().rss / 2**20)
    time.sleep(0.1)
cpu = sum(proceso.cpu_times()[:2]) - cpu_inicial
servidor.terminate()

if errores:
    sys.exit(f"{len(errores)} clientes con error, por ejemplo: {errores[0]}")

fila = {
    "modo": args.modo,
    "clientes": n,
    "tam": args.tam,
    "conexion_p50_ms": statistics.median(conexion),
    "conexion_p95_ms": statistics.quantiles(conexion, n=20)[-1],
    "login_p50_ms": statistics.median(login),
    "rtt_p50_ms": statistics.median(rtt),
    "rtt_p95_ms": statistics.quantiles(rtt, n=20)[-1],
    "throughput_MBps": 2 * len(rtt) * args.tam / (max(finales) - tiempos[0]) / 1e6,  # ida y vuelta de los mensajes
    "cpu_ms_por_sesion": cpu * 1000 / n,
    "ram_max_MiB": ram_max,
}
fila = {k: round(v, 2) if isinstance(v, float) else v for k, v in fila.items()}
print(fila)

RESULTADOS.parent.mkdir(exist_ok=True)
nuevo = not RESULTADOS.exists()
with open(RESULTADOS, "a", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fila.keys())
    if nuevo:
        w.writeheader()
    w.writerow(fila)
