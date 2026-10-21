"""Gráficas y tabla comparativa a partir de bench/results/resultados.csv."""
import csv
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CARPETA = Path(__file__).resolve().parent / "results"
COLORES = {"tls": "#2a78d6", "sin_tls": "#eb6834"}
NOMBRES = {"tls": "TLS 1.3 + mTLS", "sin_tls": "TCP sin cifrar"}
METRICAS = ["conexion_p50_ms", "conexion_p95_ms", "login_p50_ms", "rtt_p50_ms", "rtt_p95_ms",
            "throughput_MBps", "cpu_ms_por_sesion", "ram_max_MiB"]

# media de las repeticiones de cada configuración
grupos = defaultdict(list)
for fila in csv.DictReader(open(CARPETA / "resultados.csv")):
    grupos[fila["modo"], int(fila["clientes"]), int(fila["tam"])].append(fila)
medias = {clave: {m: statistics.mean(float(f[m]) for f in filas) for m in METRICAS}
          for clave, filas in grupos.items()}

plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": "#e4e3df"})
fig, ejes = plt.subplots(2, 2, figsize=(9, 6))
graficas = [("conexion_p50_ms", "Conexión + handshake (mediana, ms)"),
            ("rtt_p50_ms", "RTT por mensaje de 1 KiB (mediana, ms)"),
            ("throughput_MBps", "Throughput (MB/s)"),
            ("ram_max_MiB", "Memoria del servidor (MiB)")]
for ax, (metrica, titulo) in zip(ejes.flat, graficas):
    for modo in ("tls", "sin_tls"):
        puntos = sorted((n, m[metrica]) for (mo, n, tam), m in medias.items() if mo == modo and tam == 1024)
        x, y = zip(*puntos)
        ax.plot(x, y, marker="o", linewidth=2, color=COLORES[modo], label=NOMBRES[modo])
    ax.set_title(titulo, loc="left")
    ax.set_xlabel("clientes simultáneos")
    ax.set_xticks(x)
    ax.set_ylim(bottom=0)
ejes[0][0].legend(frameon=False)
fig.tight_layout()
fig.savefig(CARPETA / "benchmark.png", dpi=200)

lineas = ["| Modo | Clientes | Mensaje | Conexión p50/p95 (ms) | Login p50 (ms) | RTT p50/p95 (ms) "
          "| MB/s | CPU ms/sesión | RAM MiB |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
for (modo, n, tam), m in sorted(medias.items(), key=lambda x: (x[0][2], x[0][1], x[0][0])):
    lineas.append(f"| {NOMBRES[modo]} | {n} | {tam} B | {m['conexion_p50_ms']:.1f} / {m['conexion_p95_ms']:.1f} "
                  f"| {m['login_p50_ms']:.1f} | {m['rtt_p50_ms']:.2f} / {m['rtt_p95_ms']:.2f} "
                  f"| {m['throughput_MBps']:.1f} | {m['cpu_ms_por_sesion']:.1f} | {m['ram_max_MiB']:.0f} |")
(CARPETA / "resumen.md").write_text("\n".join(lineas) + "\n")
print("\n".join(lineas))
