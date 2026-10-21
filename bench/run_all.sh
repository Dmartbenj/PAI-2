#!/bin/bash
# Benchmark completo: 50, 100, 200 y 300 clientes, con y sin TLS, 3 repeticiones.
# Al final, 300 clientes con mensajes de 32 KiB para ver el coste del cifrado.
set -e
cd "$(dirname "$0")/.."
PY=${PYTHON:-.venv/bin/python}

# glibc reserva una arena de memoria por hilo y se queda con los 16 MiB de cada
# scrypt; con 2 arenas el servidor usa la mitad de RAM
export MALLOC_ARENA_MAX=2

rm -f bench/results/resultados.csv
for rep in 1 2 3; do
    for n in 50 100 200 300; do
        $PY bench/load_test.py --modo tls --clientes $n
        $PY bench/load_test.py --modo sin_tls --clientes $n
    done
    $PY bench/load_test.py --modo tls --clientes 300 --mensajes 20 --tam 32768
    $PY bench/load_test.py --modo sin_tls --clientes 300 --mensajes 20 --tam 32768
done
$PY bench/plot.py
