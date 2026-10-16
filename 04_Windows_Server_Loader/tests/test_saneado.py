import os

import pytest

DIR = os.path.dirname(os.path.abspath(__file__))
PROHIBIDAS = [bytes.fromhex("65488b042560000000")]     # el resto de cadenas va en tests/.prohibidos.txt (local)


def _prohibidos_locales():
    p = os.path.join(DIR, ".prohibidos.txt")
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as fh:
        return [l.strip() for l in fh if l.strip() and not l.startswith("#")]


def test_sin_cadenas_prohibidas_en_salidas(salidas):
    nombres = _prohibidos_locales()
    if nombres is None:
        pytest.skip("falta tests/.prohibidos.txt (local, no versionado): solo se comprueban las cadenas fijas")
    agujas = [(n, n.encode("utf-8").lower(), n.encode("utf-16-le").lower()) for n in nombres]
    agujas += [(a.decode("latin-1"), a.lower(), a.lower()) for a in PROHIBIDAS]
    for ruta, datos in salidas.items():
        bajo = datos.lower()
        for n, u8, u16 in agujas:
            assert u8 not in bajo and u16 not in bajo, (ruta, n)


def test_las_cadenas_fijas_se_comprueban_siempre(salidas):
    for ruta, datos in salidas.items():
        for a in PROHIBIDAS:
            assert a not in datos.lower() and a.decode("latin-1").encode("utf-16-le") not in datos.lower(), ruta


def test_ficheros_versionados_sin_cadenas_reales():
    """Diseño, plan, código y tests también van al repositorio: no pueden llevar los identificadores reales."""
    import subprocess
    nombres = _prohibidos_locales()
    if nombres is None:
        pytest.skip("falta tests/.prohibidos.txt (local, no versionado)")
    raiz = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=DIR, capture_output=True, text=True,
                          check=True).stdout.strip()
    ficheros = subprocess.run(["git", "ls-files"], cwd=raiz, capture_output=True, text=True, check=True).stdout.split("\n")
    for rel in filter(None, ficheros):
        if rel.endswith(".pyc") or not os.path.exists(os.path.join(raiz, rel)):
            continue
        datos = open(os.path.join(raiz, rel), "rb").read().lower()
        for n in nombres:
            assert n.encode("utf-8").lower() not in datos, (rel, "cadena prohibida")
