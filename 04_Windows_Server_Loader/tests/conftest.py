import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import io
import zipfile

import pytest


@pytest.fixture(scope="session")
def _generado(tmp_path_factory):
    from generar_escenario import main
    out = tmp_path_factory.mktemp("salidas")
    sim = main(out_dir=str(out))
    return sim, out


@pytest.fixture(scope="session")
def sim_final(_generado):
    return _generado[0]


@pytest.fixture(scope="session")
def salidas(_generado):
    """ruta relativa -> bytes de todo lo escrito; los miembros de cada ZIP van como 'ruta.zip!miembro' y también sueltos."""
    out = _generado[1]
    d = {}
    for p in sorted(out.rglob("*")):
        if p.is_file():
            rel = p.relative_to(out).as_posix()
            d[rel] = p.read_bytes()
            if rel.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(d[rel])) as z:
                    for n in z.namelist():
                        if not n.endswith("/"):
                            d[f"{rel}!{n}"] = z.read(n)
    return d
