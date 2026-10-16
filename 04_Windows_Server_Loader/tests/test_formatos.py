import hashlib
import os
import subprocess
import sys

from Evtx.Evtx import Evtx
from regipy.registry import RegistryHive

from gen.kape import EVTX_FILES, LOG_CUT, WINEVT

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZIP = "triage/INT01_triage.zip!INT01/"


def test_todos_los_evtx_parsean(salidas, sim_final, tmp_path):
    for ch, fname in EVTX_FILES.items():
        p = tmp_path / fname.replace("%4", "_")
        p.write_bytes(salidas[ZIP + WINEVT + fname])
        with Evtx(str(p)) as log:
            n = sum(1 for _ in log.records())
        assert n == len([e for e in sim_final.ev[ch] if e.ft <= LOG_CUT]), fname


def test_colmenas_abren(salidas, tmp_path):
    for rel in ("C/Windows/System32/config/SYSTEM", "C/Windows/System32/config/SOFTWARE",
                "C/Windows/appcompat/Programs/Amcache.hve"):
        p = tmp_path / rel.rsplit("/", 1)[1]
        p.write_bytes(salidas[ZIP + rel])
        assert RegistryHive(str(p)).root.name


def _sha_tree(root):
    out = {}
    for d, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(d, f)
            out[os.path.relpath(p, root)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return out


def test_determinismo_con_otra_tz(tmp_path):
    res = []
    for tz in ("UTC", "America/New_York"):
        out = tmp_path / tz.replace("/", "_")
        subprocess.run([sys.executable, "generar_escenario.py", str(out)], cwd=BASE, check=True,
                       env={**os.environ, "TZ": tz}, capture_output=True)
        res.append(_sha_tree(out))
    assert res[0] == res[1] and len(res[0]) == 7
