import re

from gen.const import ONEDRIVE, ONESYNC, hashes
from gen.winfmt import FT, TICKS

RX = re.compile(r"^(\S+) \| GET \| (\S+) (\S+) \| UA=(.*)$")
ZIP = "triage/INT01_triage.zip!INT01/"


def f(ev):
    return {n: v for n, _, v in ev.data}


def test_cada_sysmon1_tiene_4688(sim_final):
    s4688 = {(f(e)["NewProcessId"], f(e)["CommandLine"]) for e in sim_final.ev["Security"] if e.eid == 4688}
    s1 = [f(e) for e in sim_final.ev["Sysmon"] if e.eid == 1]
    assert s1
    faltan = [x["Image"] for x in s1 if (x["ProcessId"], x["CommandLine"]) not in s4688]
    assert not faltan, faltan[:5]


def test_accesslog_alineado_con_sysmon(salidas, sim_final):
    log = salidas["inteligencia/opendir_104.234.26.225_8090/access.log"].decode()
    s3 = [e.ft for e in sim_final.ev["Sysmon"] if e.eid == 3 and f(e)["DestinationPort"] == 8090]
    n = 0
    for l in log.splitlines():
        m = RX.match(l)
        if m and m.group(2) == "192.0.2.25":
            d, t = m.group(1).split("T")
            y, mo, dd = map(int, d.split("-"))
            h, mi, s = t.split(":")
            ft = FT(y, mo, dd, int(h), int(mi), float(s))
            assert any(0 <= ft - x <= TICKS for x in s3), l
            n += 1
    assert n == 14           # las 13 reales y la descarga de client64.exe


def test_hashes_reales_en_sysmon_y_amcache(sim_final):
    md5, sha256, imp, sha1 = hashes(ONEDRIVE)
    assert md5 == "215336E9270941186AC2BCA89425E49B" and sha1 == "9a199096b7ed2f23166296e2fde5f8dcdf8dee51"
    for path in (ONEDRIVE, ONESYNC):
        h = hashes(path)
        hs = [f(e)["Hashes"] for e in sim_final.ev["Sysmon"] if e.eid == 1 and f(e)["Image"] == path]
        assert hs and all(x == f"MD5={h[0]},SHA256={h[1]},IMPHASH={h[2]}" for x in hs)
