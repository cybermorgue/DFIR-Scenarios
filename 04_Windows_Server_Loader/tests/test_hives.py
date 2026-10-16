import struct

import pytest
from regipy.registry import RegistryHive

from gen.const import MCSERVICE, ONEDRIVE, ONESYNC, START_T, TRIAGE_T, hashes
from gen.hives import build_amcache, build_software, build_system
from gen.sim import Sim
from gen.timeline import attack, background
from gen.winfmt import T


@pytest.fixture(scope="module")
def sim():
    s = Sim()
    background(s, START_T, TRIAGE_T)
    attack(s)
    return s


def abrir(tmp_path, data, name):
    p = tmp_path / name
    p.write_bytes(data)
    return RegistryHive(str(p))


def vals(hive, path):
    return {v.name: v.value for v in hive.get_key(path).get_values()}


def test_servicio_onesynchost(sim, tmp_path):
    h = abrir(tmp_path, build_system(sim), "SYSTEM")
    key = h.get_key(r"\ControlSet001\Services\OneSyncHost")
    v = vals(h, r"\ControlSet001\Services\OneSyncHost")
    assert v["ImagePath"] == ONESYNC and v["Start"] == 2 and v["ObjectName"] == "LocalSystem"
    fa = v["FailureActions"]
    assert struct.unpack_from("<I", fa, 0)[0] == 86400
    assert struct.unpack_from("<I", fa, 12)[0] == 3
    assert struct.unpack_from("<II", fa, 20) == (1, 60000)
    assert key.header.last_modified == T(4, 19, 19, 5.0)
    mc = vals(h, r"\ControlSet001\Services\Mirth Connect Service")
    assert mc["ObjectName"] == "LocalSystem" and MCSERVICE in mc["ImagePath"]
    assert vals(h, r"\ControlSet001\Control\ComputerName\ComputerName")["ComputerName"] == "INT01"
    tz = vals(h, r"\ControlSet001\Control\TimeZoneInformation")
    assert tz["TimeZoneKeyName"] == "Romance Standard Time"
    assert tz["Bias"] & 0xFFFFFFFF == 0xFFFFFFC4 and tz["ActiveTimeBias"] & 0xFFFFFFFF == 0xFFFFFF88


def test_amcache_onedrive_sha1(sim, tmp_path):
    h = abrir(tmp_path, build_amcache(sim), "Amcache.hve")
    ents = {}
    for k in h.get_key(r"\Root\InventoryApplicationFile").iter_subkeys():
        d = {v.name: v.value for v in k.get_values()}
        ents[d["LowerCaseLongPath"]] = d
    od, sh = ents[ONEDRIVE.lower()], ents[ONESYNC.lower()]
    assert od["FileId"] == "0000" + hashes(ONEDRIVE)[3] and sh["FileId"] == "0000" + hashes(ONESYNC)[3]
    assert od["Size"] == 9728 and sh["Size"] == 4741632
    assert od["LinkDate"].endswith("1970 00:00:00") or od["LinkDate"] == ""


def test_build_server2019(sim, tmp_path):
    h = abrir(tmp_path, build_software(sim), "SOFTWARE")
    cv = vals(h, r"\Microsoft\Windows NT\CurrentVersion")
    assert cv["CurrentBuild"] == "17763" and cv["UBR"] == 6054 and cv["ProductName"] == "Windows Server 2019 Standard"
    un = {}
    for k in h.get_key(r"\Microsoft\Windows\CurrentVersion\Uninstall").iter_subkeys():
        d = {v.name: v.value for v in k.get_values()}
        un[d["DisplayName"]] = d
    assert un["Mirth Connect"]["DisplayVersion"] == "4.4.0"
    ex = vals(h, r"\Microsoft\Windows Defender\Exclusions\Paths")
    assert r"C:\Program Files\Mirth Connect" in "".join(ex)
    assert "WUServer" in vals(h, r"\Policies\Microsoft\Windows\WindowsUpdate")
