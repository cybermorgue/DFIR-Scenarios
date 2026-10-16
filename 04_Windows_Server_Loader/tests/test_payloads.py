import base64

from gen.payloads import XOR_KEY, blob_b64, handshake, script, shellcode, stage3


def test_shellcode_neutralizado_conserva_analisis():
    sc = shellcode()
    assert len(sc) == 1388
    assert sc[0x475:0x47e] == b"\xcc" * 9
    for h in (0x0726774C, 0x006B8029, 0xE0DF0FEA, 0x6174A599, 0x5F38EBC2, 0xE553A458, 0x5FC8D902,
              0x614D6E75, 0x803428A9, 0x4D7B1E12, 0xD0EB608D, 0x70F2FA31, 0xE449F330):
        assert h.to_bytes(4, "little") in sc
    for s in (b"104.", b"234.", b"26.2", b"\x02\x00\x1f\x94", b"\x80\x34\x39\x99"):
        assert s in sc


def test_blob_descifra_al_shellcode():
    raw = base64.b64decode(blob_b64())
    assert bytes(b ^ XOR_KEY[i % 32] for i, b in enumerate(raw)) == shellcode()


def test_scripts_conservan_el_bug():
    for n in ("run.ps1", "run2.ps1"):
        assert '[DllImport(""kernel32"")]' in script(n) and "{BLOB}" not in script(n)
        assert blob_b64() in script(n)


def test_handshake():
    assert handshake()[:8] == b"w64   \x1f\x94" and len(handshake()) == 40
    assert handshake()[8:24] == b"104.234.26.225\0\0"


def test_stage3():
    d = bytes(b ^ 0x99 for b in stage3(4096))
    assert len(d) == 4096
    assert d.startswith(b"KELBROOK-04 FASE3 FICTICIA\n") and not d.startswith(b"MZ")
    assert stage3(4096) == stage3(4096)
