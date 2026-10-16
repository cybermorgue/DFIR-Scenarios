"""Cargas útiles del caso, todas inertes.

- El shellcode es el real con la lectura del PEB (offset 0x475) sustituida por int3: se analiza
  igual que el original, pero no puede resolver ninguna API ni ejecutarse.
- Los scripts son el texto real de run.ps1 y run2.ps1, bug del here-string incluido, con el
  blob regenerado a partir del shellcode neutralizado y la clave XOR real.
- La fase 3 es un buffer ficticio: no contiene código.
"""
import base64
import os
import random

from .const import FUENTES

XOR_KEY = bytes.fromhex("9C9066C118BC1C5BEC80CECD029248DCE0626814CF4D89FBD86AB1354AAEE54A")
STAGE3_KEY = 0x99
STAGE3_SIZE = 8_431_616
STAGE3_HEADER = b"KELBROOK-04 FASE3 FICTICIA\n"


def shellcode() -> bytes:
    with open(os.path.join(FUENTES, "shellcode_neutralizado.hex"), encoding="ascii") as f:
        return bytes.fromhex(f.read().strip())


def blob_b64() -> str:
    sc = shellcode()
    return base64.b64encode(bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(sc))).decode("ascii")


def script(name: str) -> str:
    with open(os.path.join(FUENTES, name + ".txt"), encoding="utf-8", newline="") as f:
        return f.read().replace("{BLOB}", blob_b64())


def handshake() -> bytes:
    """Saludo de 40 bytes que el shellcode envía al :8084 (arquitectura, puerto y host en trozos de 4)."""
    chunks = [b"104.", b"234.", b"26.2", b"25\0\0"] + [b"\0" * 4] * 4
    return b"w64   " + b"\x1f\x94" + b"".join(chunks)


def stage3(size: int) -> bytes:
    """Fase 3 ficticia ya cifrada con XOR 0x99, tal y como viaja por el socket."""
    body = STAGE3_HEADER + random.Random(84).randbytes(max(0, size - len(STAGE3_HEADER)))
    return bytes(b ^ STAGE3_KEY for b in body[:size])
