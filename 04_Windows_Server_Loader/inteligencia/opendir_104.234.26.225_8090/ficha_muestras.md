# Ficha de muestras del open directory

Servidor: `http://104.234.26.225:8090/`. No se entrega ningún binario del atacante: solo estos identificadores.

| Muestra | Tamaño (bytes) | MD5 | SHA-1 | SHA-256 |
| --- | --- | --- | --- | --- |
| OneDrive.exe | 9728 | `215336e9270941186ac2bca89425e49b` | `9a199096b7ed2f23166296e2fde5f8dcdf8dee51` | `ad07d54b62359749b7a32c265e19e5f36cd4962cf957ea6c0fb07ceddb702230` |
| client64.exe | 4741632 | `1e801255fe8d2ac238f59e89cf440b81` | `26be6c96183437760ca0c49042338a1984ffb18c` | `1b6ffac83b04b5772b0b733020f2d66b2b2b9f1a462b4bb179342282a2dbca0f` |
| DLL embebido en client64.exe | 8173568 | `bf2f84fa4d0244e056fd18c719ddfccb` | `f7448bfbc8c60e28fa5f77b3eca9d378e4653894` | `23ba8ede69a54a343e6ec559b507d383e3c8941905e1f56b27864a54c5a59578` |
| winpty-agent.exe | 727552 | `d982861fcb09b0d1f898cb91c2398408` | `a46e23f6e27d6418bd5f3ec438319ddf675be449` | `9add1a61155ec47cf6f347faf776b746eebbde1dc9360d81b8a909da34650642` |
| winpty.dll | 640000 | `1cd271fbb5b1da3e6569aba939c99b10` | `40863bf78e386da10020e519aeff65af70fb335a` | `936f611c2129600d35ab7aad45546a837f4f3a9ca7f673e5d66b48c313b9cd75` |
| run.ps1 | 2915 | `5866e42b2dfba75dcd2d288844f8b5da` | `eba0dce7b6dffbe747a8a66fc4902dba65521372` | `d5322f15c1a7c258e1eeedabc0d7921b7b78f38223db44c3b37c73322c0d6139` |
| run2.ps1 | 3227 | `790b50b31042805f59b81812c24cacae` | `dda4761ca8ba0e635b7ac7927a372a21703c12b9` | `7f6ce972759a0a7b59f7b03936ab56d36ce8d49c33e03f011e09c2410c63cd78` |

Notas:
- `OneDrive.exe` es un loader .NET (`OriginalFileName` `ldr_win3.exe`, sin empresa ni descripción).
- `client64.exe` es un ejecutable Go con cgo ofuscado; el DLL va comprimido dentro.
- `run.ps1` y `run2.ps1`: hashes de los ficheros publicados en el directorio.
- `server.py` y `bootstrap_enc.txt` figuran en el listado pero no se analizaron.
