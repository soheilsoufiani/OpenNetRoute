# WinDivert native payloads

`WinDivert.dll` (user-mode library) and `WinDivert64.sys` (kernel driver) —
WinDivert 2.2, x64, **unmodified official binaries**.

- Project: https://reqrypt.org/windivert.html (https://github.com/basil00/Divert)
- License: dual **LGPL-3.0-or-later / GPL-2.0**; the binaries are redistributed
  unmodified and the WinDivert license notices must accompany any
  redistribution of these files.

`WinDivert64.sys` must sit next to `WinDivert.dll` in the output directory:
`WinDivertOpen()` installs/starts the driver service pointing at the `.sys`
beside the DLL — a missing `.sys` surfaces as WinDivert error 2
(ERROR_FILE_NOT_FOUND) at START.
