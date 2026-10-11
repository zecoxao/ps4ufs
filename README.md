# ps4ufs
Script to retrieve any file from a eap hdd encrypted partition from ps4

## Files

| File | What |
|------|------|
| `ps4ufs.py` | original Python script |
| `ps4ufs.c` / `ps4ufs.exe` | C port (CLI): `parts`, `info`, `ls`, `stat`, `tree`, `cat`, `get`, `getdir`, `find`, `scan`, `carve`, `recover`, `shell` |
| `ps4ufs_gui.c` / `ps4ufs_gui.exe` | Windows GUI built on the same core |

## GUI

`ps4ufs_gui.exe` is an Explorer-style browser for the encrypted image:

- pick the image (whole-disk GPT image or bare partition) and `keys.bin`, press **Open**
  (or drop the image on the window); the UFS2 partition is auto-detected, or pick a GPT
  entry / bare offset in the **Partition** box. Already-decrypted images are detected
  and open without a key.
- folder tree + sortable file list (size, type, modified, mode, inode); symlinks are followed
- **Extract...** the selected files/folders (or the current folder) with progress and cancel;
  `.pkg` files stored plaintext inside the volume are passed through untouched
- **Find** (name search below the current folder), double-click to view a file (text/hex),
  Alt+Enter for properties
- **Scan PKGs...** = CLI `scan` (Options: dry run, `--defrag`, `--geom`) and
  Actions > **Recover deleted packages** = CLI `recover`; output goes to the log pane, cancelable

Settings are remembered in `ps4ufs_gui.ini` next to the exe.

## Build (MSVC x64)

```
build_gui.bat        :: ps4ufs_gui.exe
build_gui.bat cli    :: ps4ufs_gui.exe + ps4ufs.exe
```

The GUI compiles `ps4ufs.c` in with `PS4UFS_GUI` defined (which turns `die()` into a
recoverable error and drops the CLI `main`), so the CLI still builds standalone with
`gcc -O2 -o ps4ufs ps4ufs.c` / `cl /O2 ps4ufs.c`.
