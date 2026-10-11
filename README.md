# ps4ufs
Script to retrieve any file from a eap hdd encrypted partition from ps4

## Files

| File | What |
|------|------|
| `ps4ufs.py` | original Python script |
| `ps4ufs.c` / `ps4ufs.exe` | C port (CLI): `parts`, `info`, `ls`, `stat`, `tree`, `cat`, `get`, `getdir`, `find`, `scan`, `carve`, `recover`, `shell` |
| `ps4ufs_gui.c` / `ps4ufs_gui.exe` | original Windows-only Win32 GUI |
| `qt/` | **cross-platform Qt 6 GUI** (`ps4ufs-qt`) built on the same core — Windows, Linux, macOS |

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

## Qt GUI (`ps4ufs-qt`) — Windows / Linux / macOS

The `qt/` directory is a Qt 6 Widgets port of the browser with the same feature set
(partition picker, folder tree + sortable file list, extract with progress/cancel,
recursive find, text/hex viewer, properties, Scan/Recover, drag & drop). It reuses
`ps4ufs.c` **unchanged**: `qt/core_bridge.c` compiles the core with `PS4UFS_GUI`
defined and exposes a small C API (`qt/core_bridge.h`) that the C++ front-end calls;
the core's `die()`/`longjmp` error model is contained entirely within C frames and
surfaced as return codes. Settings persist via `QSettings`.

Prebuilt archives for all three platforms are attached to each
[release](../../releases) (`ps4ufs-qt` GUI + `ps4ufs` CLI per OS).

### Build everything with CMake

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/path/to/Qt/6.x/<kit>
cmake --build build
# -> build/ps4ufs  (CLI)  and  build/ps4ufs-qt  (GUI)
```

If Qt 6 is not found the CLI still builds. Link `-lpthread` is handled by CMake.

## Build the CLI / old Win32 GUI directly

```
gcc -O2 -o ps4ufs ps4ufs.c          # portable CLI (Linux/macOS/MinGW)
cl  /O2 ps4ufs.c                     # MSVC CLI
build_gui.bat                        # original Win32 ps4ufs_gui.exe (MSVC)
build_gui.bat cli                    # + ps4ufs.exe
```

The core compiles the same standalone (its CLI `main` is dropped only when
`PS4UFS_GUI` is defined).
