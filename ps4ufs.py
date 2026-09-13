#!/usr/bin/env python3
r"""
ps4ufs - browse a PS4/FreeBSD UFS2 disk image that is AES-128-XTS encrypted,
decrypting on the fly, while treating *.pkg file contents as plaintext
(they are stored un-encrypted inside the encrypted volume).

Discovered layout for C:\hdd\12.img:
    cipher      : AES-128-XTS  (key = keys.bin, 32 bytes, used verbatim)
    data unit   : 512 bytes
    tweak(sec)  : ivoffset + (byte_offset // 512)      (16-byte little-endian)
    ivoffset    : 111669149696  (0x1A00000000)
    filesystem  : UFS2, little-endian, bsize=32768, fsize=4096

Inspired by / a spiritual port of ufs2tools (https://sourceforge.net/projects/ufs2tools/)
with an added transparent XTS decryption layer + plaintext-.pkg handling.

Usage:
    python ps4ufs.py info
    python ps4ufs.py ls  /
    python ps4ufs.py ls  /system_ex/app
    python ps4ufs.py stat /path/to/file
    python ps4ufs.py tree / --depth 2
    python ps4ufs.py get  /path/to/foo.pkg  D:\out\foo.pkg
    python ps4ufs.py getdir /app  D:\out\app            (recursive extract of a tree)
    python ps4ufs.py getdir /app  D:\out\app --dry-run  (preview, write nothing)
    python ps4ufs.py getdir /app  D:\out\app --skip-pkg --max-size 104857600
    python ps4ufs.py cat  /path/to/text            (prints to stdout)
    python ps4ufs.py find .pkg                      (recursive name search)
    python ps4ufs.py shell                          (interactive browser)

Global options (before the subcommand):
    --img PATH        (default C:\hdd\12.img)
    --keys PATH       (default C:\hdd\keys.bin)
    --ivoffset N      (default 111669149696)
    --no-pkg-plain    (decrypt .pkg contents too, i.e. disable passthrough)
"""
import os
import sys
import stat as pystat
import struct
import argparse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
SECTOR          = 512
SBLOCK_UFS2     = 65536
UFS2_MAGIC      = 0x19540119
ROOTINO         = 2
DINODE_SIZE     = 256
NDADDR          = 12          # direct block pointers
NIADDR          = 3           # indirect block pointers
PKG_MAGIC       = b"\x7fCNT"  # PS4/PS4 .pkg (CNT) magic

S_IFMT  = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000


# ---------------------------------------------------------------------------
# transparent XTS-decrypting block reader
# ---------------------------------------------------------------------------
class CryptImage:
    """Random-access reader over the encrypted image.

    read(off, n)             -> decrypted bytes (filesystem metadata + data)
    read_plain(off, n)       -> raw bytes, no decryption (for .pkg passthrough)
    """
    def __init__(self, path, key, ivoffset):
        self.f = open(path, "rb")
        self.key = key
        self.ivoffset = ivoffset
        self._backend = default_backend()

    def close(self):
        self.f.close()

    def _dec_sector(self, data, sector_index):
        tweak = sector_index.to_bytes(16, "little")
        c = Cipher(algorithms.AES(self.key), modes.XTS(tweak), backend=self._backend)
        d = c.decryptor()
        return d.update(data) + d.finalize()

    def read_plain(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    def read(self, off, n):
        """Decrypt an arbitrary byte range [off, off+n). Handles unaligned
        starts/ends by decrypting whole 512-byte sectors then slicing."""
        start_sec = off // SECTOR
        end_sec   = (off + n + SECTOR - 1) // SECTOR
        base      = start_sec * SECTOR
        raw       = self.read_plain(base, (end_sec - start_sec) * SECTOR)
        out = bytearray()
        for i in range(0, len(raw), SECTOR):
            sec_index = self.ivoffset + (base + i) // SECTOR
            out += self._dec_sector(raw[i:i + SECTOR], sec_index)
        skip = off - base
        return bytes(out[skip:skip + n])


# ---------------------------------------------------------------------------
# UFS2 superblock
# ---------------------------------------------------------------------------
class Superblock:
    def __init__(self, sb):
        i32 = lambda o: struct.unpack_from("<i", sb, o)[0]
        i64 = lambda o: struct.unpack_from("<q", sb, o)[0]
        self.magic     = struct.unpack_from("<I", sb, 1372)[0]
        if self.magic != UFS2_MAGIC:
            raise ValueError("not a UFS2 superblock (magic=0x%08x)" % self.magic)
        self.sblkno    = i32(8)
        self.cblkno    = i32(12)
        self.iblkno    = i32(16)
        self.dblkno    = i32(20)
        self.ncg       = i32(44)
        self.bsize     = i32(48)
        self.fsize     = i32(52)
        self.frag      = i32(56)
        self.bshift    = i32(80)
        self.fshift    = i32(84)
        self.fragshift = i32(96)
        self.fsbtodb   = i32(100)
        self.nindir    = i32(116)
        self.inopb     = i32(120)
        self.ipg       = i32(184)
        self.fpg       = i32(188)
        self.size      = i64(1080)   # frags
        self.bmask     = i32(72)
        self.fmask     = i32(76)

    # --- address arithmetic (all block addresses are in *frag* units) -------
    def cgbase(self, c):        return self.fpg * c
    def cgstart(self, c):       return self.cgbase(c)              # UFS2: no cg offset
    def cgimin(self, c):        return self.cgstart(c) + self.iblkno
    def frag_to_byte(self, fa): return fa * self.fsize
    def blkstofrags(self, b):   return b << self.fragshift

    def ino_to_offset(self, ino):
        cg      = ino // self.ipg
        within  = ino % self.ipg
        blk     = within // self.inopb
        off_in  = within % self.inopb
        fsba    = self.cgimin(cg) + self.blkstofrags(blk)
        return self.frag_to_byte(fsba) + off_in * DINODE_SIZE


# ---------------------------------------------------------------------------
# UFS2 inode
# ---------------------------------------------------------------------------
class Inode:
    def __init__(self, ino, data):
        self.ino     = ino
        self.mode    = struct.unpack_from("<H", data, 0)[0]
        self.nlink   = struct.unpack_from("<h", data, 2)[0]
        self.uid     = struct.unpack_from("<I", data, 4)[0]
        self.gid     = struct.unpack_from("<I", data, 8)[0]
        self.size    = struct.unpack_from("<Q", data, 16)[0]
        self.blocks  = struct.unpack_from("<Q", data, 24)[0]
        self.atime   = struct.unpack_from("<q", data, 32)[0]
        self.mtime   = struct.unpack_from("<q", data, 40)[0]
        self.ctime   = struct.unpack_from("<q", data, 48)[0]
        self.flags   = struct.unpack_from("<I", data, 88)[0]
        self.db      = list(struct.unpack_from("<12q", data, 112))   # direct
        self.ib      = list(struct.unpack_from("<3q",  data, 208))   # indirect
        self._raw    = data

    @property
    def ftype(self):  return self.mode & S_IFMT
    @property
    def isdir(self):  return self.ftype == S_IFDIR
    @property
    def isreg(self):  return self.ftype == S_IFREG
    @property
    def islnk(self):  return self.ftype == S_IFLNK


# ---------------------------------------------------------------------------
# the filesystem
# ---------------------------------------------------------------------------
class UFS2FS:
    def __init__(self, img, pkg_plaintext=True):
        self.img = img
        self.pkg_plaintext = pkg_plaintext
        self.sb = Superblock(img.read(SBLOCK_UFS2, 8192))

    # -- inode fetch --------------------------------------------------------
    def inode(self, ino):
        off = self.sb.ino_to_offset(ino)
        return Inode(ino, self.img.read(off, DINODE_SIZE))

    # -- read one indirect block (metadata -> always decrypted) -------------
    def _read_indirect(self, frag_addr):
        if frag_addr == 0:
            return [0] * self.sb.nindir
        data = self.img.read(self.sb.frag_to_byte(frag_addr), self.sb.bsize)
        return list(struct.unpack_from("<%dq" % self.sb.nindir, data, 0))

    # -- map logical block number -> frag address ---------------------------
    def _bmap(self, inode, lbn):
        nindir = self.sb.nindir
        if lbn < NDADDR:
            return inode.db[lbn]
        lbn -= NDADDR
        # single indirect
        if lbn < nindir:
            l1 = self._read_indirect(inode.ib[0])
            return l1[lbn]
        lbn -= nindir
        # double indirect
        if lbn < nindir * nindir:
            l1 = self._read_indirect(inode.ib[1])
            a  = l1[lbn // nindir]
            l2 = self._read_indirect(a)
            return l2[lbn % nindir]
        lbn -= nindir * nindir
        # triple indirect
        l1 = self._read_indirect(inode.ib[2])
        a  = l1[lbn // (nindir * nindir)]
        l2 = self._read_indirect(a)
        b  = l2[(lbn // nindir) % nindir]
        l3 = self._read_indirect(b)
        return l3[lbn % nindir]

    # -- iterate file contents block by block -------------------------------
    def read_file_iter(self, inode, decrypt_data=True):
        bsize = self.sb.bsize
        remaining = inode.size
        lbn = 0
        while remaining > 0:
            want = min(bsize, remaining)
            addr = self._bmap(inode, lbn)
            if addr == 0:                         # sparse hole
                yield b"\x00" * want
            else:
                boff = self.sb.frag_to_byte(addr)
                if decrypt_data:
                    yield self.img.read(boff, want)
                else:
                    yield self.img.read_plain(boff, want)
            remaining -= want
            lbn += 1

    def read_file(self, inode, decrypt_data=True):
        return b"".join(self.read_file_iter(inode, decrypt_data))

    # -- symlink target -----------------------------------------------------
    def readlink(self, inode):
        # fast symlink: target stored inline in the block-pointer area
        if inode.blocks == 0 or inode.size <= (NDADDR + NIADDR) * 8:
            return inode._raw[112:112 + inode.size].decode("utf-8", "replace")
        return self.read_file(inode).decode("utf-8", "replace")

    # -- directory listing --------------------------------------------------
    def listdir(self, inode):
        """Yields (name, ino, dtype) for a directory inode."""
        data = self.read_file(inode)          # dir data is metadata -> decrypt
        off = 0
        n = len(data)
        while off + 8 <= n:
            d_ino, d_reclen, d_type, d_namlen = struct.unpack_from("<IHBB", data, off)
            if d_reclen == 0:
                break
            if d_ino != 0 and d_namlen > 0:
                name = data[off + 8: off + 8 + d_namlen].decode("utf-8", "replace")
                yield name, d_ino, d_type
            off += d_reclen

    # -- path resolution ----------------------------------------------------
    def resolve(self, path):
        """Resolve an absolute path to an Inode (following symlinks in dirs)."""
        ino = self.inode(ROOTINO)
        if path in ("", "/"):
            return ino
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        for i, part in enumerate(parts):
            if not ino.isdir:
                raise FileNotFoundError("not a directory: " + "/".join(parts[:i]))
            found = None
            for name, cino, _ in self.listdir(ino):
                if name == part:
                    found = cino
                    break
            if found is None:
                raise FileNotFoundError("/" + "/".join(parts[:i + 1]))
            ino = self.inode(found)
            # follow symlink for intermediate components
            if ino.islnk and i < len(parts) - 1:
                target = self.readlink(ino)
                if target.startswith("/"):
                    ino = self.resolve(target)
                else:
                    base = "/" + "/".join(parts[:i])
                    ino = self.resolve(os.path.normpath(base + "/" + target).replace("\\", "/"))
        return ino

    # -- decide whether a file's data should be read as plaintext -----------
    def is_plaintext_pkg(self, name, inode):
        if not self.pkg_plaintext:
            return False
        if not name.lower().endswith(".pkg"):
            return False
        # confirm: first block reads as a raw (un-encrypted) PKG header
        addr = self._bmap(inode, 0)
        if addr == 0:
            return False
        head = self.img.read_plain(self.sb.frag_to_byte(addr), 4)
        return head == PKG_MAGIC

    def extract(self, name, inode, out_fp, progress=None):
        plain = self.is_plaintext_pkg(name, inode)
        written = 0
        for chunk in self.read_file_iter(inode, decrypt_data=not plain):
            out_fp.write(chunk)
            written += len(chunk)
            if progress:
                progress(written, inode.size)
        return plain, written


# ---------------------------------------------------------------------------
# formatting helpers
# ---------------------------------------------------------------------------
def mode_str(mode):
    t = mode & S_IFMT
    ch = {S_IFDIR: "d", S_IFREG: "-", S_IFLNK: "l"}.get(t, "?")
    perm = ""
    for who in (6, 3, 0):
        bits = (mode >> who) & 7
        perm += ("r" if bits & 4 else "-") + ("w" if bits & 2 else "-") + ("x" if bits & 1 else "-")
    return ch + perm

def human(n):
    for u in ("B", "K", "M", "G", "T"):
        if n < 1024 or u == "T":
            return ("%d%s" % (n, u)) if u == "B" else ("%.1f%s" % (n, u))
        n /= 1024


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_info(fs, args):
    sb = fs.sb
    total = sb.size * sb.fsize
    print("UFS2 filesystem")
    print("  magic        : 0x%08x" % sb.magic)
    print("  block size   : %d" % sb.bsize)
    print("  frag size    : %d" % sb.fsize)
    print("  frags/block  : %d" % sb.frag)
    print("  cyl groups   : %d" % sb.ncg)
    print("  inodes/group : %d" % sb.ipg)
    print("  frags/group  : %d" % sb.fpg)
    print("  fs size      : %d frags (%s)" % (sb.size, human(total)))
    print("  pkg-plaintext: %s" % ("on" if fs.pkg_plaintext else "off"))

def _list(fs, path):
    ino = fs.resolve(path)
    if not ino.isdir:
        name = path.rstrip("/").split("/")[-1]
        return [(name, ino)]
    out = []
    for name, cino, _ in sorted(fs.listdir(ino), key=lambda x: x[0]):
        if name in (".", ".."):
            continue
        out.append((name, fs.inode(cino)))
    return out

def cmd_ls(fs, args):
    for name, ino in _list(fs, args.path):
        suffix = ""
        if ino.islnk:
            try:
                suffix = " -> " + fs.readlink(ino)
            except Exception:
                suffix = " -> ?"
        tag = "/" if ino.isdir else ""
        pkg = "  [plaintext pkg]" if ino.isreg and fs.is_plaintext_pkg(name, ino) else ""
        print("%s %10s  %s%s%s%s" % (mode_str(ino.mode), human(ino.size), name, tag, suffix, pkg))

def cmd_stat(fs, args):
    ino = fs.resolve(args.path)
    name = args.path.rstrip("/").split("/")[-1] or "/"
    print("path   : %s" % args.path)
    print("inode  : %d" % ino.ino)
    print("mode   : %s (0o%o)" % (mode_str(ino.mode), ino.mode))
    print("size   : %d (%s)" % (ino.size, human(ino.size)))
    print("blocks : %d (x512)" % ino.blocks)
    print("uid/gid: %d/%d" % (ino.uid, ino.gid))
    print("mtime  : %d" % ino.mtime)
    if ino.isreg:
        print("plaintext-pkg: %s" % fs.is_plaintext_pkg(name, ino))
    if ino.islnk:
        print("target : %s" % fs.readlink(ino))

def cmd_tree(fs, args):
    def walk(path, depth, prefix=""):
        try:
            entries = _list(fs, path)
        except Exception as e:
            print(prefix + "  [error: %s]" % e)
            return
        for i, (name, ino) in enumerate(entries):
            last = i == len(entries) - 1
            conn = "└── " if last else "├── "
            tag = "/" if ino.isdir else ("@" if ino.islnk else "")
            print(prefix + conn + name + tag)
            if ino.isdir and depth > 1:
                ext = "    " if last else "│   "
                walk((path.rstrip("/") + "/" + name), depth - 1, prefix + ext)
    print(args.path)
    walk(args.path, args.depth)

def cmd_cat(fs, args):
    ino = fs.resolve(args.path)
    if not ino.isreg:
        sys.exit("not a regular file")
    name = args.path.rstrip("/").split("/")[-1]
    plain = fs.is_plaintext_pkg(name, ino)
    out = sys.stdout.buffer
    for chunk in fs.read_file_iter(ino, decrypt_data=not plain):
        out.write(chunk)

def cmd_get(fs, args):
    ino = fs.resolve(args.path)
    if not ino.isreg:
        sys.exit("not a regular file")
    name = args.path.rstrip("/").split("/")[-1]
    outpath = args.out
    if os.path.isdir(outpath):
        outpath = os.path.join(outpath, name)
    def prog(done, total):
        pct = (done * 100 // total) if total else 100
        sys.stderr.write("\r  %s / %s (%d%%)" % (human(done), human(total), pct))
        sys.stderr.flush()
    with open(outpath, "wb") as fp:
        plain, written = fs.extract(name, ino, fp, prog)
    sys.stderr.write("\n")
    print("wrote %s (%s)%s" % (outpath, human(written), "  [plaintext pkg]" if plain else "  [decrypted]"))

def cmd_find(fs, args):
    needle = args.name.lower()
    def walk(path, ino, depth):
        if depth <= 0:
            return
        for name, cino, dtype in fs.listdir(ino):
            if name in (".", ".."):
                continue
            full = (path.rstrip("/") + "/" + name)
            if needle in name.lower():
                print(full)
            child = fs.inode(cino)
            if child.isdir:
                walk(full, child, depth - 1)
    walk("", fs.resolve("/"), args.depth)

def cmd_getdir(fs, args):
    """Recursively extract a directory from the image into an output folder,
    mirroring the tree. Regular files use the .pkg-plaintext passthrough;
    symlinks are recorded as '<name>.symlink' sidecar text files (not followed)."""
    src = args.path.rstrip("/") or "/"
    outroot = args.out
    root = fs.resolve(src)
    if not root.isdir:
        # single file: drop it straight into outroot
        os.makedirs(outroot, exist_ok=True)
        name = src.split("/")[-1]
        with open(os.path.join(outroot, name), "wb") as fp:
            plain, n = fs.extract(name, root, fp)
        print("wrote %s (%s)%s" % (name, human(n), "  [plaintext pkg]" if plain else ""))
        return

    st = {"dirs": 0, "files": 0, "links": 0, "bytes": 0, "skipped": 0, "errors": 0}

    def walk(rel, ino, depth):
        for name, cino, _ in fs.listdir(ino):
            if name in (".", ".."):
                continue
            child_rel = (rel + "/" + name) if rel else name
            outpath = os.path.join(outroot, *child_rel.split("/"))
            try:
                child = fs.inode(cino)
                if child.isdir:
                    st["dirs"] += 1
                    if not args.dry_run:
                        os.makedirs(outpath, exist_ok=True)
                    if depth != 0:
                        walk(child_rel, child, depth - 1 if depth > 0 else -1)
                elif child.isreg:
                    if args.skip_pkg and name.lower().endswith(".pkg"):
                        st["skipped"] += 1
                        print("  skip (pkg): /%s/%s" % (src.strip("/"), child_rel))
                        continue
                    if args.max_size and child.size > args.max_size:
                        st["skipped"] += 1
                        print("  skip (>%s): %s (%s)" % (human(args.max_size), child_rel, human(child.size)))
                        continue
                    plain = fs.is_plaintext_pkg(name, child)
                    tag = " [pkg]" if plain else ""
                    print("  %s  %s%s" % (human(child.size).rjust(8), child_rel, tag))
                    if not args.dry_run:
                        os.makedirs(os.path.dirname(outpath) or ".", exist_ok=True)
                        with open(outpath, "wb") as fp:
                            for chunk in fs.read_file_iter(child, decrypt_data=not plain):
                                fp.write(chunk)
                    st["files"] += 1
                    st["bytes"] += child.size
                elif child.islnk:
                    st["links"] += 1
                    target = fs.readlink(child)
                    print("  link      %s -> %s" % (child_rel, target))
                    if not args.dry_run:
                        os.makedirs(os.path.dirname(outpath) or ".", exist_ok=True)
                        with open(outpath + ".symlink", "w", encoding="utf-8") as fp:
                            fp.write(target + "\n")
            except Exception as e:
                st["errors"] += 1
                print("  ERROR %s: %s" % (child_rel, e))

    if not args.dry_run:
        os.makedirs(outroot, exist_ok=True)
    print("extracting %s -> %s%s" % (src, outroot, "  (dry run)" if args.dry_run else ""))
    walk("", root, args.depth)
    print("\ndone: %d dirs, %d files (%s), %d symlinks, %d skipped, %d errors"
          % (st["dirs"], st["files"], human(st["bytes"]), st["links"], st["skipped"], st["errors"]))


def cmd_shell(fs, args):
    cwd = "/"
    print("ps4ufs interactive browser. commands: ls, cd, stat, cat, get <src> <dst>, pwd, find <s>, exit")
    while True:
        try:
            line = input("ps4ufs:%s> " % cwd).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        argv = line.split()
        cmd = argv[0]
        def abspath(p):
            if p.startswith("/"):
                return os.path.normpath(p).replace("\\", "/")
            return os.path.normpath(cwd.rstrip("/") + "/" + p).replace("\\", "/") or "/"
        try:
            if cmd in ("exit", "quit"):
                break
            elif cmd == "pwd":
                print(cwd)
            elif cmd == "ls":
                target = abspath(argv[1]) if len(argv) > 1 else cwd
                cmd_ls(fs, argparse.Namespace(path=target))
            elif cmd == "cd":
                target = abspath(argv[1]) if len(argv) > 1 else "/"
                ino = fs.resolve(target)
                if ino.islnk:
                    tgt = fs.readlink(ino)
                    target = abspath(tgt) if not tgt.startswith("/") else tgt
                    ino = fs.resolve(target)
                if not ino.isdir:
                    print("not a directory")
                else:
                    cwd = target if target else "/"
            elif cmd == "stat":
                cmd_stat(fs, argparse.Namespace(path=abspath(argv[1])))
            elif cmd == "cat":
                cmd_cat(fs, argparse.Namespace(path=abspath(argv[1])))
            elif cmd == "get":
                cmd_get(fs, argparse.Namespace(path=abspath(argv[1]), out=argv[2]))
            elif cmd == "find":
                cmd_find(fs, argparse.Namespace(name=argv[1], depth=64))
            else:
                print("unknown command:", cmd)
        except Exception as e:
            print("error:", e)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Browse an XTS-encrypted PS4 UFS2 image (plaintext .pkg passthrough).")
    p.add_argument("--img",      default=r"C:\hdd\12.img")
    p.add_argument("--keys",     default=r"C:\hdd\keys.bin")
    p.add_argument("--ivoffset", type=int, default=111669149696)
    p.add_argument("--no-pkg-plain", action="store_true", help="decrypt .pkg contents instead of passthrough")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("info")
    sp = sub.add_parser("ls");   sp.add_argument("path", nargs="?", default="/")
    sp = sub.add_parser("stat"); sp.add_argument("path")
    sp = sub.add_parser("tree"); sp.add_argument("path", nargs="?", default="/"); sp.add_argument("--depth", type=int, default=2)
    sp = sub.add_parser("cat");  sp.add_argument("path")
    sp = sub.add_parser("get");  sp.add_argument("path"); sp.add_argument("out")
    sp = sub.add_parser("getdir", help="recursively extract a directory tree")
    sp.add_argument("path"); sp.add_argument("out")
    sp.add_argument("--depth", type=int, default=-1, help="recursion depth (-1 = unlimited)")
    sp.add_argument("--skip-pkg", action="store_true", help="do not extract .pkg files")
    sp.add_argument("--max-size", type=int, default=0, help="skip files larger than N bytes")
    sp.add_argument("--dry-run", action="store_true", help="list what would be extracted, write nothing")
    sp = sub.add_parser("find"); sp.add_argument("name"); sp.add_argument("--depth", type=int, default=64)
    sub.add_parser("shell")

    args = p.parse_args()
    key = open(args.keys, "rb").read()
    img = CryptImage(args.img, key, args.ivoffset)
    fs = UFS2FS(img, pkg_plaintext=not args.no_pkg_plain)

    {
        "info": cmd_info, "ls": cmd_ls, "stat": cmd_stat, "tree": cmd_tree,
        "cat": cmd_cat, "get": cmd_get, "getdir": cmd_getdir, "find": cmd_find, "shell": cmd_shell,
    }[args.cmd](fs, args)

    img.close()


if __name__ == "__main__":
    main()
