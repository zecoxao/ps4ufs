/* core_bridge.c - portable C bridge between ps4ufs.c and the Qt front-end.
 *
 * Compiles the whole ps4ufs core in with PS4UFS_GUI defined, so every static
 * core symbol is reachable here. The core aborts errors by calling gui_die(),
 * which we turn into a thread-local setjmp/longjmp unwind back to the bridge
 * entry point - all within C stack frames, so no C++ destructors are ever
 * crossed. Each public bridge function installs a guard and reports failures
 * as a return code + error string. */

#define PS4UFS_GUI 1
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include "ps4ufs.c"          /* the core (all its symbols are static -> ours) */

#include "core_bridge.h"
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(_WIN32)
  #include <io.h>
  #include <fcntl.h>
  #include <sys/utime.h>
  #define BR_UTIME   _utime
  #define BR_UTIMBUF struct _utimbuf
  #define BR_PIPE(fds) _pipe((fds), 1 << 16, _O_BINARY)
  #define BR_DUP   _dup
  #define BR_DUP2  _dup2
  #define BR_CLOSE _close
  #define BR_READ  _read
  #define BR_FNO   _fileno
#else
  #include <unistd.h>
  #include <utime.h>
  #define BR_UTIME   utime
  #define BR_UTIMBUF struct utimbuf
  #define BR_PIPE(fds) pipe(fds)
  #define BR_DUP   dup
  #define BR_DUP2  dup2
  #define BR_CLOSE close
  #define BR_READ  read
  #define BR_FNO   fileno
#endif

/* ===================== error model (die -> return) ===================== */

#if defined(_MSC_VER)
  #define BR_TLS __declspec(thread)
#else
  #define BR_TLS _Thread_local
#endif

static BR_TLS jmp_buf *t_jb;
static BR_TLS char     t_err[1024];

/* called by the core's die() under PS4UFS_GUI */
static void gui_die(const char *msg) {
    snprintf(t_err, sizeof t_err, "%s", msg ? msg : "error");
    if (t_jb) longjmp(*t_jb, 1);
    /* No recovery point on this thread. The core only ever calls die() on the
     * thread that drives the fs ops (the bridge always guards those), so this
     * is unreachable in practice; abort rather than silently corrupt state. */
    fprintf(stderr, "ps4ufs fatal: %s\n", t_err);
    abort();
}

/* Install a guard. Put at the very top of a function body; on a core error it
 * copies t_err into (err,errsz) and returns FAILVAL. Pair with GUARD_OK() on
 * every normal return path. */
#define GUARD(err, errsz, FAILVAL)                                            \
    jmp_buf _jb; jmp_buf *_prev = t_jb; t_jb = &_jb;                          \
    if (setjmp(_jb)) { t_jb = _prev;                                          \
        if ((err) && (errsz) > 0) snprintf((err), (errsz), "%s", t_err);      \
        return (FAILVAL); }
#define GUARD_OK() (t_jb = _prev)

/* ============================= context ================================= */

struct ps4ufs_ctx {
    CryptImage ci;
    UFS2FS     fs;
    char       img_path[4096];
    uint8_t    key[32];
    int        have_key;
    uint64_t   ivoffset;
    uint64_t   part_offset;
    int        plain;
    int        nthreads;
};

/* ============================ small helpers ============================ */

static void br_set_mtime(const char *path, int64_t mtime, int64_t atime) {
    if (mtime <= 0) return;
    BR_UTIMBUF tb;
    tb.modtime = (time_t)mtime;
    tb.actime  = (time_t)(atime > 0 ? atime : mtime);
    BR_UTIME(path, &tb);
}

/* sanitise one path component for the host filesystem (Windows-strict set, so
 * the same output works everywhere) */
static void br_safe_name(const char *in, char *out, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < cap; i++) {
        unsigned char ch = (unsigned char)in[i];
        int bad = ch < 0x20 || ch == '/' || ch == '\\' || ch == ':' ||
                  ch == '*' || ch == '?' || ch == '"' || ch == '<' ||
                  ch == '>' || ch == '|';
        out[j++] = bad ? '_' : (char)ch;
    }
    out[j] = 0;
    if (j == 0) { out[0] = '_'; out[1] = 0; j = 1; }
    /* Windows dislikes a trailing space or dot */
    while (j > 0 && (out[j - 1] == ' ' || out[j - 1] == '.')) out[--j] = 0;
    if (j == 0) { out[0] = '_'; out[1] = 0; }
}

static void br_path_join(const char *dir, const char *name, char *out, size_t cap) {
    if (!dir || !dir[0] || (dir[0] == '/' && !dir[1]))
        snprintf(out, cap, "/%s", name);
    else
        snprintf(out, cap, "%s/%s", dir, name);
}

static int br_ends_pkg(const char *n) {
    size_t l = strlen(n);
    return l >= 4 &&
           (n[l-4]=='.') && (n[l-3]=='p'||n[l-3]=='P') &&
           (n[l-2]=='k'||n[l-2]=='K') && (n[l-1]=='g'||n[l-1]=='G');
}

static void br_fill_row(ps4ufs_ctx *c, const char *name, const char *path,
                        const Inode *in, ps4ufs_row *r) {
    memset(r, 0, sizeof *r);
    snprintf(r->name, sizeof r->name, "%s", name);
    if (path) snprintf(r->path, sizeof r->path, "%s", path);
    r->ino   = in->ino;
    r->mode  = in->mode;
    r->size  = in->size;
    r->mtime = in->mtime;
    r->is_dir = in_isdir(in);
    r->is_lnk = in_islnk(in);
    r->is_reg = in_isreg(in);
    if (r->is_reg) r->is_pkg = fs_is_plaintext_pkg(&c->fs, name, in);
    if (r->is_lnk) fs_readlink(&c->fs, in, r->link, sizeof r->link);
}

/* resolve a path, then follow a final symlink up to 16 hops (like the GUI's
 * navigate). Leaves the resolved inode in *out. Returns 0 ok / -1 not found. */
static int br_resolve_follow(ps4ufs_ctx *c, const char *path, Inode *out, char *cwd_out, size_t cwdsz) {
    char cur[4096];
    snprintf(cur, sizeof cur, "%s", path && path[0] ? path : "/");
    for (int hop = 0; hop < 16; hop++) {
        if (fs_resolve(&c->fs, cur, out) != 0) return -1;
        if (!in_islnk(out)) { if (cwd_out) snprintf(cwd_out, cwdsz, "%s", cur); return 0; }
        char tgt[4096];
        fs_readlink(&c->fs, out, tgt, sizeof tgt);
        if (tgt[0] == '/') snprintf(cur, sizeof cur, "%s", tgt);
        else {
            /* resolve relative to the link's parent */
            char parent[4096]; snprintf(parent, sizeof parent, "%s", cur);
            char *slash = strrchr(parent, '/');
            if (slash) *slash = 0;
            char joined[4096];
            snprintf(joined, sizeof joined, "%s/%s", parent[0] ? parent : "", tgt);
            char normed[4096];
            norm_path(joined, normed, sizeof normed);
            snprintf(cur, sizeof cur, "%s", normed);
        }
    }
    return -1; /* loop */
}

/* ========================= directory collection ======================== */

typedef struct { char name[256]; uint32_t ino; } br_dent;
typedef struct { br_dent *v; int n, cap; } br_dlist;

static int br_dent_cb(const char *name, uint32_t ino, uint8_t dtype, void *ud) {
    (void)dtype;
    br_dlist *dl = (br_dlist *)ud;
    if (!strcmp(name, ".") || !strcmp(name, "..")) return 0;
    if (dl->n >= dl->cap) {
        int nc = dl->cap ? dl->cap * 2 : 64;
        br_dent *nv = (br_dent *)realloc(dl->v, (size_t)nc * sizeof(br_dent));
        if (!nv) return 1;
        dl->v = nv; dl->cap = nc;
    }
    snprintf(dl->v[dl->n].name, sizeof dl->v[dl->n].name, "%s", name);
    dl->v[dl->n].ino = ino;
    dl->n++;
    return 0;
}

/* ============================ scan_parts =============================== */

int ps4ufs_scan_parts(const char *img_path,
                      const uint8_t key[32], int have_key, uint64_t ivoffset,
                      ps4ufs_part *out, int max, char *err, int errsz) {
    GUARD(err, errsz, -1);
    build_inv_sbox();
    int n = 0;
    FILE *f = fopen(img_path, "rb");
    if (!f) { GUARD_OK(); if (err) snprintf(err, errsz, "cannot open image: %s", img_path); return -1; }

    xts_ctx xts; int have_xts = 0;
    if (have_key) { xts_init(&xts, key); have_xts = 1; }

    /* bare partition at offset 0 */
    if (n < max) {
        out[n].index = -1; out[n].base = 0; out[n].size = 0;
        out[n].is_plain = probe_ufs2_plain(f, 0);
        out[n].is_ufs2  = out[n].is_plain ? 1 :
                          (have_xts ? probe_ufs2(f, &xts, 0, ivoffset) : 0);
        n++;
    }

    /* GPT entries */
    gpt_part parts[256];
    int ng = gpt_read(f, parts, 256);
    for (int i = 0; i < ng && n < max; i++) {
        out[n].index = parts[i].index;
        out[n].base  = parts[i].base;
        out[n].size  = parts[i].size;
        out[n].is_plain = probe_ufs2_plain(f, parts[i].base);
        out[n].is_ufs2  = out[n].is_plain ? 1 :
                          (have_xts ? probe_ufs2(f, &xts, parts[i].base, ivoffset) : 0);
        n++;
    }
    fclose(f);
    GUARD_OK();
    return n;
}

/* =============================== open ================================== */

ps4ufs_ctx *ps4ufs_open(const char *img_path,
                        const uint8_t key[32], int have_key, uint64_t ivoffset,
                        uint64_t part_offset, int plain, int pkg_plaintext,
                        int nthreads, char *err, int errsz) {
    GUARD(err, errsz, NULL);
    build_inv_sbox();

    ps4ufs_ctx *c = (ps4ufs_ctx *)calloc(1, sizeof *c);
    if (!c) { GUARD_OK(); if (err) snprintf(err, errsz, "out of memory"); return NULL; }
    snprintf(c->img_path, sizeof c->img_path, "%s", img_path);
    if (have_key) memcpy(c->key, key, 32);
    c->have_key    = have_key;
    c->ivoffset    = ivoffset;
    c->part_offset = part_offset;
    c->plain       = plain;

    if (nthreads <= 0) nthreads = cpu_count();
    if (nthreads < 1)  nthreads = 1;
    if (nthreads > 64) nthreads = 64;
    c->nthreads = nthreads;
    g_nthreads  = nthreads;
    if (g_nthreads > 1) pool_init(g_nthreads);  /* must precede any ci_read */

    ci_open(&c->ci, img_path, c->key, ivoffset, part_offset, plain);
    fs_init(&c->fs, &c->ci, pkg_plaintext);

    GUARD_OK();
    return c;
}

void ps4ufs_close(ps4ufs_ctx *c) {
    if (!c) return;
    if (g_nthreads > 1) pool_shutdown();
    ci_close(&c->ci);
    free(c);
}

void ps4ufs_set_pkg_plaintext(ps4ufs_ctx *c, int on) {
    if (c) c->fs.pkg_plaintext = on ? 1 : 0;
}

void ps4ufs_info_text(ps4ufs_ctx *c, char *buf, int bufsz) {
    const Superblock *sb = &c->fs.sb;
    snprintf(buf, bufsz,
        "magic        : 0x%08x\n"
        "block size   : %d\n"
        "frag size    : %d\n"
        "frags/block  : %d\n"
        "cyl groups   : %d\n"
        "inodes/group : %d\n"
        "frags/group  : %d\n"
        "fs size      : %lld frags (%s)\n"
        "storage      : %s\n",
        sb->magic, sb->bsize, sb->fsize, sb->frag, sb->ncg, sb->ipg, sb->fpg,
        (long long)sb->size, human((uint64_t)sb->size * (uint64_t)sb->fsize),
        c->plain ? "already decrypted (no key)" : "AES-128-XTS encrypted");
}

/* =============================== list ================================== */

int ps4ufs_list(ps4ufs_ctx *c, const char *path,
                ps4ufs_row **rows, int *count, char *err, int errsz) {
    GUARD(err, errsz, -1);
    *rows = NULL; *count = 0;

    Inode dir;
    char cwd[4096];
    if (br_resolve_follow(c, path, &dir, cwd, sizeof cwd) != 0) {
        GUARD_OK(); if (err) snprintf(err, errsz, "not found: %s", path); return -1;
    }
    if (!in_isdir(&dir)) {
        GUARD_OK(); if (err) snprintf(err, errsz, "not a directory: %s", path); return -1;
    }

    br_dlist dl = {0};
    fs_listdir(&c->fs, &dir, br_dent_cb, &dl);

    ps4ufs_row *out = (ps4ufs_row *)calloc((size_t)(dl.n ? dl.n : 1), sizeof(ps4ufs_row));
    int rn = 0;
    for (int i = 0; i < dl.n; i++) {
        Inode in;
        fs_inode(&c->fs, dl.v[i].ino, &in);
        char p[1024];
        br_path_join(cwd, dl.v[i].name, p, sizeof p);
        br_fill_row(c, dl.v[i].name, p, &in, &out[rn++]);
    }
    free(dl.v);
    *rows = out; *count = rn;
    GUARD_OK();
    return 0;
}

void ps4ufs_free_rows(ps4ufs_row *rows) { free(rows); }

int ps4ufs_stat(ps4ufs_ctx *c, const char *path, ps4ufs_row *out,
                char *err, int errsz) {
    GUARD(err, errsz, -1);
    Inode in;
    if (fs_resolve(&c->fs, path, &in) != 0) {
        GUARD_OK(); if (err) snprintf(err, errsz, "not found: %s", path); return -1;
    }
    br_fill_row(c, basename_of(path), path, &in, out);
    GUARD_OK();
    return 0;
}

int ps4ufs_classify(ps4ufs_ctx *c, const char *path) {
    GUARD(NULL, 0, 0);
    Inode in;
    if (fs_resolve(&c->fs, path, &in) != 0) { GUARD_OK(); return 0; }
    int r = in_isdir(&in) ? 1 : in_isreg(&in) ? 2 : in_islnk(&in) ? 3 : 0;
    GUARD_OK();
    return r;
}

/* ============================= read_head =============================== */

typedef struct { uint8_t *d; int64_t n, max; } br_vbuf;
static int br_vbuf_cb(const uint8_t *buf, int64_t len, void *ud) {
    br_vbuf *v = (br_vbuf *)ud;
    int64_t room = v->max - v->n;
    if (room <= 0) return 1;
    int64_t take = len < room ? len : room;
    memcpy(v->d + v->n, buf, (size_t)take);
    v->n += take;
    return v->n >= v->max ? 1 : 0;
}

int64_t ps4ufs_read_head(ps4ufs_ctx *c, const char *path,
                         uint8_t *buf, int64_t max, char *err, int errsz) {
    GUARD(err, errsz, -1);
    Inode in;
    if (br_resolve_follow(c, path, &in, NULL, 0) != 0 || !in_isreg(&in)) {
        GUARD_OK(); if (err) snprintf(err, errsz, "not a regular file: %s", path); return -1;
    }
    int plain = fs_is_plaintext_pkg(&c->fs, basename_of(path), &in);
    br_vbuf v = { buf, 0, max };
    fs_read_file_iter(&c->fs, &in, !plain, br_vbuf_cb, &v);
    GUARD_OK();
    return v.n;
}

/* =============================== find ================================== */

typedef struct {
    ps4ufs_row        *rows;
    int                n, cap;
    char               needle[256];
    ps4ufs_progress_cb cb;
    void              *ud;
    int64_t            visited;
    int                cancel;
} br_find;

static void br_tolower(char *s) { for (; *s; s++) if (*s>='A'&&*s<='Z') *s += 32; }

static void br_find_walk(ps4ufs_ctx *c, br_find *f, const char *base,
                         const Inode *dir, int depth) {
    if (f->cancel || depth > 64) return;
    br_dlist dl = {0};
    fs_listdir(&c->fs, dir, br_dent_cb, &dl);
    for (int i = 0; i < dl.n && !f->cancel; i++) {
        f->visited++;
        if (f->cb && (f->visited & 0x3ff) == 0)
            if (f->cb(f->visited, 0, f->ud)) f->cancel = 1;

        Inode in;
        fs_inode(&c->fs, dl.v[i].ino, &in);
        char p[1024];
        br_path_join(base, dl.v[i].name, p, sizeof p);

        char low[256]; snprintf(low, sizeof low, "%s", dl.v[i].name); br_tolower(low);
        if (strstr(low, f->needle)) {
            if (f->n >= f->cap) {
                int nc = f->cap ? f->cap * 2 : 128;
                ps4ufs_row *nv = (ps4ufs_row *)realloc(f->rows, (size_t)nc * sizeof(ps4ufs_row));
                if (nv) { f->rows = nv; f->cap = nc; }
            }
            if (f->n < f->cap) br_fill_row(c, dl.v[i].name, p, &in, &f->rows[f->n++]);
        }
        if (in_isdir(&in)) br_find_walk(c, f, p, &in, depth + 1);
    }
    free(dl.v);
}

int ps4ufs_find(ps4ufs_ctx *c, const char *base, const char *needle,
                ps4ufs_row **rows, int *count,
                ps4ufs_progress_cb cb, void *ud, char *err, int errsz) {
    GUARD(err, errsz, -1);
    *rows = NULL; *count = 0;
    br_find f = {0};
    f.cb = cb; f.ud = ud;
    snprintf(f.needle, sizeof f.needle, "%s", needle);
    br_tolower(f.needle);

    Inode dir;
    if (br_resolve_follow(c, base, &dir, NULL, 0) != 0 || !in_isdir(&dir)) {
        GUARD_OK(); if (err) snprintf(err, errsz, "not a directory: %s", base); return -1;
    }
    br_find_walk(c, &f, (base && base[0]) ? base : "/", &dir, 0);
    *rows = f.rows; *count = f.n;
    GUARD_OK();
    return 0;
}

/* ============================= extract ================================= */

typedef struct {
    FILE              *fp;
    int                werr;
    int64_t            done;
    int64_t            total;
    ps4ufs_progress_cb cb;
    void              *ud;
    int                cancel;
} br_xsink;

static int br_xsink_cb(const uint8_t *buf, int64_t len, void *ud) {
    br_xsink *s = (br_xsink *)ud;
    if (fwrite(buf, 1, (size_t)len, s->fp) != (size_t)len) { s->werr = 1; return 1; }
    s->done += len;
    if (s->cb && s->cb(s->done, s->total, s->ud)) s->cancel = 1;
    return s->cancel ? 1 : 0;
}

typedef struct {
    ps4ufs_ctx           *c;
    int                   skip_pkg;
    ps4ufs_extract_stats *st;
    ps4ufs_log_cb         log;
    void                 *logud;
    br_xsink              sink;   /* carries cb/ud/total/done/cancel */
} br_xjob;

static void br_log(br_xjob *j, const char *fmt, ...) {
    if (!j->log) return;
    char line[2048]; va_list ap; va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap); va_end(ap);
    j->log(line, j->logud);
}

static void br_x_count(br_xjob *j, const Inode *in, const char *name, int depth) {
    if (j->sink.cancel || depth > 128) return;
    if (in_isreg(in)) {
        if (!(j->skip_pkg && br_ends_pkg(name))) j->sink.total += (int64_t)in->size;
    } else if (in_isdir(in)) {
        br_dlist dl = {0};
        fs_listdir(&j->c->fs, in, br_dent_cb, &dl);
        for (int i = 0; i < dl.n && !j->sink.cancel; i++) {
            Inode ch; fs_inode(&j->c->fs, dl.v[i].ino, &ch);
            br_x_count(j, &ch, dl.v[i].name, depth + 1);
        }
        free(dl.v);
    }
}

static void br_x_walk(br_xjob *j, const Inode *in, const char *name,
                      const char *fspath, const char *outparent, int depth) {
    if (j->sink.cancel) return;
    char safe[512], out[8192];
    br_safe_name(name, safe, sizeof safe);
    snprintf(out, sizeof out, "%s/%s", outparent, safe);

    if (in_isreg(in)) {
        if (j->skip_pkg && br_ends_pkg(name)) {
            j->st->skipped++; br_log(j, "  skip (pkg)  %s", fspath); return;
        }
        int plain = fs_is_plaintext_pkg(&j->c->fs, name, in);
        FILE *fp = fopen(out, "wb");
        if (!fp) { j->st->errors++; br_log(j, "  ERROR cannot create %s", out); return; }
        j->sink.fp = fp; j->sink.werr = 0;
        pipe_extract(&j->c->fs, in, !plain, br_xsink_cb, &j->sink);
        fclose(fp);
        br_set_mtime(out, in->mtime, in->atime);
        if (j->sink.werr) { j->st->errors++; br_log(j, "  ERROR writing %s (disk full?)", out); j->sink.cancel = 1; return; }
        if (j->sink.cancel) { remove(out); return; }
        j->st->files++; j->st->bytes += (int64_t)in->size;
        br_log(j, "  %10s  %s%s", human(in->size), fspath, plain ? "  [plaintext pkg]" : "");
    } else if (in_isdir(in)) {
        if (depth > 128) return;
        mkdirs(out);
        j->st->dirs++;
        br_dlist dl = {0};
        fs_listdir(&j->c->fs, in, br_dent_cb, &dl);
        for (int i = 0; i < dl.n && !j->sink.cancel; i++) {
            Inode ch; char cp[4096];
            fs_inode(&j->c->fs, dl.v[i].ino, &ch);
            br_path_join(fspath, dl.v[i].name, cp, sizeof cp);
            br_x_walk(j, &ch, dl.v[i].name, cp, out, depth + 1);
        }
        free(dl.v);
    } else if (in_islnk(in)) {
        char t[4096], lf[8300];
        fs_readlink(&j->c->fs, in, t, sizeof t);
        snprintf(lf, sizeof lf, "%s.symlink", out);
        FILE *f = fopen(lf, "w");
        if (f) { fprintf(f, "%s\n", t); fclose(f); j->st->links++; }
        else j->st->errors++;
        br_log(j, "  link        %s -> %s", fspath, t);
    }
}

int ps4ufs_extract(ps4ufs_ctx *c, const char *const *paths, int npaths,
                   const char *outdir, int skip_pkg,
                   ps4ufs_progress_cb cb, void *ud,
                   ps4ufs_log_cb log, void *logud,
                   ps4ufs_extract_stats *stats, char *err, int errsz) {
    GUARD(err, errsz, -1);
    ps4ufs_extract_stats st = {0};
    br_xjob j = {0};
    j.c = c; j.skip_pkg = skip_pkg; j.st = &st; j.log = log; j.logud = logud;
    j.sink.cb = cb; j.sink.ud = ud;

    for (int i = 0; i < npaths && !j.sink.cancel; i++) {
        Inode in;
        if (fs_resolve(&c->fs, paths[i], &in) != 0) continue;
        const char *nm = basename_of(paths[i]);
        br_x_count(&j, &in, nm[0] ? nm : "root", 0);
    }
    br_log(&j, "extracting %d item(s) -> %s  (%s)", npaths, outdir, human((uint64_t)j.sink.total));
    mkdirs(outdir);
    for (int i = 0; i < npaths && !j.sink.cancel; i++) {
        Inode in;
        if (fs_resolve(&c->fs, paths[i], &in) != 0) {
            st.errors++; br_log(&j, "  ERROR not found: %s", paths[i]); continue;
        }
        const char *nm = basename_of(paths[i]);
        br_x_walk(&j, &in, nm[0] ? nm : "root", paths[i], outdir, 0);
    }
    if (stats) *stats = st;
    GUARD_OK();
    return j.sink.cancel ? 1 : 0;   /* 1 == canceled/partial, 0 == done */
}

/* ========================= scan / recover ============================== */

void ps4ufs_set_abort(int on) { g_abort = on ? 1 : 0; }

/* portable stdout+stderr capture: redirect fd 1/2 into a pipe, read it on a
 * worker thread, emit whole lines to the log callback, restore on finish. */
typedef struct { int rfd; ps4ufs_log_cb log; void *ud; } br_cap;

static THREAD_RET br_cap_reader(void *arg) {
    br_cap *cap = (br_cap *)arg;
    char acc[4096]; size_t al = 0;
    char buf[4096]; int n;
    while ((n = BR_READ(cap->rfd, buf, sizeof buf)) > 0) {
        for (int i = 0; i < n; i++) {
            char ch = buf[i];
            if (ch == '\n' || ch == '\r') {
                acc[al] = 0;
                if (al && cap->log) cap->log(acc, cap->ud);
                al = 0;
            } else if (al + 1 < sizeof acc) {
                acc[al++] = ch;
            }
        }
    }
    if (al) { acc[al] = 0; if (cap->log) cap->log(acc, cap->ud); }
    THREAD_RETURN;
}

/* run fn() with stdout/stderr captured to the log callback */
static int br_with_capture(ps4ufs_log_cb log, void *ud,
                           void (*fn)(void *), void *fnarg) {
    if (!log) { fn(fnarg); return 0; }
    int fds[2];
    if (BR_PIPE(fds) != 0) { fn(fnarg); return 0; }
    fflush(stdout); fflush(stderr);
    int save_out = BR_DUP(BR_FNO(stdout));
    int save_err = BR_DUP(BR_FNO(stderr));
    BR_DUP2(fds[1], BR_FNO(stdout));
    BR_DUP2(fds[1], BR_FNO(stderr));
    BR_CLOSE(fds[1]);

    br_cap cap = { fds[0], log, ud };
    thread_t rt; thread_start(&rt, br_cap_reader, &cap);

    fn(fnarg);

    fflush(stdout); fflush(stderr);
    BR_DUP2(save_out, BR_FNO(stdout)); BR_CLOSE(save_out);
    BR_DUP2(save_err, BR_FNO(stderr)); BR_CLOSE(save_err);
    /* closing the write ends above lets the reader hit EOF */
    thread_join(rt);
    BR_CLOSE(fds[0]);
    return 0;
}

struct br_scan_args { ps4ufs_ctx *c; int dry, defrag, geom; const char *outroot; };
static void br_scan_fn(void *a) {
    struct br_scan_args *s = (struct br_scan_args *)a;
    cmd_scan(&s->c->fs, s->c->img_path, s->outroot, s->c->key, s->c->ivoffset,
             s->c->nthreads, s->dry, s->defrag, s->geom);
}

int ps4ufs_scan(ps4ufs_ctx *c, int dry, int defrag, int geom,
                const char *outroot, ps4ufs_log_cb log, void *logud,
                char *err, int errsz) {
    GUARD(err, errsz, -1);
    g_abort = 0;
    struct br_scan_args a = { c, dry, defrag, geom, outroot };
    br_with_capture(log, logud, br_scan_fn, &a);
    GUARD_OK();
    return 0;
}

struct br_rec_args { ps4ufs_ctx *c; int64_t min_size; int dry, linked; const char *outroot; };
static void br_rec_fn(void *a) {
    struct br_rec_args *r = (struct br_rec_args *)a;
    cmd_recover(&r->c->fs, r->outroot, r->min_size, r->dry, r->linked);
}

int ps4ufs_recover(ps4ufs_ctx *c, int64_t min_size, int dry, int include_linked,
                   const char *outroot, ps4ufs_log_cb log, void *logud,
                   char *err, int errsz) {
    GUARD(err, errsz, -1);
    g_abort = 0;
    struct br_rec_args a = { c, min_size, dry, include_linked, outroot };
    br_with_capture(log, logud, br_rec_fn, &a);
    GUARD_OK();
    return 0;
}
