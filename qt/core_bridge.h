/* core_bridge.h - clean, portable C API over ps4ufs.c for the Qt front-end.
 *
 * The Qt (C++) code only ever sees this header; it never includes ps4ufs.c
 * or touches the core's internal structs. core_bridge.c compiles ps4ufs.c
 * (with PS4UFS_GUI) as C and turns the core's die()/longjmp error model into
 * ordinary return codes + an error string. */
#ifndef PS4UFS_CORE_BRIDGE_H
#define PS4UFS_CORE_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ps4ufs_ctx ps4ufs_ctx;

/* one GPT / partition candidate for the picker */
typedef struct {
    int      index;       /* GPT entry index, or -1 for the whole-image/bare case */
    uint64_t base;        /* byte offset of the partition in the image           */
    uint64_t size;        /* partition size in bytes (0 if unknown)              */
    int      is_ufs2;     /* decrypts (with the key) as a UFS2 superblock        */
    int      is_plain;    /* already-decrypted UFS2 (no key needed)              */
} ps4ufs_part;

/* one row in a directory listing / search result */
typedef struct {
    char     name[256];
    char     link[1024];  /* symlink target, or "" */
    uint32_t ino;
    uint16_t mode;
    uint64_t size;
    int64_t  mtime;       /* unix seconds */
    int      is_dir;
    int      is_lnk;
    int      is_reg;
    int      is_pkg;      /* plaintext .pkg inside the volume */
    char     path[1024];  /* absolute path inside the volume (for search rows)   */
} ps4ufs_row;

/* progress / cancel callback: return non-zero to request cancellation.
 * total may be 0 when unknown (indeterminate). */
typedef int (*ps4ufs_progress_cb)(int64_t done, int64_t total, void *ud);
/* log line sink (used by scan/recover) */
typedef void (*ps4ufs_log_cb)(const char *line, void *ud);

/* ---- lifecycle ------------------------------------------------------- */

/* enumerate partitions. Returns the number written to out[] (<= max), or -1
 * on error (err filled). have_key==0 means only plaintext detection runs. */
int ps4ufs_scan_parts(const char *img_path,
                      const uint8_t key[32], int have_key, uint64_t ivoffset,
                      ps4ufs_part *out, int max, char *err, int errsz);

/* open a volume. part_offset/plain are usually chosen from a ps4ufs_part.
 * plain==1 opens an already-decrypted image (key ignored). Returns NULL on
 * error. nthreads<=0 -> auto. */
ps4ufs_ctx *ps4ufs_open(const char *img_path,
                        const uint8_t key[32], int have_key, uint64_t ivoffset,
                        uint64_t part_offset, int plain, int pkg_plaintext,
                        int nthreads, char *err, int errsz);
void ps4ufs_close(ps4ufs_ctx *c);
void ps4ufs_set_pkg_plaintext(ps4ufs_ctx *c, int on);

/* superblock / summary text (multi-line) into buf */
void ps4ufs_info_text(ps4ufs_ctx *c, char *buf, int bufsz);

/* ---- browsing -------------------------------------------------------- */

/* list a directory (final symlinks followed). On success *rows points to a
 * malloc'd array of *count rows (free with ps4ufs_free_rows). Returns 0 ok,
 * -1 error. */
int  ps4ufs_list(ps4ufs_ctx *c, const char *path,
                 ps4ufs_row **rows, int *count, char *err, int errsz);
void ps4ufs_free_rows(ps4ufs_row *rows);

/* stat a single path (no final-symlink follow). 0 ok / -1 not found. */
int  ps4ufs_stat(ps4ufs_ctx *c, const char *path, ps4ufs_row *out,
                 char *err, int errsz);

/* resolve a path and report its type (dir follow-through). Returns:
 *  0 = not found, 1 = dir, 2 = regular file, 3 = symlink (unresolved). */
int  ps4ufs_classify(ps4ufs_ctx *c, const char *path);

/* read up to max bytes of a regular file's start (viewer). Returns bytes
 * read, or -1 on error. */
int64_t ps4ufs_read_head(ps4ufs_ctx *c, const char *path,
                         uint8_t *buf, int64_t max, char *err, int errsz);

/* recursive name search under base. Same row array contract as ps4ufs_list.
 * cb receives (visited,0) periodically; return non-zero to cancel. */
int  ps4ufs_find(ps4ufs_ctx *c, const char *base, const char *needle,
                 ps4ufs_row **rows, int *count,
                 ps4ufs_progress_cb cb, void *ud, char *err, int errsz);

/* ---- extraction ------------------------------------------------------ */

typedef struct {
    int64_t files, dirs, links, skipped, errors;
    int64_t bytes;
} ps4ufs_extract_stats;

/* extract the given volume paths into outdir (host path). skip_pkg drops
 * *.pkg files. cb reports byte progress and cancellation. 0 ok / -1 error. */
int  ps4ufs_extract(ps4ufs_ctx *c, const char *const *paths, int npaths,
                    const char *outdir, int skip_pkg,
                    ps4ufs_progress_cb cb, void *ud,
                    ps4ufs_log_cb log, void *logud,
                    ps4ufs_extract_stats *stats, char *err, int errsz);

/* ---- scan / recover (package carving) -------------------------------- */

/* set/clear the core abort flag (cancels a running scan/recover) */
void ps4ufs_set_abort(int on);

/* carve .pkg packages from the raw partition (CLI `scan`). log receives the
 * core's textual output. 0 ok / -1 error. */
int  ps4ufs_scan(ps4ufs_ctx *c, int dry, int defrag, int geom,
                 const char *outroot, ps4ufs_log_cb log, void *logud,
                 char *err, int errsz);

/* recover deleted .pkg inodes (CLI `recover`). */
int  ps4ufs_recover(ps4ufs_ctx *c, int64_t min_size, int dry, int include_linked,
                    const char *outroot, ps4ufs_log_cb log, void *logud,
                    char *err, int errsz);

#ifdef __cplusplus
}
#endif
#endif
