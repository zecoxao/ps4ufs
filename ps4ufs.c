/* ps4ufs.c - C port of ps4ufs.py
 *
 * Browse a PS4/FreeBSD UFS2 disk image that is AES-128-XTS encrypted,
 * decrypting on the fly, while treating *.pkg file contents as plaintext
 * (they are stored un-encrypted inside the encrypted volume).
 *
 * Works directly on the whole-disk image C:\hdd\hdd.img -- the UFS2 filesystem
 * lives inside a GPT partition, and this reads it in place (no need to extract
 * a multi-hundred-GB copy of the partition first). It also still opens a bare
 * partition dump (the old C:\hdd\12.img) via --partbase 0.
 *
 * It ALSO accepts an individual *already-decrypted* partition image such as
 * C:\hdd\user.bin. Pass --plain (or just let it auto-detect: a plaintext UFS2
 * superblock is recognized verbatim). In plain mode no key is used and no
 * keys.bin is required -- every read is a raw passthrough, including the cg
 * bitmaps used by `scan --defrag`. So:
 *     ps4ufs --img C:\hdd\user.bin scan D:\out\pkgs
 *     ps4ufs --img C:\hdd\user.bin scan D:\out\pkgs --defrag
 * work on a decrypted image exactly like the encrypted one.
 *
 * Discovered layout for C:\hdd\hdd.img:
 *     container   : GPT whole-disk image (partition table is plaintext)
 *     /user fs    : GPT partition #26, base 18254659584, ~451 GB (auto-detected)
 *     cipher      : AES-128-XTS  (key = keys.bin, 32 bytes, used verbatim)
 *     data unit   : 512 bytes
 *     tweak(sec)  : ivoffset + (partition_byte_offset / 512)  (16-byte LE)
 *     ivoffset    : 0            (tweak is the partition-relative sector number)
 *     filesystem  : UFS2, little-endian, bsize=32768, fsize=4096
 *
 * Physical reads are taken at (part_offset + partition_byte_offset); the XTS
 * tweak stays partition-relative, so the crypto matches the extracted-partition
 * case exactly -- only the file seek base changes.
 *
 * Self-contained: bundles a small AES-128 + XTS implementation, no external
 * crypto library required.
 *
 * Build:
 *     gcc  -O2 -o ps4ufs ps4ufs.c
 *     clang -O2 -o ps4ufs ps4ufs.c
 *     cl /O2 ps4ufs.c            (MSVC)
 *
 * Usage:
 *     ps4ufs parts                              (list GPT partitions, flag UFS2)
 *     ps4ufs info
 *     ps4ufs ls  /
 *     ps4ufs ls  /system_ex/app
 *     ps4ufs stat /path/to/file
 *     ps4ufs tree / --depth 2
 *     ps4ufs get  /path/to/foo.pkg  D:\out\foo.pkg
 *     ps4ufs getdir /app  D:\out\app            (recursive extract of a tree)
 *     ps4ufs getdir /app  D:\out\app --dry-run  (preview, write nothing)
 *     ps4ufs getdir /app  D:\out\app --skip-pkg --max-size 104857600
 *     ps4ufs cat  /path/to/text                 (prints to stdout)
 *     ps4ufs find .pkg                          (recursive name search)
 *     ps4ufs scan D:\out\pkgs                   (carve raw .pkg packages, parallel)
 *     ps4ufs scan D:\out\pkgs --threads 8 --dry-run
 *     ps4ufs scan D:\out\pkgs --defrag          (reassemble via free-block bitmap)
 *     ps4ufs scan D:\out\pkgs --geom            (reassemble via cg geometry; try this
 *                                                if --defrag output fails pkg_pfs_tool)
 *     ps4ufs recover D:\out\pkgs                (rebuild deleted pkgs from inode block maps)
 *     ps4ufs recover D:\out\pkgs --dry-run      (list recoverable deleted pkgs, write nothing)
 *     ps4ufs shell                              (interactive browser)
 *
 * `scan` carves by CNT magic and (with --defrag) guesses block order from the
 * free-block bitmaps; `recover` instead walks the UFS2 inode table for deleted
 * inodes whose block pointers survive and rebuilds each .pkg from its actual
 * direct/indirect block map (4 KB frags -> 32 KB blocks), so fragmentation is
 * reproduced exactly. Prefer `recover` for fragmented/deleted packages.
 *
 * Global options (before the subcommand):
 *     --img PATH        (default C:\hdd\hdd.img)
 *     --keys PATH       (default C:\hdd\keys.bin)
 *     --part N          (use GPT partition entry N)
 *     --partbase BYTES  (raw partition byte offset; default = auto-detect UFS2,
 *                        or 0 for a bare partition image)
 *     --ivoffset N      (partition-relative XTS tweak base; default 0)
 *     --no-pkg-plain    (decrypt .pkg contents too, i.e. disable passthrough)
 *     --threads N       (decryption worker threads; default = CPU count, 1 = off)
 *
 * Threading: AES-128-XTS decryption is offloaded to a worker pool (each 512-byte
 * sector is an independent XTS data unit). File I/O stays on the main thread, so
 * there is no shared-handle race. Build with -lpthread on POSIX.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>

#ifdef _WIN32
  #include <direct.h>
  #include <io.h>
  #include <fcntl.h>
  #include <sys/stat.h>
  #define FSEEK64 _fseeki64
  #define FTELL64 _ftelli64
  #define MKDIR(p) _mkdir(p)
  #ifndef S_ISDIR
    #define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
  #endif
  typedef struct _stati64 stat_t;
  #define STAT64 _stati64
#else
  #include <sys/stat.h>
  #include <unistd.h>
  #define _FILE_OFFSET_BITS 64
  #define FSEEK64 fseeko
  #define FTELL64 ftello
  #define MKDIR(p) mkdir(p, 0755)
  typedef struct stat stat_t;
  #define STAT64 stat
#endif

/* --------------------------------------------------------------------------
 * portable threading primitives (mutex + condition variable + threads)
 * ------------------------------------------------------------------------ */
#ifdef _WIN32
  #include <windows.h>
  #include <process.h>
  typedef CRITICAL_SECTION   mutex_t;
  typedef CONDITION_VARIABLE cond_t;
  typedef HANDLE             thread_t;
  #define MTX_INIT(m)     InitializeCriticalSection(m)
  #define MTX_LOCK(m)     EnterCriticalSection(m)
  #define MTX_UNLOCK(m)   LeaveCriticalSection(m)
  #define MTX_DESTROY(m)  DeleteCriticalSection(m)
  #define COND_INIT(c)    InitializeConditionVariable(c)
  #define COND_WAIT(c,m)  SleepConditionVariableCS(c,m,INFINITE)
  #define COND_SIGNAL(c)  WakeConditionVariable(c)
  #define COND_BCAST(c)   WakeAllConditionVariable(c)
  #define THREAD_RET      unsigned __stdcall
  #define THREAD_RETURN   return 0
  typedef unsigned (__stdcall *thread_fn)(void *);
#else
  #include <pthread.h>
  typedef pthread_mutex_t mutex_t;
  typedef pthread_cond_t  cond_t;
  typedef pthread_t       thread_t;
  #define MTX_INIT(m)     pthread_mutex_init(m, NULL)
  #define MTX_LOCK(m)     pthread_mutex_lock(m)
  #define MTX_UNLOCK(m)   pthread_mutex_unlock(m)
  #define MTX_DESTROY(m)  pthread_mutex_destroy(m)
  #define COND_INIT(c)    pthread_cond_init(c, NULL)
  #define COND_WAIT(c,m)  pthread_cond_wait(c, m)
  #define COND_SIGNAL(c)  pthread_cond_signal(c)
  #define COND_BCAST(c)   pthread_cond_broadcast(c)
  #define THREAD_RET      void *
  #define THREAD_RETURN   return NULL
  typedef void *(*thread_fn)(void *);
#endif

static void thread_start(thread_t *t, thread_fn fn, void *arg) {
#ifdef _WIN32
    *t = (HANDLE)_beginthreadex(NULL, 0, fn, arg, 0, NULL);
#else
    pthread_create(t, NULL, fn, arg);
#endif
}
static void thread_join(thread_t t) {
#ifdef _WIN32
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
#else
    pthread_join(t, NULL);
#endif
}
static int cpu_count(void) {
#ifdef _WIN32
    SYSTEM_INFO si; GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
#endif
}

/* --------------------------------------------------------------------------
 * constants
 * ------------------------------------------------------------------------ */
#define SECTOR       512
#define SBLOCK_UFS2  65536
#define UFS2_MAGIC   0x19540119u
#define ROOTINO      2
#define DINODE_SIZE  256
#define NDADDR       12          /* direct block pointers   */
#define NIADDR       3           /* indirect block pointers */
#define PKG_MAGIC    "\x7f""CNT" /* PS4 .pkg (CNT) magic (4 bytes) */

#ifdef _WIN32
static char *strtok_r(char *s, const char *d, char **save);   /* shim, defined below */
#endif

#define S_IFMT_   0170000
#define S_IFDIR_  0040000
#define S_IFREG_  0100000
#define S_IFLNK_  0120000

/* ==========================================================================
 * AES-128 (self contained, ECB single block encrypt/decrypt)
 * ======================================================================== */
static const uint8_t sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

static uint8_t inv_sbox[256];
static void build_inv_sbox(void) {
    for (int i = 0; i < 256; i++) inv_sbox[sbox[i]] = (uint8_t)i;
}

static const uint8_t rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };

typedef struct { uint8_t rk[176]; } aes_ctx;   /* 11 round keys * 16 bytes */

static void aes128_expand(aes_ctx *c, const uint8_t key[16]) {
    memcpy(c->rk, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        int p = (i - 1) * 4;
        t[0] = c->rk[p+0]; t[1] = c->rk[p+1]; t[2] = c->rk[p+2]; t[3] = c->rk[p+3];
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = (uint8_t)(sbox[t[1]] ^ rcon[i/4]);
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[tmp];
        }
        int q = (i - 4) * 4, r = i * 4;
        c->rk[r+0] = c->rk[q+0] ^ t[0];
        c->rk[r+1] = c->rk[q+1] ^ t[1];
        c->rk[r+2] = c->rk[q+2] ^ t[2];
        c->rk[r+3] = c->rk[q+3] ^ t[3];
    }
}

static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

static void add_round_key(uint8_t s[16], const uint8_t *rk) {
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
}

/* state stored as s[r + 4*c] = column-major (FIPS-197 layout) */
static void aes_encrypt_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    add_round_key(s, c->rk);
    for (int round = 1; round <= 10; round++) {
        /* SubBytes */
        for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
        /* ShiftRows (rows 1..3 rotate left by r) */
        uint8_t t;
        t = s[1];  s[1]=s[5];  s[5]=s[9];  s[9]=s[13]; s[13]=t;
        t = s[2];  s[2]=s[10]; s[10]=t; t = s[6]; s[6]=s[14]; s[14]=t;
        t = s[15]; s[15]=s[11];s[11]=s[7]; s[7]=s[3]; s[3]=t;
        /* MixColumns (skip on last round) */
        if (round != 10) {
            for (int col = 0; col < 4; col++) {
                uint8_t *p = s + col*4;
                uint8_t a0=p[0],a1=p[1],a2=p[2],a3=p[3];
                uint8_t all = a0^a1^a2^a3;
                p[0] = (uint8_t)(a0 ^ all ^ xtime((uint8_t)(a0^a1)));
                p[1] = (uint8_t)(a1 ^ all ^ xtime((uint8_t)(a1^a2)));
                p[2] = (uint8_t)(a2 ^ all ^ xtime((uint8_t)(a2^a3)));
                p[3] = (uint8_t)(a3 ^ all ^ xtime((uint8_t)(a3^a0)));
            }
        }
        add_round_key(s, c->rk + round*16);
    }
    memcpy(out, s, 16);
}

/* GF(2^8) multiply by small constants for InvMixColumns, all via xtime */
static inline uint8_t mul9(uint8_t x)  { uint8_t x2=xtime(x),x4=xtime(x2),x8=xtime(x4); return (uint8_t)(x8^x); }
static inline uint8_t mul11(uint8_t x) { uint8_t x2=xtime(x),x4=xtime(x2),x8=xtime(x4); return (uint8_t)(x8^x2^x); }
static inline uint8_t mul13(uint8_t x) { uint8_t x2=xtime(x),x4=xtime(x2),x8=xtime(x4); return (uint8_t)(x8^x4^x); }
static inline uint8_t mul14(uint8_t x) { uint8_t x2=xtime(x),x4=xtime(x2),x8=xtime(x4); return (uint8_t)(x8^x4^x2); }

static void aes_decrypt_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    add_round_key(s, c->rk + 10*16);
    for (int round = 9; round >= 0; round--) {
        /* InvShiftRows (rows 1..3 rotate right by r) */
        uint8_t t;
        t = s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
        t = s[2];  s[2]=s[10]; s[10]=t; t = s[6]; s[6]=s[14]; s[14]=t;
        t = s[3];  s[3]=s[7];  s[7]=s[11]; s[11]=s[15]; s[15]=t;
        /* InvSubBytes */
        for (int i = 0; i < 16; i++) s[i] = inv_sbox[s[i]];
        /* AddRoundKey */
        add_round_key(s, c->rk + round*16);
        /* InvMixColumns (skip after round 0) */
        if (round != 0) {
            for (int col = 0; col < 4; col++) {
                uint8_t *p = s + col*4;
                uint8_t a0=p[0],a1=p[1],a2=p[2],a3=p[3];
                p[0] = (uint8_t)(mul14(a0)^mul11(a1)^mul13(a2)^mul9(a3));
                p[1] = (uint8_t)(mul9(a0)^mul14(a1)^mul11(a2)^mul13(a3));
                p[2] = (uint8_t)(mul13(a0)^mul9(a1)^mul14(a2)^mul11(a3));
                p[3] = (uint8_t)(mul11(a0)^mul13(a1)^mul9(a2)^mul14(a3));
            }
        }
    }
    memcpy(out, s, 16);
}

/* ==========================================================================
 * AES-128-XTS  (IEEE P1619, tweak = little-endian data-unit number)
 * ======================================================================== */
typedef struct {
    aes_ctx k1;   /* data key  */
    aes_ctx k2;   /* tweak key */
} xts_ctx;

static void xts_init(xts_ctx *x, const uint8_t key[32]) {
    aes128_expand(&x->k1, key);
    aes128_expand(&x->k2, key + 16);
}

static void xts_mult_x(uint8_t t[16]) {
    int carry = 0;
    for (int i = 0; i < 16; i++) {
        int c = t[i] >> 7;
        t[i] = (uint8_t)((t[i] << 1) | carry);
        carry = c;
    }
    if (carry) t[0] ^= 0x87;
}

/* Decrypt one data unit (multiple of 16 bytes) with the given unit number. */
static void xts_decrypt_unit(const xts_ctx *x, uint8_t *buf, size_t len, uint64_t unit) {
    uint8_t tweak[16];
    memset(tweak, 0, 16);
    for (int i = 0; i < 8; i++) tweak[i] = (uint8_t)(unit >> (8*i));
    aes_encrypt_block(&x->k2, tweak, tweak);
    for (size_t off = 0; off + 16 <= len; off += 16) {
        uint8_t *b = buf + off;
        for (int i = 0; i < 16; i++) b[i] ^= tweak[i];
        aes_decrypt_block(&x->k1, b, b);
        for (int i = 0; i < 16; i++) b[i] ^= tweak[i];
        xts_mult_x(tweak);
    }
}

/* ==========================================================================
 * decrypt thread pool
 *
 * Decrypts a contiguous run of 512-byte sectors in parallel. Each sector is
 * an independent XTS data unit (tweak = base_sector + index), so workers can
 * decrypt disjoint sector ranges of the same buffer with no coordination.
 * Only in-memory decryption is threaded; file I/O stays on the caller.
 * ======================================================================== */
#define PAR_MIN_SECTORS 32   /* below this, decrypt inline (no dispatch cost) */

typedef struct {
    int       nthreads;
    thread_t *threads;
    mutex_t   mtx;
    cond_t    work_cv;   /* workers wait here for a job          */
    cond_t    done_cv;   /* submitter waits here for completion  */
    /* current job */
    const xts_ctx *xts;
    uint8_t  *buf;
    uint64_t  base_sector;
    int64_t   total;     /* sectors in job         */
    int64_t   next;      /* next sector to claim   */
    int64_t   remaining; /* sectors not yet done   */
    int64_t   chunk;     /* sectors claimed per grab */
    int       shutdown;
} decrypt_pool;

static decrypt_pool g_pool;
static int          g_nthreads = 1;

static void pool_decrypt_serial(const xts_ctx *xts, uint8_t *buf,
                                uint64_t base_sector, int64_t nsectors) {
    for (int64_t s = 0; s < nsectors; s++)
        xts_decrypt_unit(xts, buf + s*SECTOR, SECTOR, base_sector + (uint64_t)s);
}

static THREAD_RET pool_worker(void *arg) {
    decrypt_pool *p = (decrypt_pool *)arg;
    MTX_LOCK(&p->mtx);
    for (;;) {
        while (!p->shutdown && p->next >= p->total)
            COND_WAIT(&p->work_cv, &p->mtx);
        if (p->shutdown) break;
        int64_t start = p->next;
        int64_t cnt   = p->chunk;
        if (start + cnt > p->total) cnt = p->total - start;
        p->next += cnt;
        MTX_UNLOCK(&p->mtx);

        pool_decrypt_serial(p->xts, p->buf + start*SECTOR,
                            p->base_sector + (uint64_t)start, cnt);

        MTX_LOCK(&p->mtx);
        p->remaining -= cnt;
        if (p->remaining == 0) COND_SIGNAL(&p->done_cv);
    }
    MTX_UNLOCK(&p->mtx);
    THREAD_RETURN;
}

static void pool_init(int nthreads) {
    memset(&g_pool, 0, sizeof(g_pool));
    g_pool.nthreads = nthreads;
    MTX_INIT(&g_pool.mtx);
    COND_INIT(&g_pool.work_cv);
    COND_INIT(&g_pool.done_cv);
    g_pool.threads = (thread_t *)malloc(nthreads * sizeof(thread_t));
    for (int i = 0; i < nthreads; i++)
        thread_start(&g_pool.threads[i], pool_worker, &g_pool);
}

static void pool_shutdown(void) {
    if (!g_pool.threads) return;
    MTX_LOCK(&g_pool.mtx);
    g_pool.shutdown = 1;
    COND_BCAST(&g_pool.work_cv);
    MTX_UNLOCK(&g_pool.mtx);
    for (int i = 0; i < g_pool.nthreads; i++)
        thread_join(g_pool.threads[i]);
    free(g_pool.threads);
    g_pool.threads = NULL;
    MTX_DESTROY(&g_pool.mtx);
}

/* Decrypt a contiguous run of sectors, threaded when it pays off. */
static void decrypt_sectors(const xts_ctx *xts, uint8_t *buf,
                            uint64_t base_sector, int64_t nsectors) {
    if (g_nthreads <= 1 || nsectors < PAR_MIN_SECTORS) {
        pool_decrypt_serial(xts, buf, base_sector, nsectors);
        return;
    }
    MTX_LOCK(&g_pool.mtx);
    g_pool.xts         = xts;
    g_pool.buf         = buf;
    g_pool.base_sector = base_sector;
    g_pool.total       = nsectors;
    g_pool.next        = 0;
    g_pool.remaining   = nsectors;
    g_pool.chunk       = (nsectors + g_pool.nthreads - 1) / g_pool.nthreads;
    if (g_pool.chunk < 1) g_pool.chunk = 1;
    COND_BCAST(&g_pool.work_cv);
    while (g_pool.remaining > 0)
        COND_WAIT(&g_pool.done_cv, &g_pool.mtx);
    MTX_UNLOCK(&g_pool.mtx);
}

/* ==========================================================================
 * little-endian buffer readers
 * ======================================================================== */
static uint16_t rd_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static int32_t  rd_i32(const uint8_t *p) { return (int32_t)rd_u32(p); }
static uint64_t rd_u64(const uint8_t *p) {
    return (uint64_t)rd_u32(p) | ((uint64_t)rd_u32(p+4) << 32);
}
static int64_t  rd_i64(const uint8_t *p) { return (int64_t)rd_u64(p); }

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/* ==========================================================================
 * transparent XTS-decrypting block reader (CryptImage)
 * ======================================================================== */
typedef struct {
    FILE   *f;
    xts_ctx xts;
    uint64_t ivoffset;
    uint64_t part_offset;   /* byte offset of the partition within the image
                             * file (0 for a bare partition dump). Physical
                             * reads add this; the XTS tweak stays partition-
                             * relative, so the crypto is unchanged. */
    int     plain;          /* 1 = image is already decrypted (no XTS at all):
                             * every read is a raw passthrough and no key is
                             * needed. Used for an individual decrypted user
                             * image such as C:\hdd\user.bin. */
} CryptImage;

static void ci_open(CryptImage *ci, const char *path, const uint8_t key[32],
                    uint64_t ivoffset, uint64_t part_offset, int plain) {
    ci->f = fopen(path, "rb");
    if (!ci->f) die("cannot open image: %s", path);
    if (!plain) xts_init(&ci->xts, key);
    ci->ivoffset    = ivoffset;
    ci->part_offset = part_offset;
    ci->plain       = plain;
}
static void ci_close(CryptImage *ci) { if (ci->f) fclose(ci->f); }

static void ci_read_plain(CryptImage *ci, int64_t off, int64_t n, uint8_t *out) {
    if (FSEEK64(ci->f, (int64_t)ci->part_offset + off, SEEK_SET) != 0)
        die("seek failed @ %lld", (long long)((int64_t)ci->part_offset + off));
    size_t got = fread(out, 1, (size_t)n, ci->f);
    if (got < (size_t)n) memset(out + got, 0, (size_t)n - got);
}

/* Decrypt an arbitrary byte range [off, off+n) into out (>= n bytes). */
static void ci_read(CryptImage *ci, int64_t off, int64_t n, uint8_t *out) {
    if (ci->plain) { ci_read_plain(ci, off, n, out); return; }  /* already decrypted */
    int64_t start_sec = off / SECTOR;
    int64_t end_sec   = (off + n + SECTOR - 1) / SECTOR;
    int64_t base      = start_sec * SECTOR;
    int64_t rawlen    = (end_sec - start_sec) * SECTOR;
    uint8_t *raw = (uint8_t *)malloc((size_t)rawlen);
    if (!raw) die("out of memory (%lld bytes)", (long long)rawlen);
    ci_read_plain(ci, base, rawlen, raw);
    uint64_t base_sector = ci->ivoffset + (uint64_t)(base / SECTOR);
    decrypt_sectors(&ci->xts, raw, base_sector, rawlen / SECTOR);
    int64_t skip = off - base;
    memcpy(out, raw + skip, (size_t)n);
    free(raw);
}

/* ==========================================================================
 * UFS2 superblock
 * ======================================================================== */
typedef struct {
    uint32_t magic;
    int32_t  sblkno, cblkno, iblkno, dblkno;
    int32_t  ncg, bsize, fsize, frag;
    int32_t  bshift, fshift, fragshift, fsbtodb;
    int32_t  nindir, inopb;
    int32_t  ipg, fpg;
    int64_t  size;      /* frags */
    int32_t  bmask, fmask;
} Superblock;

static void sb_parse(Superblock *sb, const uint8_t *b) {
    sb->magic = rd_u32(b + 1372);
    if (sb->magic != UFS2_MAGIC)
        die("not a UFS2 superblock (magic=0x%08x)", sb->magic);
    sb->sblkno = rd_i32(b+8);   sb->cblkno = rd_i32(b+12);
    sb->iblkno = rd_i32(b+16);  sb->dblkno = rd_i32(b+20);
    sb->ncg    = rd_i32(b+44);
    sb->bsize  = rd_i32(b+48);  sb->fsize  = rd_i32(b+52);  sb->frag = rd_i32(b+56);
    sb->bshift = rd_i32(b+80);  sb->fshift = rd_i32(b+84);
    sb->fragshift = rd_i32(b+96); sb->fsbtodb = rd_i32(b+100);
    sb->nindir = rd_i32(b+116); sb->inopb  = rd_i32(b+120);
    sb->ipg    = rd_i32(b+184); sb->fpg    = rd_i32(b+188);
    sb->size   = rd_i64(b+1080);
    sb->bmask  = rd_i32(b+72);  sb->fmask  = rd_i32(b+76);
}

static int64_t sb_cgbase(const Superblock *sb, int64_t c) { return (int64_t)sb->fpg * c; }
static int64_t sb_cgimin(const Superblock *sb, int64_t c) { return sb_cgbase(sb, c) + sb->iblkno; }
static int64_t sb_frag_to_byte(const Superblock *sb, int64_t fa) { return fa * (int64_t)sb->fsize; }
static int64_t sb_blkstofrags(const Superblock *sb, int64_t bl) { return bl << sb->fragshift; }

static int64_t sb_ino_to_offset(const Superblock *sb, uint32_t ino) {
    int64_t cg     = ino / (uint32_t)sb->ipg;
    int64_t within = ino % (uint32_t)sb->ipg;
    int64_t blk    = within / sb->inopb;
    int64_t off_in = within % sb->inopb;
    int64_t fsba   = sb_cgimin(sb, cg) + sb_blkstofrags(sb, blk);
    return sb_frag_to_byte(sb, fsba) + off_in * DINODE_SIZE;
}

/* ==========================================================================
 * UFS2 inode
 * ======================================================================== */
typedef struct {
    uint32_t ino;
    uint16_t mode;
    int16_t  nlink;
    uint32_t uid, gid;
    uint64_t size;
    uint64_t blocks;
    int64_t  atime, mtime, ctime;
    uint32_t flags;
    int64_t  db[NDADDR];
    int64_t  ib[NIADDR];
    uint8_t  raw[DINODE_SIZE];
} Inode;

static void inode_parse(Inode *in, uint32_t ino, const uint8_t *d) {
    in->ino    = ino;
    in->mode   = rd_u16(d + 0);
    in->nlink  = (int16_t)rd_u16(d + 2);
    in->uid    = rd_u32(d + 4);
    in->gid    = rd_u32(d + 8);
    in->size   = rd_u64(d + 16);
    in->blocks = rd_u64(d + 24);
    in->atime  = rd_i64(d + 32);
    in->mtime  = rd_i64(d + 40);
    in->ctime  = rd_i64(d + 48);
    in->flags  = rd_u32(d + 88);
    for (int i = 0; i < NDADDR; i++) in->db[i] = rd_i64(d + 112 + i*8);
    for (int i = 0; i < NIADDR; i++) in->ib[i] = rd_i64(d + 208 + i*8);
    memcpy(in->raw, d, DINODE_SIZE);
}

static int in_ftype(const Inode *in) { return in->mode & S_IFMT_; }
static int in_isdir(const Inode *in) { return in_ftype(in) == S_IFDIR_; }
static int in_isreg(const Inode *in) { return in_ftype(in) == S_IFREG_; }
static int in_islnk(const Inode *in) { return in_ftype(in) == S_IFLNK_; }

/* ==========================================================================
 * the filesystem
 * ======================================================================== */
#define IND_CACHE 4   /* indirect-block cache slots (enough for l1/l2/l3) */
typedef struct {
    CryptImage *img;
    Superblock  sb;
    int         pkg_plaintext;
    /* indirect-block cache: avoids re-reading/re-decrypting the same indirect
     * block for every data block it maps (huge win on large files). */
    int64_t     ic_addr[IND_CACHE];
    int64_t    *ic_data[IND_CACHE];
    int         ic_next;
    int64_t    *zero_ind;   /* nindir zeros, for addr==0 */
} UFS2FS;

static void fs_init(UFS2FS *fs, CryptImage *img, int pkg_plaintext) {
    memset(fs, 0, sizeof(*fs));
    fs->img = img;
    fs->pkg_plaintext = pkg_plaintext;
    uint8_t buf[8192];
    ci_read(img, SBLOCK_UFS2, sizeof(buf), buf);
    sb_parse(&fs->sb, buf);
    fs->zero_ind = (int64_t *)calloc(fs->sb.nindir, sizeof(int64_t));
    if (!fs->zero_ind) die("out of memory");
}

static void fs_inode(UFS2FS *fs, uint32_t ino, Inode *out) {
    int64_t off = sb_ino_to_offset(&fs->sb, ino);
    uint8_t d[DINODE_SIZE];
    ci_read(fs->img, off, DINODE_SIZE, d);
    inode_parse(out, ino, d);
}

/* read one indirect block (metadata -> always decrypted).
 * Returns a pointer OWNED by the fs indirect cache -- do NOT free it. */
static const int64_t *fs_read_indirect(UFS2FS *fs, int64_t frag_addr) {
    int n = fs->sb.nindir;
    if (frag_addr == 0) return fs->zero_ind;
    for (int i = 0; i < IND_CACHE; i++)
        if (fs->ic_data[i] && fs->ic_addr[i] == frag_addr) return fs->ic_data[i];
    int slot = fs->ic_next;
    fs->ic_next = (fs->ic_next + 1) % IND_CACHE;
    if (!fs->ic_data[slot]) {
        fs->ic_data[slot] = (int64_t *)malloc(n * sizeof(int64_t));
        if (!fs->ic_data[slot]) die("out of memory");
    }
    uint8_t *data = (uint8_t *)malloc(fs->sb.bsize);
    if (!data) die("out of memory");
    ci_read(fs->img, sb_frag_to_byte(&fs->sb, frag_addr), fs->sb.bsize, data);
    for (int i = 0; i < n; i++) fs->ic_data[slot][i] = rd_i64(data + i*8);
    free(data);
    fs->ic_addr[slot] = frag_addr;
    return fs->ic_data[slot];
}

/* map logical block number -> frag address */
static int64_t fs_bmap(UFS2FS *fs, const Inode *in, int64_t lbn) {
    int nindir = fs->sb.nindir;
    if (lbn < NDADDR) return in->db[lbn];
    lbn -= NDADDR;
    if (lbn < nindir) {
        const int64_t *l1 = fs_read_indirect(fs, in->ib[0]);
        return l1[lbn];
    }
    lbn -= nindir;
    if (lbn < (int64_t)nindir * nindir) {
        const int64_t *l1 = fs_read_indirect(fs, in->ib[1]);
        int64_t a = l1[lbn / nindir];
        const int64_t *l2 = fs_read_indirect(fs, a);
        return l2[lbn % nindir];
    }
    lbn -= (int64_t)nindir * nindir;
    const int64_t *l1 = fs_read_indirect(fs, in->ib[2]);
    int64_t a = l1[lbn / ((int64_t)nindir * nindir)];
    const int64_t *l2 = fs_read_indirect(fs, a);
    int64_t b = l2[(lbn / nindir) % nindir];
    const int64_t *l3 = fs_read_indirect(fs, b);
    return l3[lbn % nindir];
}

/* Iterate file contents block by block into a callback.
 * Returns 0 on success. decrypt_data: 1 = decrypt, 0 = raw passthrough. */
typedef int (*chunk_cb)(const uint8_t *buf, int64_t len, void *ud);

static int fs_read_file_iter(UFS2FS *fs, const Inode *in, int decrypt_data,
                             chunk_cb cb, void *ud) {
    int bsize = fs->sb.bsize;
    int64_t remaining = (int64_t)in->size;
    int64_t lbn = 0;
    uint8_t *buf = (uint8_t *)malloc(bsize);
    uint8_t *zero = (uint8_t *)calloc(bsize, 1);
    if (!buf || !zero) die("out of memory");
    int rc = 0;
    while (remaining > 0) {
        int64_t want = remaining < bsize ? remaining : bsize;
        int64_t addr = fs_bmap(fs, in, lbn);
        if (addr == 0) {
            rc = cb(zero, want, ud);
        } else {
            int64_t boff = sb_frag_to_byte(&fs->sb, addr);
            if (decrypt_data) ci_read(fs->img, boff, want, buf);
            else              ci_read_plain(fs->img, boff, want, buf);
            rc = cb(buf, want, ud);
        }
        if (rc) break;
        remaining -= want;
        lbn++;
    }
    free(buf);
    free(zero);
    return rc;
}

/* --------------------------------------------------------------------------
 * pipelined file extractor
 *
 * A single producer thread reads the next data block(s) from the image while
 * the main thread decrypts (via the sector pool) and writes the current block,
 * overlapping I/O with compute/output. The block address list is resolved up
 * front (single-threaded, uses the indirect cache), so the producer performs
 * only raw reads and never touches the decrypt pool -> no contention, and only
 * the producer touches the image FILE* -> no shared-handle race.
 * ------------------------------------------------------------------------ */
#define PIPE_SLOTS      6    /* ring depth (blocks read ahead)  */
#define PIPE_MIN_BLOCKS 3    /* below this, just go serial      */

typedef struct {
    CryptImage *img;
    Superblock *sb;
    int         decrypt;
    int64_t     nblocks;
    const int64_t *addr;     /* frag addr per block (0 = sparse hole) */
    const int64_t *want;     /* logical bytes per block               */
    int         nslots;
    uint8_t   **slot;        /* nslots buffers, each bsize            */
    int64_t    *slot_rlen;   /* bytes actually read into each slot    */
    int64_t     produced, consumed;
    mutex_t     mtx;
    cond_t      not_full, not_empty;
} pipe_ctx;

static THREAD_RET pipe_producer(void *arg) {
    pipe_ctx *p = (pipe_ctx *)arg;
    for (int64_t i = 0; i < p->nblocks; i++) {
        MTX_LOCK(&p->mtx);
        while (i - p->consumed >= p->nslots) COND_WAIT(&p->not_full, &p->mtx);
        MTX_UNLOCK(&p->mtx);

        int idx = (int)(i % p->nslots);
        uint8_t *s = p->slot[idx];
        int64_t  w = p->want[i];
        int64_t  a = p->addr[i];
        int64_t  rlen;
        if (a == 0) {                     /* sparse hole -> zeros, never decrypted */
            memset(s, 0, (size_t)w);
            rlen = w;
        } else {
            rlen = p->decrypt ? ((w + SECTOR - 1) / SECTOR) * SECTOR : w;
            ci_read_plain(p->img, sb_frag_to_byte(p->sb, a), rlen, s);
        }
        p->slot_rlen[idx] = rlen;

        MTX_LOCK(&p->mtx);
        p->produced = i + 1;
        COND_SIGNAL(&p->not_empty);
        MTX_UNLOCK(&p->mtx);
    }
    THREAD_RETURN;
}

/* Extract inode contents, overlapping reads with decrypt+write. Same callback
 * contract as fs_read_file_iter. */
static int pipe_extract(UFS2FS *fs, const Inode *in, int decrypt, chunk_cb cb, void *ud) {
    int bsize = fs->sb.bsize;
    int64_t nblocks = (int64_t)((in->size + bsize - 1) / bsize);

    if (g_nthreads <= 1 || nblocks < PIPE_MIN_BLOCKS)
        return fs_read_file_iter(fs, in, decrypt, cb, ud);

    /* resolve all block addresses up front (uses indirect cache) */
    int64_t *addr = (int64_t *)malloc(nblocks * sizeof(int64_t));
    int64_t *want = (int64_t *)malloc(nblocks * sizeof(int64_t));
    if (!addr || !want) die("out of memory");
    int64_t remaining = (int64_t)in->size;
    for (int64_t i = 0; i < nblocks; i++) {
        want[i] = remaining < bsize ? remaining : bsize;
        addr[i] = fs_bmap(fs, in, i);
        remaining -= want[i];
    }

    pipe_ctx p;
    memset(&p, 0, sizeof(p));
    p.img = fs->img; p.sb = &fs->sb; p.decrypt = decrypt;
    p.nblocks = nblocks; p.addr = addr; p.want = want;
    p.nslots = PIPE_SLOTS;
    p.slot = (uint8_t **)malloc(p.nslots * sizeof(uint8_t *));
    p.slot_rlen = (int64_t *)malloc(p.nslots * sizeof(int64_t));
    for (int i = 0; i < p.nslots; i++) {
        p.slot[i] = (uint8_t *)malloc(bsize);
        if (!p.slot[i]) die("out of memory");
    }
    MTX_INIT(&p.mtx); COND_INIT(&p.not_full); COND_INIT(&p.not_empty);

    thread_t prod;
    thread_start(&prod, pipe_producer, &p);

    int rc = 0;
    for (int64_t j = 0; j < nblocks; j++) {
        MTX_LOCK(&p.mtx);
        while (p.produced <= j) COND_WAIT(&p.not_empty, &p.mtx);
        MTX_UNLOCK(&p.mtx);

        int idx = (int)(j % p.nslots);
        uint8_t *s = p.slot[idx];
        int64_t  rlen = p.slot_rlen[idx];
        int64_t  w = want[j];
        if (decrypt && addr[j] != 0 && !fs->img->plain) {
            uint64_t base_sec = fs->img->ivoffset +
                                (uint64_t)(sb_frag_to_byte(&fs->sb, addr[j]) / SECTOR);
            decrypt_sectors(&fs->img->xts, s, base_sec, rlen / SECTOR);
        }
        rc = cb(s, w, ud);

        MTX_LOCK(&p.mtx);
        p.consumed = j + 1;
        COND_SIGNAL(&p.not_full);
        MTX_UNLOCK(&p.mtx);
        if (rc) break;
    }

    /* if the writer bailed early, let the producer run to completion so it does
     * not block on a full ring (nblocks are bounded; simplest correct drain) */
    if (rc) {
        MTX_LOCK(&p.mtx);
        p.consumed = nblocks;           /* unblock producer's not_full waits */
        COND_BCAST(&p.not_full);
        MTX_UNLOCK(&p.mtx);
    }
    thread_join(prod);

    for (int i = 0; i < p.nslots; i++) free(p.slot[i]);
    free(p.slot); free(p.slot_rlen);
    MTX_DESTROY(&p.mtx);
    free(addr); free(want);
    return rc;
}

/* collect whole file into a malloc'd buffer (used for metadata: dirs, symlinks) */
typedef struct { uint8_t *data; int64_t len, cap; } bytebuf;
static int bb_cb(const uint8_t *buf, int64_t len, void *ud) {
    bytebuf *bb = (bytebuf *)ud;
    if (bb->len + len > bb->cap) {
        bb->cap = (bb->len + len) * 2 + 64;
        bb->data = (uint8_t *)realloc(bb->data, (size_t)bb->cap);
        if (!bb->data) die("out of memory");
    }
    memcpy(bb->data + bb->len, buf, (size_t)len);
    bb->len += len;
    return 0;
}
static bytebuf fs_read_file(UFS2FS *fs, const Inode *in, int decrypt_data) {
    bytebuf bb = {0,0,0};
    fs_read_file_iter(fs, in, decrypt_data, bb_cb, &bb);
    return bb;
}

/* symlink target (returned in caller buffer, NUL-terminated) */
static void fs_readlink(UFS2FS *fs, const Inode *in, char *out, size_t outsz) {
    if (in->blocks == 0 || in->size <= (NDADDR + NIADDR) * 8) {
        size_t n = in->size < outsz-1 ? (size_t)in->size : outsz-1;
        memcpy(out, in->raw + 112, n);
        out[n] = 0;
    } else {
        bytebuf bb = fs_read_file(fs, in, 1);
        size_t n = (size_t)bb.len < outsz-1 ? (size_t)bb.len : outsz-1;
        memcpy(out, bb.data, n);
        out[n] = 0;
        free(bb.data);
    }
}

/* directory iteration callback */
typedef int (*dir_cb)(const char *name, uint32_t ino, uint8_t dtype, void *ud);
static void fs_listdir(UFS2FS *fs, const Inode *in, dir_cb cb, void *ud) {
    bytebuf bb = fs_read_file(fs, in, 1);
    int64_t off = 0, n = bb.len;
    while (off + 8 <= n) {
        uint32_t d_ino    = rd_u32(bb.data + off);
        uint16_t d_reclen = rd_u16(bb.data + off + 4);
        uint8_t  d_type   = bb.data[off + 6];
        uint8_t  d_namlen = bb.data[off + 7];
        if (d_reclen == 0) break;
        if (d_ino != 0 && d_namlen > 0 && off + 8 + d_namlen <= n) {
            char name[256];
            memcpy(name, bb.data + off + 8, d_namlen);
            name[d_namlen] = 0;
            if (cb(name, d_ino, d_type, ud)) break;
        }
        off += d_reclen;
    }
    free(bb.data);
}

/* --- path resolution ---------------------------------------------------- */
/* Find one child ino by name inside dir. Returns ino or 0. */
typedef struct { const char *want; uint32_t found; } find_ctx;
static int find_cb(const char *name, uint32_t ino, uint8_t dtype, void *ud) {
    (void)dtype;
    find_ctx *fc = (find_ctx *)ud;
    if (strcmp(name, fc->want) == 0) { fc->found = ino; return 1; }
    return 0;
}

static int fs_resolve(UFS2FS *fs, const char *path, Inode *out);  /* fwd */

/* normalize path (collapse ., .., duplicate /) into out, absolute */
static void norm_path(const char *in, char *out, size_t outsz) {
    char tmp[4096];
    size_t ti = 0;
    for (const char *p = in; *p && ti < sizeof(tmp)-1; p++)
        tmp[ti++] = (*p == '\\') ? '/' : *p;
    tmp[ti] = 0;
    /* split into components onto a stack */
    char *comps[512]; int nc = 0;
    char *save = NULL, *tok = strtok_r(tmp, "/", &save);
    while (tok) {
        if (strcmp(tok, ".") == 0 || tok[0] == 0) { }
        else if (strcmp(tok, "..") == 0) { if (nc > 0) nc--; }
        else if (nc < 512) comps[nc++] = tok;
        tok = strtok_r(NULL, "/", &save);
    }
    size_t oi = 0;
    if (nc == 0) { out[0] = '/'; out[1] = 0; return; }
    for (int i = 0; i < nc; i++) {
        if (oi < outsz-1) out[oi++] = '/';
        for (char *c = comps[i]; *c && oi < outsz-1; c++) out[oi++] = *c;
    }
    out[oi] = 0;
}

#ifdef _WIN32
/* strtok_r shim */
static char *strtok_r(char *s, const char *d, char **save) {
    if (!s) s = *save;
    if (!s) return NULL;
    s += strspn(s, d);
    if (!*s) { *save = NULL; return NULL; }
    char *tok = s;
    s += strcspn(s, d);
    if (*s) { *s = 0; *save = s + 1; } else *save = NULL;
    return tok;
}
#endif

static int fs_resolve(UFS2FS *fs, const char *path, Inode *out) {
    fs_inode(fs, ROOTINO, out);
    if (path[0] == 0 || (path[0] == '/' && path[1] == 0)) return 0;

    char work[4096];
    size_t wi = 0;
    for (const char *p = path; *p && wi < sizeof(work)-1; p++)
        work[wi++] = (*p == '\\') ? '/' : *p;
    work[wi] = 0;

    /* split into parts */
    char *parts[512]; int np = 0;
    char *save = NULL, *tok = strtok_r(work, "/", &save);
    while (tok) { if (np < 512) parts[np++] = tok; tok = strtok_r(NULL, "/", &save); }

    for (int i = 0; i < np; i++) {
        if (!in_isdir(out)) return -1;
        find_ctx fc = { parts[i], 0 };
        fs_listdir(fs, out, find_cb, &fc);
        if (fc.found == 0) return -1;
        fs_inode(fs, fc.found, out);
        /* follow symlink for intermediate components */
        if (in_islnk(out) && i < np - 1) {
            char target[4096];
            fs_readlink(fs, out, target, sizeof(target));
            if (target[0] == '/') {
                if (fs_resolve(fs, target, out) != 0) return -1;
            } else {
                /* base = "/" + parts[0..i-1] */
                char base[4096]; size_t bi = 0;
                for (int j = 0; j < i; j++) {
                    base[bi++] = '/';
                    for (char *c = parts[j]; *c; c++) base[bi++] = *c;
                }
                base[bi] = 0;
                char joined[4096];
                snprintf(joined, sizeof(joined), "%s/%s", base, target);
                char normed[4096];
                norm_path(joined, normed, sizeof(normed));
                if (fs_resolve(fs, normed, out) != 0) return -1;
            }
        }
    }
    return 0;
}

/* decide whether a file's data should be read as plaintext (.pkg passthrough) */
static int fs_is_plaintext_pkg(UFS2FS *fs, const char *name, const Inode *in) {
    if (!fs->pkg_plaintext) return 0;
    size_t ln = strlen(name);
    if (ln < 4) return 0;
    const char *ext = name + ln - 4;
    if (!(tolower((unsigned char)ext[0])=='.' && tolower((unsigned char)ext[1])=='p' &&
          tolower((unsigned char)ext[2])=='k' && tolower((unsigned char)ext[3])=='g')) return 0;
    int64_t addr = fs_bmap(fs, in, 0);
    if (addr == 0) return 0;
    uint8_t head[4];
    ci_read_plain(fs->img, sb_frag_to_byte(&fs->sb, addr), 4, head);
    return memcmp(head, PKG_MAGIC, 4) == 0;
}

/* ==========================================================================
 * formatting helpers
 * ======================================================================== */
static const char *mode_str(uint16_t mode) {
    static char s[11];
    int t = mode & S_IFMT_;
    s[0] = (t == S_IFDIR_) ? 'd' : (t == S_IFREG_) ? '-' : (t == S_IFLNK_) ? 'l' : '?';
    const int who[3] = {6,3,0};
    for (int k = 0; k < 3; k++) {
        int bits = (mode >> who[k]) & 7;
        s[1+k*3+0] = (bits & 4) ? 'r' : '-';
        s[1+k*3+1] = (bits & 2) ? 'w' : '-';
        s[1+k*3+2] = (bits & 1) ? 'x' : '-';
    }
    s[10] = 0;
    return s;
}

/* rotating static buffers so several human() calls in one printf are safe */
static const char *human(uint64_t n) {
    static char bufs[8][32];
    static int idx = 0;
    char *out = bufs[idx = (idx + 1) & 7];
    const char *u[] = {"B","K","M","G","T"};
    double v = (double)n;
    for (int i = 0; i < 5; i++) {
        if (v < 1024.0 || i == 4) {
            if (i == 0) snprintf(out, 32, "%d%s", (int)v, u[i]);
            else        snprintf(out, 32, "%.1f%s", v, u[i]);
            return out;
        }
        v /= 1024.0;
    }
    return out;
}

/* ==========================================================================
 * directory/file helpers for output side
 * ======================================================================== */
static int is_directory(const char *path) {
    stat_t st;
    if (STAT64(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

static void mkdirs(const char *path) {
    char tmp[4096];
    size_t n = 0;
    for (const char *p = path; *p && n < sizeof(tmp)-1; p++) tmp[n++] = *p;
    tmp[n] = 0;
    for (size_t i = 1; i < n; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            char c = tmp[i]; tmp[i] = 0;
            if (tmp[0]) MKDIR(tmp);
            tmp[i] = c;
        }
    }
    if (tmp[0]) MKDIR(tmp);
}

static const char *basename_of(const char *path) {
    const char *b = path;
    for (const char *p = path; *p; p++)
        if (*p == '/' || *p == '\\') b = p + 1;
    return b;
}

/* ==========================================================================
 * commands
 * ======================================================================== */
static void cmd_info(UFS2FS *fs) {
    Superblock *sb = &fs->sb;
    uint64_t total = (uint64_t)sb->size * sb->fsize;
    printf("UFS2 filesystem\n");
    printf("  magic        : 0x%08x\n", sb->magic);
    printf("  block size   : %d\n", sb->bsize);
    printf("  frag size    : %d\n", sb->fsize);
    printf("  frags/block  : %d\n", sb->frag);
    printf("  cyl groups   : %d\n", sb->ncg);
    printf("  inodes/group : %d\n", sb->ipg);
    printf("  frags/group  : %d\n", sb->fpg);
    printf("  fs size      : %lld frags (%s)\n", (long long)sb->size, human(total));
    printf("  crypto       : %s\n", fs->img->plain ? "none (already decrypted)" : "AES-128-XTS");
    printf("  pkg-plaintext: %s\n", fs->pkg_plaintext ? "on" : "off");
}

/* --- ls listing collection --------------------------------------------- */
typedef struct { char name[256]; uint32_t ino; } dirent_row;
typedef struct { dirent_row *rows; int n, cap; } dirent_list;
static int collect_cb(const char *name, uint32_t ino, uint8_t dtype, void *ud) {
    (void)dtype;
    dirent_list *dl = (dirent_list *)ud;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return 0;
    if (dl->n >= dl->cap) {
        dl->cap = dl->cap ? dl->cap*2 : 64;
        dl->rows = (dirent_row *)realloc(dl->rows, dl->cap * sizeof(dirent_row));
        if (!dl->rows) die("out of memory");
    }
    snprintf(dl->rows[dl->n].name, 256, "%s", name);
    dl->rows[dl->n].ino = ino;
    dl->n++;
    return 0;
}
static int row_cmp(const void *a, const void *b) {
    return strcmp(((const dirent_row*)a)->name, ((const dirent_row*)b)->name);
}

static void cmd_ls(UFS2FS *fs, const char *path) {
    Inode dir;
    if (fs_resolve(fs, path, &dir) != 0) die("path not found: %s", path);
    if (!in_isdir(&dir)) {
        const char *name = basename_of(path);
        char sfx[4096] = "";
        if (in_islnk(&dir)) { char t[4096]; fs_readlink(fs, &dir, t, sizeof(t)); snprintf(sfx, sizeof(sfx), " -> %s", t); }
        const char *pkg = (in_isreg(&dir) && fs_is_plaintext_pkg(fs, name, &dir)) ? "  [plaintext pkg]" : "";
        printf("%s %10s  %s%s%s\n", mode_str(dir.mode), human(dir.size), name, sfx, pkg);
        return;
    }
    dirent_list dl = {0,0,0};
    fs_listdir(fs, &dir, collect_cb, &dl);
    qsort(dl.rows, dl.n, sizeof(dirent_row), row_cmp);
    for (int i = 0; i < dl.n; i++) {
        Inode ci; fs_inode(fs, dl.rows[i].ino, &ci);
        char sfx[4096] = "";
        if (in_islnk(&ci)) { char t[4096]; fs_readlink(fs, &ci, t, sizeof(t)); snprintf(sfx, sizeof(sfx), " -> %s", t); }
        const char *tag = in_isdir(&ci) ? "/" : "";
        const char *pkg = (in_isreg(&ci) && fs_is_plaintext_pkg(fs, dl.rows[i].name, &ci)) ? "  [plaintext pkg]" : "";
        printf("%s %10s  %s%s%s%s\n", mode_str(ci.mode), human(ci.size), dl.rows[i].name, tag, sfx, pkg);
    }
    free(dl.rows);
}

static void cmd_stat(UFS2FS *fs, const char *path) {
    Inode in;
    if (fs_resolve(fs, path, &in) != 0) die("path not found: %s", path);
    const char *name = basename_of(path);
    if (!*name) name = "/";
    printf("path   : %s\n", path);
    printf("inode  : %u\n", in.ino);
    printf("mode   : %s (0%o)\n", mode_str(in.mode), in.mode);
    printf("size   : %llu (%s)\n", (unsigned long long)in.size, human(in.size));
    printf("blocks : %llu (x512)\n", (unsigned long long)in.blocks);
    printf("uid/gid: %u/%u\n", in.uid, in.gid);
    printf("mtime  : %lld\n", (long long)in.mtime);
    if (in_isreg(&in)) printf("plaintext-pkg: %s\n", fs_is_plaintext_pkg(fs, name, &in) ? "True" : "False");
    if (in_islnk(&in)) { char t[4096]; fs_readlink(fs, &in, t, sizeof(t)); printf("target : %s\n", t); }
}

static void tree_walk(UFS2FS *fs, const char *path, int depth, const char *prefix) {
    Inode dir;
    if (fs_resolve(fs, path, &dir) != 0) { printf("%s  [error: not found]\n", prefix); return; }
    if (!in_isdir(&dir)) return;
    dirent_list dl = {0,0,0};
    fs_listdir(fs, &dir, collect_cb, &dl);
    qsort(dl.rows, dl.n, sizeof(dirent_row), row_cmp);
    for (int i = 0; i < dl.n; i++) {
        int last = (i == dl.n - 1);
        Inode ci; fs_inode(fs, dl.rows[i].ino, &ci);
        const char *conn = last ? "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 " : "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 ";
        const char *tag  = in_isdir(&ci) ? "/" : (in_islnk(&ci) ? "@" : "");
        printf("%s%s%s%s\n", prefix, conn, dl.rows[i].name, tag);
        if (in_isdir(&ci) && depth > 1) {
            char child[4096], newpref[4096];
            const char *base = path;
            /* strip trailing slash from base for join */
            char b2[4096]; snprintf(b2, sizeof(b2), "%s", base);
            size_t bl = strlen(b2); while (bl > 1 && b2[bl-1] == '/') b2[--bl] = 0;
            snprintf(child, sizeof(child), "%s/%s", b2, dl.rows[i].name);
            snprintf(newpref, sizeof(newpref), "%s%s", prefix, last ? "    " : "\xe2\x94\x82   ");
            tree_walk(fs, child, depth - 1, newpref);
        }
    }
    free(dl.rows);
}
static void cmd_tree(UFS2FS *fs, const char *path, int depth) {
    printf("%s\n", path);
    tree_walk(fs, path, depth, "");
}

/* cat: write file to stdout */
static int stdout_cb(const uint8_t *buf, int64_t len, void *ud) {
    (void)ud;
    fwrite(buf, 1, (size_t)len, stdout);
    return 0;
}
static void cmd_cat(UFS2FS *fs, const char *path) {
    Inode in;
    if (fs_resolve(fs, path, &in) != 0) die("path not found: %s", path);
    if (!in_isreg(&in)) die("not a regular file");
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    const char *name = basename_of(path);
    int plain = fs_is_plaintext_pkg(fs, name, &in);
    pipe_extract(fs, &in, !plain, stdout_cb, NULL);
    fflush(stdout);
}

/* get: extract one file to disk, with progress */
typedef struct { FILE *fp; int64_t written; uint64_t total; } extract_ctx;
static int extract_cb(const uint8_t *buf, int64_t len, void *ud) {
    extract_ctx *ec = (extract_ctx *)ud;
    fwrite(buf, 1, (size_t)len, ec->fp);
    ec->written += len;
    int pct = ec->total ? (int)(ec->written * 100 / (int64_t)ec->total) : 100;
    fprintf(stderr, "\r  %s / %s (%d%%)   ", human((uint64_t)ec->written), human(ec->total), pct);
    fflush(stderr);
    return 0;
}
static int extract_cb_quiet(const uint8_t *buf, int64_t len, void *ud) {
    extract_ctx *ec = (extract_ctx *)ud;
    fwrite(buf, 1, (size_t)len, ec->fp);
    ec->written += len;
    return 0;
}
static void cmd_get(UFS2FS *fs, const char *path, const char *out) {
    Inode in;
    if (fs_resolve(fs, path, &in) != 0) die("path not found: %s", path);
    if (!in_isreg(&in)) die("not a regular file");
    const char *name = basename_of(path);
    char outpath[4096];
    if (is_directory(out)) snprintf(outpath, sizeof(outpath), "%s/%s", out, name);
    else                   snprintf(outpath, sizeof(outpath), "%s", out);
    int plain = fs_is_plaintext_pkg(fs, name, &in);
    FILE *fp = fopen(outpath, "wb");
    if (!fp) die("cannot open output: %s", outpath);
    extract_ctx ec = { fp, 0, in.size };
    pipe_extract(fs, &in, !plain, extract_cb, &ec);
    fclose(fp);
    fprintf(stderr, "\n");
    printf("wrote %s (%s)%s\n", outpath, human((uint64_t)ec.written),
           plain ? "  [plaintext pkg]" : "  [decrypted]");
}

/* find: recursive name search */
static void find_walk(UFS2FS *fs, const char *path, const Inode *dir, const char *needle, int depth);
typedef struct { UFS2FS *fs; const char *base; const char *needle; int depth; } fw_ctx;
static int fw_cb(const char *name, uint32_t ino, uint8_t dtype, void *ud) {
    (void)dtype;
    fw_ctx *c = (fw_ctx *)ud;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return 0;
    char full[4096];
    char b2[4096]; snprintf(b2, sizeof(b2), "%s", c->base);
    size_t bl = strlen(b2); while (bl > 1 && b2[bl-1] == '/') b2[--bl] = 0;
    snprintf(full, sizeof(full), "%s/%s", b2, name);
    /* case-insensitive substring match */
    char lname[256]; size_t i;
    for (i = 0; name[i] && i < 255; i++) lname[i] = (char)tolower((unsigned char)name[i]);
    lname[i] = 0;
    if (strstr(lname, c->needle)) printf("%s\n", full);
    Inode child; fs_inode(c->fs, ino, &child);
    if (in_isdir(&child) && c->depth - 1 > 0)
        find_walk(c->fs, full, &child, c->needle, c->depth - 1);
    return 0;
}
static void find_walk(UFS2FS *fs, const char *path, const Inode *dir, const char *needle, int depth) {
    if (depth <= 0) return;
    fw_ctx c = { fs, path, needle, depth };
    fs_listdir(fs, dir, fw_cb, &c);
}
static void cmd_find(UFS2FS *fs, const char *name, int depth) {
    char needle[256]; size_t i;
    for (i = 0; name[i] && i < 255; i++) needle[i] = (char)tolower((unsigned char)name[i]);
    needle[i] = 0;
    Inode root; fs_resolve(fs, "/", &root);
    find_walk(fs, "", &root, needle, depth);
}

/* getdir: recursive extract */
typedef struct {
    UFS2FS *fs;
    const char *outroot;
    const char *src;
    int dry_run, skip_pkg;
    int64_t max_size;
    long long dirs, files, links, bytes, skipped, errors;
} getdir_state;

static void getdir_walk(getdir_state *st, const char *rel, const Inode *dir, int depth);

typedef struct { getdir_state *st; const char *rel; int depth; } gd_ctx;
static int gd_cb(const char *name, uint32_t ino, uint8_t dtype, void *ud) {
    (void)dtype;
    gd_ctx *c = (gd_ctx *)ud;
    getdir_state *st = c->st;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return 0;

    char child_rel[4096];
    if (c->rel && c->rel[0]) snprintf(child_rel, sizeof(child_rel), "%s/%s", c->rel, name);
    else                     snprintf(child_rel, sizeof(child_rel), "%s", name);
    char outpath[8192];
    snprintf(outpath, sizeof(outpath), "%s/%s", st->outroot, child_rel);

    Inode child; fs_inode(st->fs, ino, &child);

    if (in_isdir(&child)) {
        st->dirs++;
        if (!st->dry_run) mkdirs(outpath);
        if (c->depth != 0)
            getdir_walk(st, child_rel, &child, c->depth > 0 ? c->depth - 1 : -1);
    } else if (in_isreg(&child)) {
        size_t ln = strlen(name);
        int is_pkg = ln >= 4 && tolower((unsigned char)name[ln-4])=='.' &&
                     tolower((unsigned char)name[ln-3])=='p' &&
                     tolower((unsigned char)name[ln-2])=='k' &&
                     tolower((unsigned char)name[ln-1])=='g';
        if (st->skip_pkg && is_pkg) {
            st->skipped++;
            printf("  skip (pkg): %s\n", child_rel);
            return 0;
        }
        if (st->max_size && (int64_t)child.size > st->max_size) {
            st->skipped++;
            printf("  skip (>%s): %s (%s)\n", human((uint64_t)st->max_size), child_rel, human(child.size));
            return 0;
        }
        int plain = fs_is_plaintext_pkg(st->fs, name, &child);
        printf("  %8s  %s%s\n", human(child.size), child_rel, plain ? " [pkg]" : "");
        if (!st->dry_run) {
            /* ensure parent dir exists */
            char parent[8192]; snprintf(parent, sizeof(parent), "%s", outpath);
            char *slash = strrchr(parent, '/');
            if (slash) { *slash = 0; mkdirs(parent); }
            FILE *fp = fopen(outpath, "wb");
            if (!fp) { st->errors++; printf("  ERROR %s: cannot create\n", child_rel); return 0; }
            extract_ctx ec = { fp, 0, 0 };   /* no per-file progress bar in getdir */
            pipe_extract(st->fs, &child, !plain, extract_cb_quiet, &ec);
            fclose(fp);
        }
        st->files++;
        st->bytes += (long long)child.size;
    } else if (in_islnk(&child)) {
        st->links++;
        char target[4096];
        fs_readlink(st->fs, &child, target, sizeof(target));
        printf("  link      %s -> %s\n", child_rel, target);
        if (!st->dry_run) {
            char parent[8192]; snprintf(parent, sizeof(parent), "%s", outpath);
            char *slash = strrchr(parent, '/');
            if (slash) { *slash = 0; mkdirs(parent); }
            char linkfile[8200];
            snprintf(linkfile, sizeof(linkfile), "%s.symlink", outpath);
            FILE *lf = fopen(linkfile, "w");
            if (lf) { fprintf(lf, "%s\n", target); fclose(lf); }
        }
    }
    return 0;
}
static void getdir_walk(getdir_state *st, const char *rel, const Inode *dir, int depth) {
    gd_ctx c = { st, rel, depth };
    fs_listdir(st->fs, dir, gd_cb, &c);
}

static void cmd_getdir(UFS2FS *fs, const char *path, const char *out,
                       int depth, int skip_pkg, int64_t max_size, int dry_run) {
    /* strip trailing slash */
    char src[4096]; snprintf(src, sizeof(src), "%s", path);
    size_t sl = strlen(src); while (sl > 1 && src[sl-1] == '/') src[--sl] = 0;
    if (!src[0]) { src[0] = '/'; src[1] = 0; }

    Inode root;
    if (fs_resolve(fs, src, &root) != 0) die("path not found: %s", src);

    if (!in_isdir(&root)) {
        mkdirs(out);
        const char *name = basename_of(src);
        char outpath[8192]; snprintf(outpath, sizeof(outpath), "%s/%s", out, name);
        int plain = fs_is_plaintext_pkg(fs, name, &root);
        FILE *fp = fopen(outpath, "wb");
        if (!fp) die("cannot create %s", outpath);
        extract_ctx ec = { fp, 0, root.size };
        pipe_extract(fs, &root, !plain, extract_cb, &ec);
        fclose(fp);
        fprintf(stderr, "\n");
        printf("wrote %s (%s)%s\n", name, human((uint64_t)ec.written), plain ? "  [plaintext pkg]" : "");
        return;
    }

    if (!dry_run) mkdirs(out);
    printf("extracting %s -> %s%s\n", src, out, dry_run ? "  (dry run)" : "");

    getdir_state st;
    memset(&st, 0, sizeof(st));
    st.fs = fs; st.outroot = out; st.src = src;
    st.dry_run = dry_run; st.skip_pkg = skip_pkg; st.max_size = max_size;

    getdir_walk(&st, "", &root, depth);

    printf("\ndone: %lld dirs, %lld files (%s), %lld symlinks, %lld skipped, %lld errors\n",
           st.dirs, st.files, human((uint64_t)st.bytes), st.links, st.skipped, st.errors);
}

/* ==========================================================================
 * scan: carve raw .pkg (CNT) packages out of the partition, in parallel
 *
 * Installed packages are stored PLAINTEXT inside the encrypted volume (their
 * data blocks bypass XTS), so a .pkg begins with the CNT magic 0x7F"CNT" in
 * the raw image even though the surrounding filesystem metadata is encrypted.
 * Some packages are no longer referenced by any directory entry (e.g. /app is
 * empty) yet their bytes are still on disk, so we locate them by carving the
 * raw partition for the magic rather than by walking the directory tree.
 *
 * Phase 1 (parallel): the partition is split into byte ranges, one per worker;
 *   each worker scans its range (own FILE*, no shared handle) for frag-aligned
 *   CNT headers, validates them, and records {offset, size, content_id}.
 * Phase 2 (parallel): workers copy each carved package (raw, no decryption) to
 *   OUTDIR/<content_id>.pkg. The package length is pkg_size from the PKG header
 *   (big-endian u64 @ 0x430, verified == pfs_image_offset + pfs_image_size).
 *
 * --defrag: a deleted package's blocks are marked FREE in the UFS2 cylinder-
 *   group bitmaps, while blocks still ALLOCATED inside its byte span belong to
 *   other live files or to cg metadata (backup superblock + inode table at each
 *   cg boundary) -- i.e. the foreign fragments a plain carve wrongly includes.
 *   With --defrag, phase 2 walks the bitmaps and copies only free frags,
 *   skipping allocated ones, until pkg_size real bytes are collected -- so a
 *   package fragmented around cg metadata (any package larger than one cylinder
 *   group, ~740 MB here) is reassembled correctly. Applied only when a
 *   package's first frag is free (i.e. it was deleted); a live package (first
 *   frag allocated) is copied contiguously instead.
 * ======================================================================== */
#define CNT_MAGIC   0x7f434e54u     /* "\x7fCNT", big-endian */
#define PKG_HDR_LEN 0x440           /* bytes needed to reach pkg_size @0x430  */
#define PKG_ALIGN   4096            /* .pkg files start on a UFS2 frag boundary */
#define SCAN_CHUNK  (16*1024*1024)  /* per-worker read buffer (frag multiple)  */
#define CARVE_CHUNK (8*1024*1024)   /* per-worker copy buffer                   */

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];
}
static uint64_t rd_be64(const uint8_t *p) {
    return ((uint64_t)rd_be32(p) << 32) | rd_be32(p + 4);
}

typedef struct { uint64_t offset, size; char cid[80]; } pkg_hit;
typedef struct { pkg_hit *v; int n, cap; mutex_t mtx; } hit_list;

static void hit_add(hit_list *hl, uint64_t off, uint64_t size, const char *cid) {
    MTX_LOCK(&hl->mtx);
    if (hl->n >= hl->cap) {
        hl->cap = hl->cap ? hl->cap * 2 : 32;
        hl->v = (pkg_hit *)realloc(hl->v, hl->cap * sizeof(pkg_hit));
        if (!hl->v) die("out of memory");
    }
    hl->v[hl->n].offset = off; hl->v[hl->n].size = size;
    snprintf(hl->v[hl->n].cid, sizeof(hl->v[hl->n].cid), "%s", cid);
    hl->n++;
    MTX_UNLOCK(&hl->mtx);
}

/* Validate a CNT header. On success set *size (total pkg bytes) and cid[]. */
static int pkg_validate(const uint8_t *h, uint64_t *size, char *cid, size_t cidsz) {
    if (rd_be32(h) != CNT_MAGIC) return 0;
    uint64_t total  = rd_be64(h + 0x430);   /* pkg_size          */
    uint64_t pfsoff = rd_be64(h + 0x410);   /* pfs_image_offset  */
    uint64_t pfssz  = rd_be64(h + 0x418);   /* pfs_image_size    */
    if (total < 0x40000ULL || total > (1ULL << 40)) return 0;          /* 256KB .. 1TB */
    if (pfsoff < 0x2000ULL || pfssz == 0) return 0;
    if (pfsoff + pfssz > total || total - (pfsoff + pfssz) > 0x100000ULL) return 0;
    int n = 0;                                                          /* content_id @0x40 */
    for (int i = 0; i < 0x24; i++) {
        unsigned char c = h[0x40 + i];
        if (c == 0) break;
        if (c < 0x20 || c > 0x7e) return 0;                            /* must be printable */
        if ((size_t)n < cidsz - 1) cid[n++] = (char)c;
    }
    cid[n] = 0;
    if (n < 10) return 0;
    *size = total;
    return 1;
}

/* ---- phase 1: parallel detection ---- */
typedef struct {
    const char *img_path;
    uint64_t    part_offset, start, end, total_bytes;
    hit_list   *hits;
    mutex_t    *pmtx;            /* guards *scanned + progress print */
    uint64_t   *scanned;
} detect_arg;

static THREAD_RET detect_worker(void *arg) {
    detect_arg *a = (detect_arg *)arg;
    FILE *f = fopen(a->img_path, "rb");
    if (!f) die("cannot open image: %s", a->img_path);
    uint8_t *buf = (uint8_t *)malloc(SCAN_CHUNK);
    if (!buf) die("out of memory");
    uint64_t pos = a->start;
    while (pos < a->end) {
        size_t want = (size_t)((a->end - pos < SCAN_CHUNK) ? (a->end - pos) : SCAN_CHUNK);
        FSEEK64(f, (int64_t)(a->part_offset + pos), SEEK_SET);
        size_t got = fread(buf, 1, want, f);
        for (size_t j = 0; j + 4 <= got; j += PKG_ALIGN) {
            if (rd_be32(buf + j) != CNT_MAGIC) continue;
            uint8_t hdr[PKG_HDR_LEN];
            FSEEK64(f, (int64_t)(a->part_offset + pos + j), SEEK_SET);
            if (fread(hdr, 1, PKG_HDR_LEN, f) != PKG_HDR_LEN) continue;
            uint64_t sz; char cid[80];
            if (pkg_validate(hdr, &sz, cid, sizeof(cid)))
                hit_add(a->hits, pos + j, sz, cid);
        }
        pos += got;
        MTX_LOCK(a->pmtx);
        uint64_t before = *a->scanned; *a->scanned += got;
        if (*a->scanned / (16ULL<<30) != before / (16ULL<<30)) {
            fprintf(stderr, "\r  scanned %s / %s ...     ",
                    human(*a->scanned), human(a->total_bytes));
            fflush(stderr);
        }
        MTX_UNLOCK(a->pmtx);
        if (got < want) break;                 /* short read: end of file */
    }
    free(buf);
    fclose(f);
    THREAD_RETURN;
}

static int hit_cmp(const void *a, const void *b) {
    uint64_t x = ((const pkg_hit *)a)->offset, y = ((const pkg_hit *)b)->offset;
    return x < y ? -1 : x > y ? 1 : 0;
}

/* ---- phase 2: parallel extraction (raw copy, optional bitmap defrag) ---- */
typedef struct {
    hit_list   *hits;
    int         next;
    mutex_t     mtx;
    const char *img_path, *outroot;
    uint64_t    part_offset, ivoffset;
    const uint8_t *key;
    Superblock  sb;              /* shared read-only copy (for defrag) */
    int         plain;           /* image is already decrypted (no XTS) */
    int         dry_run, defrag, geom;
    long long   done, files, errors;
    uint64_t    bytes;
} carve_state;

/* small per-worker cache of cylinder-group free-block bitmaps */
#define CG_CACHE 4
typedef struct {
    CryptImage *img; Superblock *sb;
    int64_t  cg[CG_CACHE];
    uint8_t *bm[CG_CACHE];
    int      nb, next, have[CG_CACHE];
} cgcache;

/* Is fragment `frag` (partition-relative) FREE per its cg bitmap? A deleted
 * package's own blocks are free; blocks still allocated inside its span belong
 * to other live files or to cg metadata -- i.e. the foreign fragments to skip.
 * The cg block is metadata (encrypted): read raw, then decrypt inline (serial,
 * thread-safe -- never touches the shared decrypt pool). */
static int frag_is_free(cgcache *cc, int64_t frag) {
    Superblock *sb = cc->sb;
    int64_t cg = frag / sb->fpg;
    int64_t w  = frag % sb->fpg;
    uint8_t *bm = NULL;
    for (int i = 0; i < CG_CACHE; i++)
        if (cc->have[i] && cc->cg[i] == cg) { bm = cc->bm[i]; break; }
    if (!bm) {
        if (cc->nb == 0) cc->nb = (sb->fpg + 7) / 8;
        int slot = cc->next; cc->next = (cc->next + 1) % CG_CACHE;
        if (!cc->bm[slot]) cc->bm[slot] = (uint8_t *)malloc(cc->nb);
        uint8_t *cgblk = (uint8_t *)malloc(sb->bsize);
        if (!cc->bm[slot] || !cgblk) die("out of memory");
        int64_t cgblk_off = (int64_t)(sb->fpg * cg + sb->cblkno) * sb->fsize;
        ci_read_plain(cc->img, cgblk_off, sb->bsize, cgblk);
        if (!cc->img->plain) {          /* cg block is metadata: decrypt unless plain image */
            uint64_t base_sec = cc->img->ivoffset + (uint64_t)(cgblk_off / SECTOR);
            pool_decrypt_serial(&cc->img->xts, cgblk, base_sec, sb->bsize / SECTOR);
        }
        int32_t freeoff = rd_i32(cgblk + 0x60);          /* cg_freeoff */
        if (freeoff < 0 || freeoff + cc->nb > sb->bsize) freeoff = 0;
        memcpy(cc->bm[slot], cgblk + freeoff, cc->nb);
        free(cgblk);
        cc->cg[slot] = cg; cc->have[slot] = 1; bm = cc->bm[slot];
    }
    return (bm[w >> 3] >> (w & 7)) & 1;
}

/* Reconstruct a fragmented (deleted) package by copying only FREE frags,
 * skipping allocated (foreign) ones, until pkg_size bytes are collected. */
static uint64_t carve_defrag(CryptImage *ci, cgcache *cc, const Superblock *sb,
                             uint64_t off, uint64_t size, uint8_t *buf, FILE *out,
                             long long *skipped) {
    int64_t fsize = sb->fsize;
    int64_t fr = (int64_t)(off / fsize);
    uint64_t wrote = 0;
    while (wrote < size) {
        if (!frag_is_free(cc, fr)) { fr++; (*skipped)++; continue; }
        int64_t remain = (int64_t)((size - wrote + fsize - 1) / fsize);
        int64_t run = 1;
        while (run < remain && frag_is_free(cc, fr + run)) run++;
        int64_t r = fr, left = run;
        while (left > 0 && wrote < size) {
            int64_t c = left < (CARVE_CHUNK / fsize) ? left : (CARVE_CHUNK / fsize);
            int64_t nbytes = c * fsize;
            if (wrote + (uint64_t)nbytes > size) nbytes = (int64_t)(size - wrote);
            ci_read_plain(ci, r * fsize, nbytes, buf);
            fwrite(buf, 1, (size_t)nbytes, out);
            wrote += (uint64_t)nbytes; r += c; left -= c;
        }
        fr += run;
    }
    return wrote;
}

/* Reconstruct a fragmented package by UFS2 *geometry* rather than the free-block
 * bitmap. A large file's data blocks are laid down contiguously in the DATA area
 * of each cylinder group; the only interruptions are the fixed metadata region
 * at the head of every cg (boot/backup-superblock + cg block + inode table),
 * which occupies frags [cgbase, cgbase+dblkno) and is identical for every cg.
 *
 * So we read contiguous data-region frags and, at each cg boundary, skip exactly
 * that reserved gap -- no bitmap, no per-frag free/allocated guess (which mis-
 * classifies reused/other-deleted frags and splices foreign bytes into the PFS
 * image, breaking pkg_pfs_tool). This follows the on-disk structure "every 4 KB
 * frag, extrapolated across 32 KB blocks", the way the file was actually written.
 *
 * Correct when the package is contiguous within the cg data areas (the common
 * case for an install package written into free space, then deleted). */
static uint64_t carve_geom(CryptImage *ci, const Superblock *sb,
                           uint64_t off, uint64_t size, uint8_t *buf, FILE *out,
                           long long *skipped) {
    int64_t fsize  = sb->fsize;
    int64_t fpg    = sb->fpg;
    int64_t dblkno = sb->dblkno;            /* first data frag within each cg */
    int64_t fr = (int64_t)(off / fsize);
    uint64_t wrote = 0;
    while (wrote < size) {
        int64_t within = fr % fpg;
        if (within < dblkno) {              /* cg reserved metadata region -> skip */
            int64_t skip = dblkno - within;
            fr += skip; *skipped += skip;
            continue;
        }
        int64_t frags_in_cg = fpg - within;                 /* data frags left in cg */
        int64_t remain = (int64_t)((size - wrote + fsize - 1) / fsize);
        int64_t run = frags_in_cg < remain ? frags_in_cg : remain;
        int64_t r = fr, left = run;
        while (left > 0 && wrote < size) {
            int64_t c = left < (CARVE_CHUNK / fsize) ? left : (CARVE_CHUNK / fsize);
            int64_t nbytes = c * fsize;
            if (wrote + (uint64_t)nbytes > size) nbytes = (int64_t)(size - wrote);
            ci_read_plain(ci, r * fsize, nbytes, buf);
            fwrite(buf, 1, (size_t)nbytes, out);
            wrote += (uint64_t)nbytes; r += c; left -= c;
        }
        fr += run;
    }
    return wrote;
}

static THREAD_RET carve_worker(void *arg) {
    carve_state *st = (carve_state *)arg;
    CryptImage ci; ci_open(&ci, st->img_path, st->key, st->ivoffset, st->part_offset, st->plain);
    uint8_t *buf = (uint8_t *)malloc(CARVE_CHUNK);
    if (!buf) die("out of memory");
    cgcache cc; memset(&cc, 0, sizeof(cc)); cc.img = &ci; cc.sb = &st->sb;

    for (;;) {
        MTX_LOCK(&st->mtx);
        int j = (st->next < st->hits->n) ? st->next++ : -1;
        MTX_UNLOCK(&st->mtx);
        if (j < 0) break;

        pkg_hit *h = &st->hits->v[j];
        char outpath[8192];
        snprintf(outpath, sizeof(outpath), "%s/%s.pkg", st->outroot, h->cid);
        uint64_t wrote = 0; int err = 0; long long skipped = 0;
        /* --geom always follows the cg data-region geometry (no bitmap).
         * --defrag applies the bitmap method, but only to deleted packages
         * (first frag free); a live package (first frag allocated) is copied
         * contiguously. --geom takes precedence when both are given. */
        int use_geom   = st->geom;
        int use_defrag = !use_geom && st->defrag &&
                         frag_is_free(&cc, (int64_t)(h->offset / st->sb.fsize));
        if (!st->dry_run) {
            FILE *out = fopen(outpath, "wb");
            if (!out) err = 1;
            else {
                if (use_geom) {
                    wrote = carve_geom(&ci, &st->sb, h->offset, h->size, buf, out, &skipped);
                } else if (use_defrag) {
                    wrote = carve_defrag(&ci, &cc, &st->sb, h->offset, h->size, buf, out, &skipped);
                } else {
                    uint64_t rem = h->size;
                    FSEEK64(ci.f, (int64_t)(st->part_offset + h->offset), SEEK_SET);
                    while (rem > 0) {
                        size_t want = (size_t)(rem < CARVE_CHUNK ? rem : CARVE_CHUNK);
                        size_t got  = fread(buf, 1, want, ci.f);
                        if (got == 0) break;
                        fwrite(buf, 1, got, out);
                        wrote += got; rem -= got;
                        if (got < want) break;
                    }
                }
                fclose(out);
            }
        } else {
            wrote = h->size;
            if (use_defrag) (void)frag_is_free(&cc, (int64_t)(h->offset / st->sb.fsize));
        }

        MTX_LOCK(&st->mtx);
        st->done++;
        if (err) {
            st->errors++;
            fprintf(stderr, "  [%lld/%d] ERROR (cannot create) %s.pkg\n",
                    st->done, st->hits->n, h->cid);
        } else {
            st->files++; st->bytes += wrote;
            if (use_geom)
                printf("  [%lld/%d] %10s  %s.pkg  @0x%llx  [geom: skipped %lld frag]\n",
                       st->done, st->hits->n, human(wrote), h->cid,
                       (unsigned long long)h->offset, skipped);
            else if (use_defrag)
                printf("  [%lld/%d] %10s  %s.pkg  @0x%llx  [defrag: skipped %lld frag]\n",
                       st->done, st->hits->n, human(wrote), h->cid,
                       (unsigned long long)h->offset, skipped);
            else
                printf("  [%lld/%d] %10s  %s.pkg  @0x%llx\n", st->done, st->hits->n,
                       human(wrote), h->cid, (unsigned long long)h->offset);
            fflush(stdout);
        }
        MTX_UNLOCK(&st->mtx);
    }
    for (int i = 0; i < CG_CACHE; i++) free(cc.bm[i]);
    free(buf);
    ci_close(&ci);
    THREAD_RETURN;
}

static void cmd_scan(UFS2FS *fs, const char *img_path, const char *outroot,
                     const uint8_t *key, uint64_t ivoffset,
                     int nthreads, int dry_run, int defrag, int geom) {
    uint64_t total_bytes = (uint64_t)fs->sb.size * (uint64_t)fs->sb.fsize;
    uint64_t part_offset = fs->img->part_offset;
    if (nthreads < 1) nthreads = 1;
    printf("scanning %s partition for .pkg (CNT) packages, %d threads...\n",
           human(total_bytes), nthreads);

    hit_list hits; memset(&hits, 0, sizeof(hits)); MTX_INIT(&hits.mtx);
    uint64_t scanned = 0; mutex_t pmtx; MTX_INIT(&pmtx);

    uint64_t seg = (total_bytes / (uint64_t)nthreads) & ~((uint64_t)PKG_ALIGN - 1);
    if (seg == 0) seg = total_bytes;
    detect_arg *da = (detect_arg *)malloc(nthreads * sizeof(detect_arg));
    thread_t   *th = (thread_t *)malloc(nthreads * sizeof(thread_t));
    if (!da || !th) die("out of memory");
    int nd = 0;
    for (int i = 0; i < nthreads; i++) {
        uint64_t s = (uint64_t)i * seg;
        if (s >= total_bytes) break;
        uint64_t e = (i == nthreads - 1) ? total_bytes : (uint64_t)(i + 1) * seg;
        if (e > total_bytes) e = total_bytes;
        da[nd].img_path = img_path; da[nd].part_offset = part_offset;
        da[nd].start = s; da[nd].end = e; da[nd].total_bytes = total_bytes;
        da[nd].hits = &hits; da[nd].pmtx = &pmtx; da[nd].scanned = &scanned;
        thread_start(&th[nd], detect_worker, &da[nd]);
        nd++;
    }
    for (int i = 0; i < nd; i++) thread_join(th[i]);
    fprintf(stderr, "\r  scanned %s / %s          \n", human(total_bytes), human(total_bytes));
    free(da); free(th); MTX_DESTROY(&pmtx);

    /* sort by offset, drop any header found inside a previous package's extent
     * (guards the rare interior/cross-boundary false positive) */
    qsort(hits.v, hits.n, sizeof(pkg_hit), hit_cmp);
    int kept = 0; uint64_t last_end = 0;
    for (int i = 0; i < hits.n; i++) {
        if (hits.v[i].offset < last_end) continue;
        hits.v[kept++] = hits.v[i];
        last_end = hits.v[i].offset + hits.v[i].size;
    }
    hits.n = kept;

    if (hits.n == 0) { printf("no .pkg packages found\n"); free(hits.v); MTX_DESTROY(&hits.mtx); return; }
    uint64_t tot = 0;
    for (int i = 0; i < hits.n; i++) tot += hits.v[i].size;
    printf("found %d package(s), %s total\n", hits.n, human(tot));
    for (int i = 0; i < hits.n; i++)
        printf("  %10s  %s.pkg  @0x%llx\n", human(hits.v[i].size),
               hits.v[i].cid, (unsigned long long)hits.v[i].offset);

    /* disambiguate identical content ids so files don't clobber each other */
    for (int i = 0; i < hits.n; i++)
        for (int k = i + 1; k < hits.n; k++)
            if (strcmp(hits.v[i].cid, hits.v[k].cid) == 0) {
                char suf[24];
                snprintf(suf, sizeof(suf), "_%llx", (unsigned long long)hits.v[k].offset);
                size_t l = strlen(hits.v[k].cid);
                if (l + strlen(suf) < sizeof(hits.v[k].cid)) strcat(hits.v[k].cid, suf);
            }

    printf("extracting -> %s%s%s%s (%d threads)\n", outroot,
           dry_run ? "  (dry run)" : "", geom ? "  (geom)" : defrag ? "  (defrag)" : "",
           "", nthreads);
    if (!dry_run) mkdirs(outroot);

    carve_state st; memset(&st, 0, sizeof(st));
    st.hits = &hits; st.img_path = img_path; st.outroot = outroot;
    st.part_offset = part_offset; st.ivoffset = ivoffset; st.key = key;
    st.sb = fs->sb; st.plain = fs->img->plain; st.dry_run = dry_run;
    st.defrag = defrag; st.geom = geom;
    MTX_INIT(&st.mtx);
    int ew = nthreads > hits.n ? hits.n : nthreads;
    if (ew < 1) ew = 1;
    thread_t *et = (thread_t *)malloc(ew * sizeof(thread_t));
    if (!et) die("out of memory");
    for (int i = 0; i < ew; i++) thread_start(&et[i], carve_worker, &st);
    for (int i = 0; i < ew; i++) thread_join(et[i]);
    free(et); MTX_DESTROY(&st.mtx);

    printf("\ndone: %lld package(s) (%s), %lld errors\n",
           st.files, human(st.bytes), st.errors);
    free(hits.v); MTX_DESTROY(&hits.mtx);
}

/* ==========================================================================
 * carve: reassemble a SINGLE package at a known partition-relative offset.
 *
 * `scan` prints each package's offset (@0x...). This lets you re-carve just one
 * of them with a chosen method -- so you can test --geom vs --defrag against
 * pkg_pfs_tool/pfs5 in seconds instead of re-scanning the whole partition.
 * ======================================================================== */
static void cmd_carve(UFS2FS *fs, uint64_t off, const char *outroot,
                      int defrag, int geom) {
    uint8_t hdr[PKG_HDR_LEN];
    ci_read_plain(fs->img, (int64_t)off, PKG_HDR_LEN, hdr);
    uint64_t size; char cid[80];
    if (!pkg_validate(hdr, &size, cid, sizeof(cid)))
        die("no valid CNT package at offset 0x%llx", (unsigned long long)off);

    mkdirs(outroot);
    char outpath[8192];
    snprintf(outpath, sizeof(outpath), "%s/%s.pkg", outroot, cid);
    FILE *out = fopen(outpath, "wb");
    if (!out) die("cannot create %s", outpath);
    uint8_t *buf = (uint8_t *)malloc(CARVE_CHUNK);
    if (!buf) die("out of memory");

    long long skipped = 0; uint64_t wrote; const char *method;
    if (geom) {
        wrote = carve_geom(fs->img, &fs->sb, off, size, buf, out, &skipped);
        method = "geom";
    } else if (defrag) {
        cgcache cc; memset(&cc, 0, sizeof(cc)); cc.img = fs->img; cc.sb = &fs->sb;
        wrote = carve_defrag(fs->img, &cc, &fs->sb, off, size, buf, out, &skipped);
        for (int i = 0; i < CG_CACHE; i++) free(cc.bm[i]);
        method = "defrag";
    } else {
        uint64_t rem = size; wrote = 0;
        FSEEK64(fs->img->f, (int64_t)(fs->img->part_offset + off), SEEK_SET);
        while (rem > 0) {
            size_t want = (size_t)(rem < CARVE_CHUNK ? rem : CARVE_CHUNK);
            size_t got  = fread(buf, 1, want, fs->img->f);
            if (got == 0) break;
            fwrite(buf, 1, got, out); wrote += got; rem -= got;
            if (got < want) break;
        }
        method = "contiguous";
    }
    fclose(out); free(buf);
    printf("carved %s.pkg (%s of %s) via %s", cid, human(wrote), human(size), method);
    if (geom || defrag) printf(", skipped %lld frag", skipped);
    printf("\n  -> %s\n", outpath);
}

/* ==========================================================================
 * recover: reconstruct deleted .pkg files from surviving UFS2 inodes
 *
 * Where `scan` carves by CNT magic and (with --defrag) *guesses* block ordering
 * from the free-block bitmaps, `recover` walks the inode table for deleted
 * inodes (link count 0) whose block pointers still survive and rebuilds each
 * file from those pointers: direct + indirect blocks, addressed in 4 KB fragment
 * units, one 32 KB block per pointer. Because the indirect blocks record the
 * TRUE (possibly non-contiguous) block layout, a package fragmented around
 * cylinder-group metadata reassembles exactly -- no bitmap heuristic.
 *
 * A deleted inode's indirect blocks are metadata (encrypted on an encrypted
 * image), so pipe_extract decrypts them while resolving the block map, and the
 * .pkg data blocks are read as plaintext passthrough (decrypt=0) -- correct for
 * both encrypted and already-decrypted (--plain) images.
 *
 * A deleted inode carries no filename, so only inodes whose first data block
 * begins with the CNT magic are treated as packages, and the content_id from
 * the .pkg header names the output file.
 * ======================================================================== */
typedef struct { uint32_t ino; uint64_t size; int16_t nlink; char cid[80]; } inode_hit;

static void cmd_recover(UFS2FS *fs, const char *outroot, int64_t min_size,
                        int dry_run, int include_linked) {
    Superblock *sb = &fs->sb;
    uint64_t total_inodes = (uint64_t)sb->ncg * (uint64_t)sb->ipg;
    int inopb = sb->inopb;
    if (inopb <= 0) die("bad superblock (inopb=%d)", inopb);

    printf("recover: scanning %llu inodes for deleted .pkg (CNT) files%s...\n",
           (unsigned long long)total_inodes, include_linked ? " (incl. linked)" : "");

    inode_hit *hits = NULL; int nhits = 0, caphits = 0;
    uint8_t *iblk = (uint8_t *)malloc(sb->bsize);   /* one inode block = inopb inodes */
    uint8_t  hdr[PKG_HDR_LEN];
    if (!iblk) die("out of memory");
    int64_t  cur_base = -1;
    uint64_t scanned = 0;
    int64_t  part_frags = sb->size;                        /* fs size in frags   */
    uint64_t part_bytes = (uint64_t)sb->size * sb->fsize;  /* fs size in bytes   */

    for (uint32_t ino = ROOTINO; ino < total_inodes; ino++) {
        int64_t cg     = ino / (uint32_t)sb->ipg;
        int64_t within = ino % (uint32_t)sb->ipg;
        int64_t blk    = within / inopb;
        int64_t off_in = within % inopb;
        int64_t fsba   = sb_cgimin(sb, cg) + sb_blkstofrags(sb, blk);
        int64_t base   = sb_frag_to_byte(sb, fsba);     /* base of this inode block */
        if (base != cur_base) {                         /* new block -> read+decrypt */
            ci_read(fs->img, base, sb->bsize, iblk);    /* inode table is metadata   */
            cur_base = base;
            scanned += (uint64_t)inopb;
            if ((scanned & 0xFFFFF) < (uint64_t)inopb) {
                fprintf(stderr, "\r  scanned %llu / %llu inodes, %d pkg found ...  ",
                        (unsigned long long)scanned, (unsigned long long)total_inodes, nhits);
                fflush(stderr);
            }
        }
        Inode in;
        inode_parse(&in, ino, iblk + off_in * DINODE_SIZE);
        if (!in_isreg(&in)) continue;
        if (!include_linked && in.nlink != 0) continue; /* keep only deleted inodes */
        if ((int64_t)in.size < min_size || in.size > part_bytes) continue;
        /* guard against stale/garbage inodes: db[0] must be a valid frag address
         * (else sb_frag_to_byte overflows to a bogus, possibly negative, offset) */
        if (in.db[0] <= 0 || in.db[0] >= part_frags) continue;
        /* validate: first data block (plaintext) must start with the CNT magic */
        ci_read_plain(fs->img, sb_frag_to_byte(sb, in.db[0]), PKG_HDR_LEN, hdr);
        uint64_t psz; char cid[80];
        if (!pkg_validate(hdr, &psz, cid, sizeof(cid))) continue;
        if (nhits >= caphits) {
            caphits = caphits ? caphits * 2 : 32;
            hits = (inode_hit *)realloc(hits, caphits * sizeof(inode_hit));
            if (!hits) die("out of memory");
        }
        hits[nhits].ino = ino; hits[nhits].size = in.size; hits[nhits].nlink = in.nlink;
        snprintf(hits[nhits].cid, sizeof(hits[nhits].cid), "%s", cid);
        nhits++;
    }
    free(iblk);
    fprintf(stderr, "\r  scanned %llu / %llu inodes                             \n",
            (unsigned long long)total_inodes, (unsigned long long)total_inodes);

    if (nhits == 0) { printf("no deleted .pkg inodes found\n"); free(hits); return; }
    uint64_t tot = 0;
    for (int i = 0; i < nhits; i++) tot += hits[i].size;
    printf("found %d recoverable package(s), %s total\n", nhits, human(tot));
    for (int i = 0; i < nhits; i++)
        printf("  %10s  %s.pkg  inode %u%s\n", human(hits[i].size), hits[i].cid,
               hits[i].ino, hits[i].nlink ? "  [linked]" : "  [deleted]");

    /* disambiguate identical content ids so files don't clobber each other */
    for (int i = 0; i < nhits; i++)
        for (int k = i + 1; k < nhits; k++)
            if (strcmp(hits[i].cid, hits[k].cid) == 0) {
                char suf[24];
                snprintf(suf, sizeof(suf), "_i%u", hits[k].ino);
                size_t l = strlen(hits[k].cid);
                if (l + strlen(suf) < sizeof(hits[k].cid)) strcat(hits[k].cid, suf);
            }

    printf("reconstructing -> %s%s\n", outroot, dry_run ? "  (dry run)" : "");
    if (!dry_run) mkdirs(outroot);

    long long files = 0, errors = 0; uint64_t bytes = 0;
    for (int i = 0; i < nhits; i++) {
        Inode in; fs_inode(fs, hits[i].ino, &in);       /* re-read; resolves block map */
        char outpath[8192];
        snprintf(outpath, sizeof(outpath), "%s/%s.pkg", outroot, hits[i].cid);
        printf("  [%d/%d] %10s  %s.pkg  (inode %u)\n", i + 1, nhits,
               human(in.size), hits[i].cid, hits[i].ino);
        fflush(stdout);
        if (dry_run) { files++; bytes += in.size; continue; }
        FILE *fp = fopen(outpath, "wb");
        if (!fp) { errors++; printf("    ERROR: cannot create %s\n", outpath); continue; }
        extract_ctx ec = { fp, 0, in.size };
        /* decrypt=0: .pkg data blocks are plaintext; pipe_extract still decrypts
         * the indirect metadata blocks it walks to build the block map. */
        pipe_extract(fs, &in, 0, extract_cb_quiet, &ec);
        fclose(fp);
        files++; bytes += (uint64_t)ec.written;
    }
    printf("\ndone: %lld package(s) reconstructed (%s), %lld errors\n",
           files, human(bytes), errors);
    free(hits);
}

/* ==========================================================================
 * interactive shell
 * ======================================================================== */
static void shell_abspath(const char *cwd, const char *p, char *out, size_t outsz) {
    if (p[0] == '/') { norm_path(p, out, outsz); return; }
    char joined[4096];
    snprintf(joined, sizeof(joined), "%s/%s", cwd, p);
    norm_path(joined, out, outsz);
}

static void cmd_shell(UFS2FS *fs) {
    char cwd[4096] = "/";
    printf("ps4ufs interactive browser. commands: ls, cd, stat, cat, get <src> <dst>, pwd, find <s>, exit\n");
    char line[4096];
    for (;;) {
        printf("ps4ufs:%s> ", cwd);
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) { printf("\n"); break; }
        /* trim */
        char *s = line; while (*s == ' ' || *s == '\t') s++;
        size_t l = strlen(s); while (l && (s[l-1]=='\n'||s[l-1]=='\r'||s[l-1]==' ')) s[--l]=0;
        if (!*s) continue;

        char *argv[8]; int argc = 0;
        char *save = NULL, *tok = strtok_r(s, " ", &save);
        while (tok && argc < 8) { argv[argc++] = tok; tok = strtok_r(NULL, " ", &save); }
        const char *cmd = argv[0];

        if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) break;
        else if (strcmp(cmd, "pwd") == 0) printf("%s\n", cwd);
        else if (strcmp(cmd, "ls") == 0) {
            char t[4096];
            if (argc > 1) shell_abspath(cwd, argv[1], t, sizeof(t)); else snprintf(t, sizeof(t), "%s", cwd);
            cmd_ls(fs, t);
        }
        else if (strcmp(cmd, "cd") == 0) {
            char t[4096];
            if (argc > 1) shell_abspath(cwd, argv[1], t, sizeof(t)); else snprintf(t, sizeof(t), "/");
            Inode in;
            if (fs_resolve(fs, t, &in) != 0) { printf("not found\n"); continue; }
            if (in_islnk(&in)) {
                char tgt[4096]; fs_readlink(fs, &in, tgt, sizeof(tgt));
                if (tgt[0] == '/') snprintf(t, sizeof(t), "%s", tgt);
                else shell_abspath(cwd, tgt, t, sizeof(t));
                if (fs_resolve(fs, t, &in) != 0) { printf("not found\n"); continue; }
            }
            if (!in_isdir(&in)) printf("not a directory\n");
            else snprintf(cwd, sizeof(cwd), "%s", t[0] ? t : "/");
        }
        else if (strcmp(cmd, "stat") == 0 && argc > 1) {
            char t[4096]; shell_abspath(cwd, argv[1], t, sizeof(t)); cmd_stat(fs, t);
        }
        else if (strcmp(cmd, "cat") == 0 && argc > 1) {
            char t[4096]; shell_abspath(cwd, argv[1], t, sizeof(t)); cmd_cat(fs, t);
        }
        else if (strcmp(cmd, "get") == 0 && argc > 2) {
            char t[4096]; shell_abspath(cwd, argv[1], t, sizeof(t)); cmd_get(fs, t, argv[2]);
        }
        else if (strcmp(cmd, "find") == 0 && argc > 1) {
            cmd_find(fs, argv[1], 64);
        }
        else printf("unknown command: %s\n", cmd);
    }
}

/* ==========================================================================
 * GPT partition table
 *
 * hdd.img is a whole-disk image: the encrypted UFS2 filesystem lives inside
 * one GPT partition, so we locate that partition and read it in place rather
 * than extracting a multi-hundred-GB copy first. The GPT itself is plaintext.
 * ======================================================================== */
typedef struct { int index; uint64_t base, size; } gpt_part;

/* Parse the primary GPT into out[] (up to max). Returns entry count, 0 if the
 * image has no GPT (e.g. a bare partition dump like the old 12.img). */
static int gpt_read(FILE *f, gpt_part *out, int max) {
    uint8_t hdr[SECTOR];
    if (FSEEK64(f, SECTOR, SEEK_SET) != 0) return 0;
    if (fread(hdr, 1, SECTOR, f) != SECTOR) return 0;
    if (memcmp(hdr, "EFI PART", 8) != 0) return 0;
    uint64_t part_lba = rd_u64(hdr + 72);
    uint32_t nparts   = rd_u32(hdr + 80);
    uint32_t entsz    = rd_u32(hdr + 84);
    if (entsz < 128 || entsz > 4096 || nparts == 0 || nparts > 4096) return 0;
    uint8_t *ent = (uint8_t *)malloc(entsz);
    if (!ent) return 0;
    int n = 0;
    for (uint32_t i = 0; i < nparts && n < max; i++) {
        int64_t at = (int64_t)(part_lba * (uint64_t)SECTOR + (uint64_t)i * entsz);
        if (FSEEK64(f, at, SEEK_SET) != 0) break;
        if (fread(ent, 1, entsz, f) != entsz) break;
        int empty = 1;
        for (int k = 0; k < 16; k++) if (ent[k]) { empty = 0; break; }
        if (empty) continue;                         /* unused GPT slot */
        uint64_t first = rd_u64(ent + 32);
        uint64_t last  = rd_u64(ent + 40);
        if (last < first) continue;
        out[n].index = (int)i;
        out[n].base  = first * (uint64_t)SECTOR;
        out[n].size  = (last - first + 1) * (uint64_t)SECTOR;
        n++;
    }
    free(ent);
    return n;
}

/* Probe a partition for a UFS2 superblock using the given key + ivoffset.
 * Returns 1 if fs_magic decrypts correctly at SBLOCK_UFS2 + 1372. */
static int probe_ufs2(FILE *f, const xts_ctx *xts, uint64_t base, uint64_t ivoffset) {
    int64_t mag_off = SBLOCK_UFS2 + 1372;            /* fs_magic within superblock */
    int64_t sec     = mag_off / SECTOR;
    int64_t within  = mag_off % SECTOR;
    uint8_t buf[SECTOR];
    if (FSEEK64(f, (int64_t)base + sec * SECTOR, SEEK_SET) != 0) return 0;
    if (fread(buf, 1, SECTOR, f) != SECTOR) return 0;
    xts_decrypt_unit(xts, buf, SECTOR, ivoffset + (uint64_t)sec);
    return rd_u32(buf + (size_t)within) == UFS2_MAGIC;
}

/* Probe a partition for a PLAINTEXT (already-decrypted) UFS2 superblock: read
 * fs_magic verbatim, no XTS. Used to auto-detect an individual decrypted image
 * such as C:\hdd\user.bin so no --plain flag or keys.bin is required. */
static int probe_ufs2_plain(FILE *f, uint64_t base) {
    int64_t mag_off = SBLOCK_UFS2 + 1372;
    uint8_t buf[4];
    if (FSEEK64(f, (int64_t)base + mag_off, SEEK_SET) != 0) return 0;
    if (fread(buf, 1, 4, f) != 4) return 0;
    return rd_u32(buf) == UFS2_MAGIC;
}

#define MAX_PARTS 128

/* Auto-locate the target partition inside a whole-disk image: the largest
 * partition whose superblock decrypts as UFS2. Returns its base offset, or
 * UINT64_MAX if none found (image is not a GPT disk, or key/ivoffset wrong). */
static uint64_t gpt_find_ufs2(FILE *f, const xts_ctx *xts, uint64_t ivoffset,
                              int *out_index) {
    gpt_part parts[MAX_PARTS];
    int n = gpt_read(f, parts, MAX_PARTS);
    uint64_t best_base = (uint64_t)-1, best_size = 0;
    int best_index = -1;
    for (int i = 0; i < n; i++) {
        if (!probe_ufs2(f, xts, parts[i].base, ivoffset)) continue;
        if (parts[i].size > best_size) {
            best_size  = parts[i].size;
            best_base  = parts[i].base;
            best_index = parts[i].index;
        }
    }
    if (out_index) *out_index = best_index;
    return best_base;
}

/* Look up a GPT entry by its index; returns base offset or UINT64_MAX. */
static uint64_t gpt_base_of_index(FILE *f, int index, uint64_t *out_size) {
    gpt_part parts[MAX_PARTS];
    int n = gpt_read(f, parts, MAX_PARTS);
    for (int i = 0; i < n; i++)
        if (parts[i].index == index) {
            if (out_size) *out_size = parts[i].size;
            return parts[i].base;
        }
    return (uint64_t)-1;
}

/* `parts` command: list GPT partitions and flag which decrypt as UFS2. */
static void cmd_parts(const char *img_path, const xts_ctx *xts, uint64_t ivoffset) {
    FILE *f = fopen(img_path, "rb");
    if (!f) die("cannot open image: %s", img_path);
    gpt_part parts[MAX_PARTS];
    int n = gpt_read(f, parts, MAX_PARTS);
    if (n == 0) { printf("no GPT found in %s (bare partition image?)\n", img_path); fclose(f); return; }
    printf("GPT partitions in %s:\n", img_path);
    printf("  idx  %-16s %-14s  fs\n", "base(bytes)", "size");
    for (int i = 0; i < n; i++) {
        int ufs2 = probe_ufs2(f, xts, parts[i].base, ivoffset);
        printf("  %3d  %-16llu %-14s  %s\n", parts[i].index,
               (unsigned long long)parts[i].base, human(parts[i].size),
               ufs2 ? "UFS2" : "");
    }
    fclose(f);
}

/* ==========================================================================
 * entry point
 * ======================================================================== */
static void usage(void) {
    fprintf(stderr,
      "usage: ps4ufs [--img PATH] [--keys PATH] [--part N|--partbase BYTES]\n"
      "              [--ivoffset N] [--plain] [--no-pkg-plain] [--threads N] <cmd> ...\n"
      "\n"
      "  --img PATH      whole-disk image, bare partition, or an already-decrypted\n"
      "                  partition image (default C:\\hdd\\hdd.img)\n"
      "  --plain         image is already decrypted (no XTS, no keys.bin needed);\n"
      "                  e.g. an individual user image C:\\hdd\\user.bin. Auto-detected\n"
      "                  when the superblock reads as UFS2 verbatim.\n"
      "  --part N        use GPT partition entry N (byte offset resolved from the GPT)\n"
      "  --partbase B    raw byte offset of the partition within the image\n"
      "                  (default: auto-detect the largest UFS2 partition; 0 for a\n"
      "                   bare partition image such as the old 12.img)\n"
      "  --ivoffset N    XTS tweak base, partition-relative (default 0)\n"
      "\n"
      "commands:\n"
      "  parts\n"
      "  info\n"
      "  ls   [PATH]\n"
      "  stat PATH\n"
      "  tree [PATH] [--depth N]\n"
      "  cat  PATH\n"
      "  get  PATH OUT\n"
      "  getdir PATH OUT [--depth N] [--skip-pkg] [--max-size N] [--dry-run]\n"
      "  find NAME [--depth N]\n"
      "  scan OUT [--threads N] [--dry-run] [--defrag|--geom]  (carve raw .pkg, parallel)\n"
      "                 --defrag: reassemble via free-block bitmap\n"
      "                 --geom:   reassemble via cg data-region geometry (skip cg\n"
      "                           metadata only) -- try this if --defrag output fails\n"
      "                           pkg_pfs_tool / pfs5\n"
      "  carve OFFSET OUT [--defrag|--geom]  (re-carve one package at OFFSET, e.g.\n"
      "                 0x1a2b3000, using a chosen method -- fast A/B testing vs pfs5)\n"
      "  recover OUT [--dry-run] [--include-linked] [--min-size N]\n"
      "                 (rebuild deleted .pkg from surviving UFS2 inode block maps;\n"
      "                  handles fragmentation exactly -- preferred over scan --defrag)\n"
      "  shell\n");
    exit(2);
}

int main(int argc, char **argv) {
    build_inv_sbox();

    const char *img_path  = "C:\\hdd\\hdd.img";
    const char *keys_path = "C:\\hdd\\keys.bin";
    uint64_t ivoffset     = 0ULL;                 /* partition-relative tweak base */
    uint64_t part_offset  = (uint64_t)-1;         /* -1 => resolve from --part / auto */
    int      part_index   = -1;                   /* -1 => not given                  */
    int no_pkg_plain      = 0;
    int plain_mode        = 0;   /* 1 => image is already decrypted (no XTS/keys) */
    int nthreads          = 0;   /* 0 => auto (CPU count) */

    int i = 1;
    /* global options before subcommand */
    for (; i < argc; i++) {
        if      (strcmp(argv[i], "--img") == 0 && i+1 < argc)      img_path = argv[++i];
        else if (strcmp(argv[i], "--keys") == 0 && i+1 < argc)     keys_path = argv[++i];
        else if (strcmp(argv[i], "--ivoffset") == 0 && i+1 < argc) ivoffset = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--partbase") == 0 && i+1 < argc) part_offset = strtoull(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--part") == 0 && i+1 < argc)     part_index = atoi(argv[++i]);
        else if (strcmp(argv[i], "--no-pkg-plain") == 0)           no_pkg_plain = 1;
        else if (strcmp(argv[i], "--plain") == 0 ||
                 strcmp(argv[i], "--decrypted") == 0)              plain_mode = 1;
        else if (strcmp(argv[i], "--threads") == 0 && i+1 < argc)  nthreads = atoi(argv[++i]);
        else break;
    }
    if (i >= argc) usage();
    const char *cmd = argv[i++];

    if (nthreads <= 0) nthreads = cpu_count();
    if (nthreads > 256) nthreads = 256;
    g_nthreads = nthreads;
    if (g_nthreads > 1) pool_init(g_nthreads);   /* must precede any ci_read */

    /* Auto-detect an already-decrypted image (e.g. an individual user.bin): if
     * no partition was named and the superblock reads as UFS2 verbatim (no XTS),
     * switch to plain mode so no keys.bin is required. */
    if (!plain_mode && part_offset == (uint64_t)-1 && part_index < 0) {
        FILE *pf = fopen(img_path, "rb");
        if (pf) {
            if (probe_ufs2_plain(pf, 0)) {
                plain_mode = 1;
                fprintf(stderr, "detected already-decrypted UFS2 image (plain mode)\n");
            }
            fclose(pf);
        }
    }

    /* load key (not required in plain mode -- a decrypted image needs no key) */
    uint8_t key[32];
    memset(key, 0, sizeof(key));
    FILE *kf = fopen(keys_path, "rb");
    if (kf) {
        if (fread(key, 1, 32, kf) != 32 && !plain_mode) die("keys.bin must be 32 bytes");
        fclose(kf);
    } else if (!plain_mode) {
        die("cannot open keys: %s", keys_path);
    }

    /* crypto context also used to probe partitions before opening the fs */
    xts_ctx probe_xts;
    xts_init(&probe_xts, key);

    /* `parts` just enumerates the GPT and flags UFS2 partitions -- no fs needed */
    if (strcmp(cmd, "parts") == 0) {
        cmd_parts(img_path, &probe_xts, ivoffset);
        if (g_nthreads > 1) pool_shutdown();
        return 0;
    }

    /* Resolve the partition byte offset within the image.
     *   --partbase B : use B verbatim
     *   --part N     : look up GPT entry N
     *   otherwise    : auto-detect the largest UFS2 partition, and if the image
     *                  has no GPT (a bare partition dump) fall back to 0. */
    if (part_offset == (uint64_t)-1 && plain_mode && part_index < 0) {
        part_offset = 0;   /* individual decrypted partition image (no GPT/XTS) */
    }
    if (part_offset == (uint64_t)-1) {
        FILE *pf = fopen(img_path, "rb");
        if (!pf) die("cannot open image: %s", img_path);
        if (part_index >= 0) {
            uint64_t sz = 0;
            part_offset = gpt_base_of_index(pf, part_index, &sz);
            if (part_offset == (uint64_t)-1) die("no GPT partition with index %d in %s", part_index, img_path);
            fprintf(stderr, "using partition %d @ %llu (%s)\n",
                    part_index, (unsigned long long)part_offset, human(sz));
        } else {
            int found_idx = -1;
            part_offset = gpt_find_ufs2(pf, &probe_xts, ivoffset, &found_idx);
            if (part_offset == (uint64_t)-1) {
                part_offset = 0;   /* bare partition image, or auto-detect failed */
            } else {
                fprintf(stderr, "auto-detected UFS2 partition %d @ %llu\n",
                        found_idx, (unsigned long long)part_offset);
            }
        }
        fclose(pf);
    }

    /* Safety net: if the superblock at the resolved partition offset is already
     * plaintext UFS2, force plain mode regardless of how part_offset was set
     * (covers --partbase/--part pointing at an already-decrypted image). */
    if (!plain_mode) {
        FILE *pf = fopen(img_path, "rb");
        if (pf) {
            if (probe_ufs2_plain(pf, part_offset)) {
                plain_mode = 1;
                fprintf(stderr, "detected already-decrypted UFS2 at partition offset (plain mode)\n");
            }
            fclose(pf);
        }
    }

    CryptImage ci;
    ci_open(&ci, img_path, key, ivoffset, part_offset, plain_mode);
    UFS2FS fs;
    fs_init(&fs, &ci, !no_pkg_plain);

    if (strcmp(cmd, "info") == 0) {
        cmd_info(&fs);
    } else if (strcmp(cmd, "ls") == 0) {
        const char *path = (i < argc) ? argv[i] : "/";
        cmd_ls(&fs, path);
    } else if (strcmp(cmd, "stat") == 0) {
        if (i >= argc) usage();
        cmd_stat(&fs, argv[i]);
    } else if (strcmp(cmd, "tree") == 0) {
        const char *path = "/"; int depth = 2;
        for (; i < argc; i++) {
            if (strcmp(argv[i], "--depth") == 0 && i+1 < argc) depth = atoi(argv[++i]);
            else path = argv[i];
        }
        cmd_tree(&fs, path, depth);
    } else if (strcmp(cmd, "cat") == 0) {
        if (i >= argc) usage();
        cmd_cat(&fs, argv[i]);
    } else if (strcmp(cmd, "get") == 0) {
        if (i+1 >= argc) usage();
        cmd_get(&fs, argv[i], argv[i+1]);
    } else if (strcmp(cmd, "getdir") == 0) {
        const char *path = NULL, *out = NULL;
        int depth = -1, skip_pkg = 0, dry_run = 0;
        int64_t max_size = 0;
        for (; i < argc; i++) {
            if      (strcmp(argv[i], "--depth") == 0 && i+1 < argc)    depth = atoi(argv[++i]);
            else if (strcmp(argv[i], "--skip-pkg") == 0)               skip_pkg = 1;
            else if (strcmp(argv[i], "--max-size") == 0 && i+1 < argc) max_size = strtoll(argv[++i], NULL, 0);
            else if (strcmp(argv[i], "--dry-run") == 0)                dry_run = 1;
            else if (!path) path = argv[i];
            else if (!out)  out  = argv[i];
        }
        if (!path || !out) usage();
        cmd_getdir(&fs, path, out, depth, skip_pkg, max_size, dry_run);
    } else if (strcmp(cmd, "find") == 0) {
        const char *name = NULL; int depth = 64;
        for (; i < argc; i++) {
            if (strcmp(argv[i], "--depth") == 0 && i+1 < argc) depth = atoi(argv[++i]);
            else name = argv[i];
        }
        if (!name) usage();
        cmd_find(&fs, name, depth);
    } else if (strcmp(cmd, "scan") == 0) {
        const char *out = NULL; int dry_run = 0, defrag = 0, geom = 0, sthreads = g_nthreads;
        for (; i < argc; i++) {
            if      (strcmp(argv[i], "--threads") == 0 && i+1 < argc) sthreads = atoi(argv[++i]);
            else if (strcmp(argv[i], "--dry-run") == 0)               dry_run = 1;
            else if (strcmp(argv[i], "--defrag") == 0)                defrag = 1;
            else if (strcmp(argv[i], "--geom") == 0)                  geom = 1;
            else if (!out) out = argv[i];
        }
        if (!out) usage();
        if (sthreads < 1) sthreads = 1;
        cmd_scan(&fs, img_path, out, key, ivoffset, sthreads, dry_run, defrag, geom);
    } else if (strcmp(cmd, "carve") == 0) {
        const char *offs = NULL, *out = NULL; int defrag = 0, geom = 0;
        for (; i < argc; i++) {
            if      (strcmp(argv[i], "--defrag") == 0) defrag = 1;
            else if (strcmp(argv[i], "--geom") == 0)   geom = 1;
            else if (!offs) offs = argv[i];
            else if (!out)  out  = argv[i];
        }
        if (!offs || !out) usage();
        uint64_t off = strtoull(offs, NULL, 0);
        cmd_carve(&fs, off, out, defrag, geom);
    } else if (strcmp(cmd, "recover") == 0) {
        const char *out = NULL; int dry_run = 0, include_linked = 0;
        int64_t min_size = 0x40000;    /* .pkg minimum (matches pkg_validate) */
        for (; i < argc; i++) {
            if      (strcmp(argv[i], "--dry-run") == 0)                dry_run = 1;
            else if (strcmp(argv[i], "--include-linked") == 0)         include_linked = 1;
            else if (strcmp(argv[i], "--min-size") == 0 && i+1 < argc) min_size = strtoll(argv[++i], NULL, 0);
            else if (!out) out = argv[i];
        }
        if (!out) usage();
        cmd_recover(&fs, out, min_size, dry_run, include_linked);
    } else if (strcmp(cmd, "shell") == 0) {
        cmd_shell(&fs);
    } else {
        usage();
    }

    ci_close(&ci);
    if (g_nthreads > 1) pool_shutdown();
    return 0;
}
