/* ps4ufs_gui.c - Win32 GUI front-end for ps4ufs
 *
 * Explorer-style browser for an AES-128-XTS encrypted PS4 UFS2 image. The
 * whole filesystem/crypto core is ps4ufs.c, compiled in unchanged with
 * PS4UFS_GUI defined (which swaps die() for an error that aborts only the
 * current GUI operation, and drops the CLI main()).
 *
 *   - folder tree + sortable file list (size, type, mtime, mode, inode)
 *   - extract files / folders with progress + cancel (.pkg passthrough kept)
 *   - recursive name search, file viewer (text / hex), properties
 *   - "Scan for packages" / "Recover deleted packages" = the CLI `scan`
 *     (incl. --defrag / --geom) and `recover` (log output, cancelable)
 *   - already-decrypted images are auto-detected (no key needed)
 *   - GPT partition picker, IV offset, drag & drop of the image
 *
 * Build (MSVC x64):  build_gui.bat
 *   rc /nologo ps4ufs_gui.rc
 *   cl /nologo /O2 /W3 ps4ufs_gui.c ps4ufs_gui.res /Fe:ps4ufs_gui.exe
 *      /link /SUBSYSTEM:WINDOWS /MANIFEST:NO user32.lib gdi32.lib comctl32.lib
 *            comdlg32.lib shell32.lib ole32.lib uuid.lib
 *
 * The embedded manifest sets the process code page to UTF-8, so every narrow
 * path in the core (fopen/_mkdir) is UTF-8 and non-ASCII names just work.
 */
#define PS4UFS_GUI 1
#define _CRT_SECURE_NO_WARNINGS
#ifndef UNICODE
  #define UNICODE
  #define _UNICODE
#endif

#include "ps4ufs.c"

#include <setjmp.h>
#include <time.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <windowsx.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

/* ==========================================================================
 * ids / messages
 * ======================================================================== */
enum {
    IDC_IMG = 100, IDC_IMG_BR, IDC_KEYS, IDC_KEYS_BR, IDC_PART, IDC_IVOFF,
    IDC_PKGPLAIN, IDC_OPEN, IDC_CLOSE, IDC_UP, IDC_PATH, IDC_GO, IDC_SEARCH,
    IDC_FIND, IDC_EXTRACT, IDC_SCAN, IDC_INFO, IDC_TREE, IDC_LIST, IDC_LOG,
    IDC_PROG, IDC_CANCEL, IDC_STATUS,
    IDC_LBL_IMG, IDC_LBL_KEYS, IDC_LBL_PART, IDC_LBL_IV,

    ID_FILE_OPEN = 200, ID_FILE_CLOSE, ID_FILE_EXIT,
    ID_ACT_EXTRACT, ID_ACT_EXTRACT_CWD, ID_ACT_SCAN, ID_ACT_INFO, ID_ACT_PARTS,
    ID_ACT_REFRESH, ID_ACT_UP, ID_ACT_FIND_FOCUS, ID_ACT_CLEARLOG,
    ID_OPT_SKIPPKG, ID_OPT_SCANDRY, ID_OPT_SCANDEFRAG,
    ID_HELP_ABOUT,
    ID_CTX_OPEN, ID_CTX_VIEW, ID_CTX_EXTRACT, ID_CTX_PROPS, ID_CTX_COPY,
    ID_ACT_RECOVER, ID_OPT_SCANGEOM, ID_OPT_RECDRY
};
#define WM_APP_LOG     (WM_APP + 1)
#define WM_APP_JOBDONE (WM_APP + 2)
#define TIMER_PROG     1
#define VIEW_MAX       (512 * 1024)

/* ==========================================================================
 * globals
 * ======================================================================== */
static HINSTANCE g_inst;
static HWND g_hwnd, g_tree, g_list, g_log, g_prog, g_status, g_path, g_search;
static HWND g_part, g_imgedit, g_keysedit, g_ivedit, g_pkgchk;
static HFONT g_font, g_mono;
static HACCEL g_accel;
static int g_dpi = 96;
static int g_split = 0;          /* tree width (px)  */
static int g_logh = 0;           /* log height (px)  */
static int g_drag = 0;           /* 1 = vertical splitter, 2 = log splitter */
static wchar_t g_ini[MAX_PATH];

/* open filesystem */
static CryptImage g_ci;
static UFS2FS     g_fs;
static int        g_open;
static uint8_t    g_key[32];
static uint64_t   g_ivoff, g_partoff;
static char       g_imgpath[4096];
static char       g_cwd[4096] = "/";
static int        g_partidx = -1;
static int        g_plain;          /* image is already decrypted (no XTS, no key) */
static gpt_part   g_parts[MAX_PARTS];
static int        g_part_ufs2[MAX_PARTS];
static int        g_nparts;

/* options */
static int g_opt_skippkg, g_opt_scandry, g_opt_defrag, g_opt_geom, g_opt_recdry;

/* list rows */
typedef struct {
    char    *name;      /* display name (full path in search mode) */
    char    *path;      /* absolute fs path */
    char    *link;      /* symlink target or NULL */
    uint32_t ino;
    uint16_t mode;
    uint64_t size;
    int64_t  mtime;
    int      is_pkg;
    int      icon;
} row_t;
static row_t *g_rows;
static int    g_nrows;
static int    g_search_mode;
static int    g_sort_col = 0, g_sort_desc = 0;

/* background job */
typedef void (*job_fn)(void *arg);
typedef void (*job_done_fn)(void *arg, int failed);
static struct {
    job_fn fn; job_done_fn done; void *arg;
    int failed; char err[1024];
    DWORD t0;
} g_job;
static volatile LONG    g_busy;
static volatile LONG    g_cancel;
static volatile int64_t g_prog_done, g_prog_total;
static wchar_t          g_prog_text[512];
static int              g_marquee;

/* die() plumbing: each thread that touches the core sets t_jb */
static __declspec(thread) jmp_buf *t_jb;
static __declspec(thread) char     t_err[1024];

static void log_printf(const char *fmt, ...);

static void gui_die(const char *msg) {
    snprintf(t_err, sizeof(t_err), "%s", msg);
    if (t_jb) longjmp(*t_jb, 1);
    /* a helper thread of the core (decrypt pool / pipeline / scan worker) has
     * no recovery point -> fatal */
    wchar_t w[1100];
    MultiByteToWideChar(CP_UTF8, 0, msg, -1, w, 1024);
    MessageBoxW(g_hwnd, w, L"ps4ufs - fatal error", MB_ICONERROR);
    ExitProcess(1);
}

/* GUARD_BEGIN ... GUARD_END wraps core calls on the GUI thread. On die() the
 * code after GUARD_ERR runs with t_err holding the message. */
#define GUARD_BEGIN  { jmp_buf _jb; jmp_buf *_prev = t_jb; t_jb = &_jb; \
                       if (setjmp(_jb) == 0) {
#define GUARD_ERR        t_jb = _prev; } else { t_jb = _prev;
#define GUARD_END    } }

static int S(int v) { return MulDiv(v, g_dpi, 96); }

/* ==========================================================================
 * string helpers
 * ======================================================================== */
static void u2w(const char *s, wchar_t *out, int n) {
    if (!MultiByteToWideChar(CP_UTF8, 0, s, -1, out, n)) out[0] = 0;
}
static void w2u(const wchar_t *s, char *out, int n) {
    if (!WideCharToMultiByte(CP_UTF8, 0, s, -1, out, n, NULL, NULL)) out[0] = 0;
}
static wchar_t *u2w_dup(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = (wchar_t *)malloc((n > 0 ? n : 1) * sizeof(wchar_t));
    if (n <= 0 || !MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n)) w[0] = 0;
    return w;
}
static void get_text_u(HWND h, char *out, int n) {
    int len = GetWindowTextLengthW(h);
    wchar_t *w = (wchar_t *)malloc((len + 1) * sizeof(wchar_t));
    GetWindowTextW(h, w, len + 1);
    w2u(w, out, n);
    free(w);
}
static void set_text_u(HWND h, const char *s) {
    wchar_t *w = u2w_dup(s);
    SetWindowTextW(h, w);
    free(w);
}
static void path_join(const char *base, const char *name, char *out, size_t n) {
    if (!base[0] || (base[0] == '/' && base[1] == 0)) snprintf(out, n, "/%s", name);
    else                                              snprintf(out, n, "%s/%s", base, name);
}
static void path_parent(const char *p, char *out, size_t n) {
    snprintf(out, n, "%s", p);
    char *s = strrchr(out, '/');
    if (!s || s == out) { out[0] = '/'; out[1] = 0; }
    else *s = 0;
}
static int ends_with_ci(const char *s, const char *suf) {
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && _stricmp(s + a - b, suf) == 0;
}
/* map a UFS name onto something Windows will accept as a file name */
static void win_safe_name(const char *in, char *out, size_t n) {
    size_t o = 0;
    for (const char *p = in; *p && o + 1 < n; p++) {
        unsigned char c = (unsigned char)*p;
        out[o++] = (c < 0x20 || strchr("<>:\"\\|?*", c)) ? '_' : (char)c;
    }
    while (o > 0 && (out[o-1] == ' ' || out[o-1] == '.')) out[--o] = '_';  /* trailing dot/space */
    out[o] = 0;
    if (!o) snprintf(out, n, "_");
}
static void fmt_time(int64_t t, wchar_t *out, int n) {
    if (t <= 0) { out[0] = 0; return; }
    ULARGE_INTEGER u; u.QuadPart = (ULONGLONG)t * 10000000ULL + 116444736000000000ULL;
    FILETIME ft = { u.LowPart, u.HighPart }, lft; SYSTEMTIME st;
    FileTimeToLocalFileTime(&ft, &lft);
    FileTimeToSystemTime(&lft, &st);
    _snwprintf(out, n, L"%04u-%02u-%02u %02u:%02u:%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}
static void human_w(uint64_t v, wchar_t *out, int n) {
    u2w(human(v), out, n);
}

/* ==========================================================================
 * log window (fed from stdout/stderr of the core and from log_printf)
 * ======================================================================== */
static int g_log_linestart;   /* char index where the current log line begins */

static void log_raw_append(const wchar_t *s, int n) {
    if (n <= 0) return;
    int len = GetWindowTextLengthW(g_log);
    if (len > 8 * 1024 * 1024) {                       /* keep it bounded */
        SendMessageW(g_log, EM_SETSEL, 0, len / 2);
        SendMessageW(g_log, EM_REPLACESEL, FALSE, (LPARAM)L"");
        len = GetWindowTextLengthW(g_log);
        g_log_linestart = len;
    }
    wchar_t *tmp = (wchar_t *)malloc((n + 1) * sizeof(wchar_t));
    memcpy(tmp, s, n * sizeof(wchar_t)); tmp[n] = 0;
    SendMessageW(g_log, EM_SETSEL, len, len);
    SendMessageW(g_log, EM_REPLACESEL, FALSE, (LPARAM)tmp);
    free(tmp);
}
/* interpret \n as newline and a bare \r as "rewrite the current line" so the
 * core's progress lines update in place */
static void log_append(const wchar_t *s) {
    const wchar_t *seg = s;
    for (const wchar_t *p = s; ; p++) {
        if (*p == 0) { log_raw_append(seg, (int)(p - seg)); break; }
        if (*p == L'\n') {
            log_raw_append(seg, (int)(p - seg));
            log_raw_append(L"\r\n", 2);
            g_log_linestart = GetWindowTextLengthW(g_log);
            seg = p + 1;
        } else if (*p == L'\r') {
            log_raw_append(seg, (int)(p - seg));
            if (p[1] != L'\n') {
                int len = GetWindowTextLengthW(g_log);
                SendMessageW(g_log, EM_SETSEL, g_log_linestart, len);
                SendMessageW(g_log, EM_REPLACESEL, FALSE, (LPARAM)L"");
            }
            seg = p + 1;
        }
    }
    SendMessageW(g_log, EM_SCROLLCARET, 0, 0);
}
/* any thread: format and hand to the GUI thread */
static void log_post_u8(const char *s) {
    wchar_t *w = u2w_dup(s);
    if (!PostMessageW(g_hwnd, WM_APP_LOG, 0, (LPARAM)w)) free(w);
}
static void log_printf(const char *fmt, ...) {
    char buf[8192];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_post_u8(buf);
}

/* reader for the stdout/stderr pipe: forwards complete UTF-8 text */
static unsigned __stdcall pipe_reader(void *arg) {
    HANDLE r = (HANDLE)arg;
    char buf[8192 + 8];
    int keep = 0;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(r, buf + keep, 8192, &got, NULL) || got == 0) break;
        int n = keep + (int)got;
        /* do not split a UTF-8 sequence across posts */
        int cut = n;
        for (int k = 1; k <= 3 && n - k >= 0; k++) {
            unsigned char c = (unsigned char)buf[n - k];
            if ((c & 0xC0) == 0x80) continue;                 /* continuation */
            int need = (c >= 0xF0) ? 4 : (c >= 0xE0) ? 3 : (c >= 0xC0) ? 2 : 1;
            if (need > k) cut = n - k;
            break;
        }
        char save[4]; int rest = n - cut;
        memcpy(save, buf + cut, rest);
        buf[cut] = 0;
        if (cut) log_post_u8(buf);
        memcpy(buf, save, rest);
        keep = rest;
    }
    return 0;
}
static void redirect_stdio(void) {
    HANDLE r, w;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
    if (!CreatePipe(&r, &w, &sa, 1 << 16)) return;
    int fd = _open_osfhandle((intptr_t)w, _O_WRONLY | _O_BINARY);
    if (fd < 0) return;
    if (_fileno(stdout) < 0) freopen("NUL", "w", stdout);
    if (_fileno(stderr) < 0) freopen("NUL", "w", stderr);
    _dup2(fd, _fileno(stdout));
    _dup2(fd, _fileno(stderr));
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    SetStdHandle(STD_OUTPUT_HANDLE, w);
    SetStdHandle(STD_ERROR_HANDLE, w);
    CloseHandle((HANDLE)_beginthreadex(NULL, 0, pipe_reader, r, 0, NULL));
}

/* ==========================================================================
 * settings (ini next to the exe)
 * ======================================================================== */
static void ini_get(const wchar_t *k, const wchar_t *def, wchar_t *out, int n) {
    GetPrivateProfileStringW(L"ps4ufs", k, def, out, n, g_ini);
}
static void ini_set(const wchar_t *k, const wchar_t *v) {
    WritePrivateProfileStringW(L"ps4ufs", k, v, g_ini);
}
static int ini_int(const wchar_t *k, int def) {
    return (int)GetPrivateProfileIntW(L"ps4ufs", k, def, g_ini);
}
static void ini_set_int(const wchar_t *k, int v) {
    wchar_t b[32]; _snwprintf(b, 32, L"%d", v); ini_set(k, b);
}
static void save_settings(void) {
    wchar_t b[4096];
    GetWindowTextW(g_imgedit, b, 4096);  ini_set(L"Image", b);
    GetWindowTextW(g_keysedit, b, 4096); ini_set(L"Keys", b);
    GetWindowTextW(g_ivedit, b, 4096);   ini_set(L"IvOffset", b);
    ini_set_int(L"PkgPlain", Button_GetCheck(g_pkgchk) == BST_CHECKED);
    ini_set_int(L"SkipPkg", g_opt_skippkg);
    ini_set_int(L"ScanDryRun", g_opt_scandry);
    ini_set_int(L"ScanDefrag", g_opt_defrag);
    ini_set_int(L"ScanGeom", g_opt_geom);
    ini_set_int(L"RecoverDryRun", g_opt_recdry);
    ini_set_int(L"Split", MulDiv(g_split, 96, g_dpi));
    ini_set_int(L"LogHeight", MulDiv(g_logh, 96, g_dpi));
    ini_set_int(L"Partition", (int)SendMessageW(g_part, CB_GETCURSEL, 0, 0));
    WINDOWPLACEMENT wp = { sizeof(wp) };
    if (GetWindowPlacement(g_hwnd, &wp)) {
        RECT r = wp.rcNormalPosition;
        _snwprintf(b, 64, L"%ld %ld %ld %ld %d", r.left, r.top, r.right, r.bottom,
                   wp.showCmd == SW_SHOWMAXIMIZED);
        ini_set(L"Window", b);
    }
}

/* ==========================================================================
 * UI state
 * ======================================================================== */
static void status_set(int part, const wchar_t *fmt, ...) {
    wchar_t b[1024];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf(b, 1024, fmt, ap);
    va_end(ap);
    b[1023] = 0;
    SendMessageW(g_status, SB_SETTEXTW, part, (LPARAM)b);
}

static void update_ui(void) {
    int busy = g_busy != 0, open = g_open;
    int nav = open && !busy;
    static const int nav_ids[] = { IDC_UP, IDC_PATH, IDC_GO, IDC_SEARCH, IDC_FIND,
                                   IDC_EXTRACT, IDC_SCAN, IDC_INFO };
    for (int i = 0; i < (int)(sizeof(nav_ids)/sizeof(nav_ids[0])); i++)
        EnableWindow(GetDlgItem(g_hwnd, nav_ids[i]), nav);
    EnableWindow(g_tree, nav);
    EnableWindow(g_list, nav);
    EnableWindow(GetDlgItem(g_hwnd, IDC_OPEN), !busy);
    EnableWindow(GetDlgItem(g_hwnd, IDC_CLOSE), open && !busy);
    EnableWindow(GetDlgItem(g_hwnd, IDC_CANCEL), busy);
    static const int cfg_ids[] = { IDC_IMG, IDC_IMG_BR, IDC_KEYS, IDC_KEYS_BR,
                                   IDC_PART, IDC_IVOFF, IDC_PKGPLAIN };
    for (int i = 0; i < (int)(sizeof(cfg_ids)/sizeof(cfg_ids[0])); i++)
        EnableWindow(GetDlgItem(g_hwnd, cfg_ids[i]), !busy);

    HMENU m = GetMenu(g_hwnd);
    UINT nf = nav ? MF_ENABLED : MF_GRAYED;
    EnableMenuItem(m, ID_FILE_OPEN, busy ? MF_GRAYED : MF_ENABLED);
    EnableMenuItem(m, ID_FILE_CLOSE, nf);
    EnableMenuItem(m, ID_ACT_EXTRACT, nf);
    EnableMenuItem(m, ID_ACT_EXTRACT_CWD, nf);
    EnableMenuItem(m, ID_ACT_SCAN, nf);
    EnableMenuItem(m, ID_ACT_RECOVER, nf);
    EnableMenuItem(m, ID_ACT_INFO, nf);
    EnableMenuItem(m, ID_ACT_PARTS, busy ? MF_GRAYED : MF_ENABLED);
    EnableMenuItem(m, ID_ACT_REFRESH, nf);
    EnableMenuItem(m, ID_ACT_UP, nf);
    CheckMenuItem(m, ID_OPT_SKIPPKG, g_opt_skippkg ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(m, ID_OPT_SCANDRY, g_opt_scandry ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(m, ID_OPT_SCANDEFRAG, g_opt_defrag ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(m, ID_OPT_SCANGEOM, g_opt_geom ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(m, ID_OPT_RECDRY, g_opt_recdry ? MF_CHECKED : MF_UNCHECKED);

    if (!open) status_set(0, L"No image open");
    else {
        wchar_t sz[32]; human_w((uint64_t)g_fs.sb.size * g_fs.sb.fsize, sz, 32);
        const wchar_t *cr = g_plain ? L"  |  decrypted" : L"";
        if (g_partidx >= 0) status_set(0, L"UFS2 %s  |  GPT #%d @ %llu%s", sz, g_partidx, (unsigned long long)g_partoff, cr);
        else                status_set(0, L"UFS2 %s  |  offset %llu%s", sz, (unsigned long long)g_partoff, cr);
    }
}

static void error_box(const char *fmt, ...) {
    char b[2048];
    va_list ap; va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    wchar_t w[2048]; u2w(b, w, 2048);
    MessageBoxW(g_hwnd, w, L"ps4ufs", MB_ICONERROR);
}

/* ==========================================================================
 * background jobs
 * ======================================================================== */
static unsigned __stdcall job_thread(void *unused) {
    (void)unused;
    jmp_buf jb;
    t_jb = &jb;
    if (setjmp(jb) == 0) {
        g_job.fn(g_job.arg);
    } else {
        g_job.failed = 1;
        snprintf(g_job.err, sizeof(g_job.err), "%s", t_err);
    }
    t_jb = NULL;
    PostMessageW(g_hwnd, WM_APP_JOBDONE, 0, 0);
    return 0;
}
static void prog_label(const wchar_t *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    _vsnwprintf(g_prog_text, 511, fmt, ap);
    va_end(ap);
    g_prog_text[511] = 0;
}
static void start_job(job_fn fn, job_done_fn done, void *arg, int marquee) {
    if (g_busy) return;
    g_job.fn = fn; g_job.done = done; g_job.arg = arg;
    g_job.failed = 0; g_job.err[0] = 0; g_job.t0 = GetTickCount();
    g_cancel = 0; g_abort = 0;
    g_prog_done = 0; g_prog_total = 0;
    g_prog_text[0] = 0;
    g_busy = 1;
    g_marquee = marquee;
    LONG_PTR st = GetWindowLongPtrW(g_prog, GWL_STYLE);
    if (marquee) {
        SetWindowLongPtrW(g_prog, GWL_STYLE, st | PBS_MARQUEE);
        SendMessageW(g_prog, PBM_SETMARQUEE, TRUE, 30);
    } else {
        SetWindowLongPtrW(g_prog, GWL_STYLE, st & ~PBS_MARQUEE);
        SendMessageW(g_prog, PBM_SETRANGE32, 0, 1000);
        SendMessageW(g_prog, PBM_SETPOS, 0, 0);
    }
    update_ui();
    SetTimer(g_hwnd, TIMER_PROG, 200, NULL);
    HANDLE h = (HANDLE)_beginthreadex(NULL, 0, job_thread, NULL, 0, NULL);
    if (h) CloseHandle(h);
}
static void on_progress_timer(void) {
    if (!g_busy) return;
    double secs = (GetTickCount() - g_job.t0) / 1000.0;
    int64_t done = g_prog_done, total = g_prog_total;
    wchar_t a[32], b[32], sp[32];
    human_w((uint64_t)done, a, 32); human_w((uint64_t)total, b, 32);
    human_w(secs > 0.2 ? (uint64_t)(done / secs) : 0, sp, 32);
    if (!g_marquee && total > 0) {
        SendMessageW(g_prog, PBM_SETPOS, (WPARAM)(done * 1000 / total), 0);
        status_set(2, L"%s / %s  (%s/s)", a, b, sp);
    } else if (done > 0) {
        status_set(2, L"%s  (%s/s)", a, sp);
    } else {
        status_set(2, L"%.0fs", secs);
    }
    status_set(1, L"%s", g_prog_text);
}
static void on_job_done(void) {
    KillTimer(g_hwnd, TIMER_PROG);
    g_busy = 0;
    SendMessageW(g_prog, PBM_SETMARQUEE, FALSE, 0);
    SetWindowLongPtrW(g_prog, GWL_STYLE, GetWindowLongPtrW(g_prog, GWL_STYLE) & ~PBS_MARQUEE);
    SendMessageW(g_prog, PBM_SETRANGE32, 0, 1000);
    SendMessageW(g_prog, PBM_SETPOS, g_job.failed || g_cancel ? 0 : 1000, 0);
    double secs = (GetTickCount() - g_job.t0) / 1000.0;
    if (g_job.failed) {
        log_printf("ERROR: %s\n", g_job.err);
        status_set(1, L"Failed");
    } else if (g_cancel) {
        status_set(1, L"Canceled after %.1fs", secs);
    } else {
        status_set(1, L"Done in %.1fs", secs);
    }
    if (g_job.done) g_job.done(g_job.arg, g_job.failed);
    update_ui();
    if (g_job.failed) error_box("%s", g_job.err);
}

/* ==========================================================================
 * file list
 * ======================================================================== */
static void rows_free(row_t *rows, int n) {
    for (int i = 0; i < n; i++) { free(rows[i].name); free(rows[i].path); free(rows[i].link); }
    free(rows);
}
static void row_from_inode(row_t *r, const char *display, const char *path,
                           const char *leaf, const Inode *in) {
    memset(r, 0, sizeof(*r));
    r->name = _strdup(display);
    r->path = _strdup(path);
    r->ino = in->ino; r->mode = in->mode; r->size = in->size; r->mtime = in->mtime;
    r->icon = -1;
    if (in_isreg(in)) r->is_pkg = fs_is_plaintext_pkg(&g_fs, leaf, in);
    if (in_islnk(in)) {
        char t[4096]; fs_readlink(&g_fs, in, t, sizeof(t));
        r->link = _strdup(t);
    }
}
static int row_is_dir(const row_t *r) { return (r->mode & S_IFMT_) == S_IFDIR_; }

static int icon_for(row_t *r) {
    if (r->icon >= 0) return r->icon;
    SHFILEINFOW sfi;
    memset(&sfi, 0, sizeof(sfi));
    if (row_is_dir(r)) {
        SHGetFileInfoW(L"folder", FILE_ATTRIBUTE_DIRECTORY, &sfi, sizeof(sfi),
                       SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);
    } else {
        const char *leaf = basename_of(r->name);
        const char *dot = strrchr(leaf, '.');
        wchar_t ext[64] = L"file";
        if (dot && strlen(dot) < 32) { wchar_t e[40]; u2w(dot, e, 40); _snwprintf(ext, 64, L"x%s", e); }
        if (r->link) wcscpy(ext, L"x.lnk");
        SHGetFileInfoW(ext, FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi),
                       SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);
    }
    r->icon = sfi.iIcon;
    return r->icon;
}

static int CALLBACK row_compare(LPARAM a, LPARAM b, LPARAM unused) {
    (void)unused;
    const row_t *x = &g_rows[a], *y = &g_rows[b];
    int dx = row_is_dir(x), dy = row_is_dir(y);
    if (dx != dy) return dy - dx;                 /* folders first, always */
    int c = 0;
    switch (g_sort_col) {
    case 1: c = x->size < y->size ? -1 : x->size > y->size; break;
    case 2: c = (x->is_pkg - y->is_pkg); if (!c) c = (x->link != NULL) - (y->link != NULL); break;
    case 3: c = x->mtime < y->mtime ? -1 : x->mtime > y->mtime; break;
    case 4: c = (int)x->mode - (int)y->mode; break;
    case 5: c = x->ino < y->ino ? -1 : x->ino > y->ino; break;
    }
    if (!c) c = _stricmp(x->name, y->name);
    return g_sort_desc ? -c : c;
}
static void list_sort(void) {
    ListView_SortItems(g_list, row_compare, 0);
    HWND hdr = ListView_GetHeader(g_list);
    int n = Header_GetItemCount(hdr);
    for (int i = 0; i < n; i++) {
        HDITEMW hi = { HDI_FORMAT };
        Header_GetItem(hdr, i, &hi);
        hi.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (i == g_sort_col) hi.fmt |= g_sort_desc ? HDF_SORTDOWN : HDF_SORTUP;
        Header_SetItem(hdr, i, &hi);
    }
}

/* replace list content with rows (takes ownership) */
static void list_set_rows(row_t *rows, int n) {
    SendMessageW(g_list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_list);
    rows_free(g_rows, g_nrows);
    g_rows = rows; g_nrows = n;
    for (int i = 0; i < n; i++) {
        LVITEMW it;
        memset(&it, 0, sizeof(it));
        it.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        it.iItem = i;
        it.pszText = LPSTR_TEXTCALLBACKW;
        it.iImage = I_IMAGECALLBACK;
        it.lParam = i;
        ListView_InsertItem(g_list, &it);
    }
    list_sort();
    SendMessageW(g_list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_list, NULL, TRUE);
}

static void on_list_dispinfo(NMLVDISPINFOW *di) {
    if ((int)di->item.lParam < 0 || (int)di->item.lParam >= g_nrows) return;
    row_t *r = &g_rows[di->item.lParam];
    if (di->item.mask & LVIF_IMAGE) di->item.iImage = icon_for(r);
    if (!(di->item.mask & LVIF_TEXT)) return;
    wchar_t *o = di->item.pszText; int n = di->item.cchTextMax;
    if (n <= 0) return;
    o[0] = 0;
    switch (di->item.iSubItem) {
    case 0: u2w(r->name, o, n); break;
    case 1: if (!row_is_dir(r)) human_w(r->size, o, n); break;
    case 2:
        if (row_is_dir(r)) wcsncpy(o, L"Folder", n);
        else if (r->link) { wchar_t t[1024]; u2w(r->link, t, 1024); _snwprintf(o, n, L"Link \x2192 %s", t); }
        else if (r->is_pkg) wcsncpy(o, L"PKG (plaintext)", n);
        else {
            const char *dot = strrchr(basename_of(r->name), '.');
            if (dot && dot[1]) { wchar_t e[32]; u2w(dot + 1, e, 32); _snwprintf(o, n, L"%s file", _wcsupr(e)); }
            else wcsncpy(o, L"File", n);
        }
        break;
    case 3: fmt_time(r->mtime, o, n); break;
    case 4: { wchar_t m[16]; u2w(mode_str(r->mode), m, 16); _snwprintf(o, n, L"%s  %04o", m, r->mode & 07777); } break;
    case 5: _snwprintf(o, n, L"%u", r->ino); break;
    }
    o[n - 1] = 0;
}

typedef struct { char name[256]; uint32_t ino; uint8_t dtype; } dent;
typedef struct { dent *v; int n, cap; } dent_list;
static int dent_cb(const char *name, uint32_t ino, uint8_t dtype, void *ud) {
    dent_list *l = (dent_list *)ud;
    if (!strcmp(name, ".") || !strcmp(name, "..")) return 0;
    if (l->n >= l->cap) {
        l->cap = l->cap ? l->cap * 2 : 64;
        l->v = (dent *)realloc(l->v, l->cap * sizeof(dent));
        if (!l->v) die("out of memory");
    }
    snprintf(l->v[l->n].name, 256, "%s", name);
    l->v[l->n].ino = ino; l->v[l->n].dtype = dtype;
    l->n++;
    return 0;
}
static int dent_cmp(const void *a, const void *b) {
    return _stricmp(((const dent *)a)->name, ((const dent *)b)->name);
}

/* resolve path; follows a final symlink (like `cd`). out_path gets the real path. */
static int resolve_follow(const char *path, Inode *in, char *out_path, size_t n) {
    char cur[4096]; norm_path(path, cur, sizeof(cur));
    for (int hop = 0; hop < 16; hop++) {
        if (fs_resolve(&g_fs, cur, in) != 0) return -1;
        if (!in_islnk(in)) { snprintf(out_path, n, "%s", cur); return 0; }
        char tgt[4096], par[4096], j[8192];
        fs_readlink(&g_fs, in, tgt, sizeof(tgt));
        if (tgt[0] == '/') snprintf(j, sizeof(j), "%s", tgt);
        else { path_parent(cur, par, sizeof(par)); snprintf(j, sizeof(j), "%s/%s", par, tgt); }
        norm_path(j, cur, sizeof(cur));
    }
    return -1;
}

static void navigate(const char *path) {
    if (!g_open || g_busy) return;
    HCURSOR old = SetCursor(LoadCursor(NULL, IDC_WAIT));
    GUARD_BEGIN
        Inode dir; char real[4096];
        if (resolve_follow(path, &dir, real, sizeof(real)) != 0) {
            error_box("Path not found:\n%s", path);
        } else if (!in_isdir(&dir)) {
            error_box("Not a folder:\n%s", path);
        } else {
            dent_list dl = {0};
            fs_listdir(&g_fs, &dir, dent_cb, &dl);
            row_t *rows = (row_t *)calloc(dl.n ? dl.n : 1, sizeof(row_t));
            for (int i = 0; i < dl.n; i++) {
                Inode ci; char full[4096];
                fs_inode(&g_fs, dl.v[i].ino, &ci);
                path_join(real, dl.v[i].name, full, sizeof(full));
                row_from_inode(&rows[i], dl.v[i].name, full, dl.v[i].name, &ci);
            }
            free(dl.v);
            snprintf(g_cwd, sizeof(g_cwd), "%s", real);
            set_text_u(g_path, g_cwd);
            g_search_mode = 0;
            list_set_rows(rows, dl.n);
            uint64_t tot = 0; int nd = 0;
            for (int i = 0; i < dl.n; i++) { if (row_is_dir(&rows[i])) nd++; else tot += rows[i].size; }
            wchar_t t[32]; human_w(tot, t, 32);
            status_set(1, L"%d items (%d folders), %s", dl.n, nd, t);
        }
    GUARD_ERR
        error_box("%s", t_err);
    GUARD_END
    SetCursor(old);
}
static void refresh(void) { navigate(g_cwd); }
static void go_up(void) {
    if (g_search_mode) { navigate(g_cwd); return; }
    char p[4096]; path_parent(g_cwd, p, sizeof(p)); navigate(p);
}

/* ==========================================================================
 * folder tree (lazy)
 * ======================================================================== */
typedef struct { char *path; int loaded; } tnode;

static HTREEITEM tree_add(HTREEITEM parent, const char *label, const char *path) {
    tnode *tn = (tnode *)calloc(1, sizeof(tnode));
    tn->path = _strdup(path);
    wchar_t *w = u2w_dup(label);
    SHFILEINFOW sfi; memset(&sfi, 0, sizeof(sfi));
    SHGetFileInfoW(L"folder", FILE_ATTRIBUTE_DIRECTORY, &sfi, sizeof(sfi),
                   SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);
    int ic = sfi.iIcon;
    SHGetFileInfoW(L"folder", FILE_ATTRIBUTE_DIRECTORY, &sfi, sizeof(sfi),
                   SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_OPENICON | SHGFI_USEFILEATTRIBUTES);
    TVINSERTSTRUCTW ins;
    memset(&ins, 0, sizeof(ins));
    ins.hParent = parent; ins.hInsertAfter = TVI_LAST;
    ins.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_CHILDREN | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
    ins.item.pszText = w; ins.item.lParam = (LPARAM)tn; ins.item.cChildren = 1;
    ins.item.iImage = ic; ins.item.iSelectedImage = sfi.iIcon;
    HTREEITEM h = TreeView_InsertItem(g_tree, &ins);
    free(w);
    return h;
}
static void tree_load(HTREEITEM item) {
    TVITEMW ti = { TVIF_PARAM }; ti.hItem = item;
    TreeView_GetItem(g_tree, &ti);
    tnode *tn = (tnode *)ti.lParam;
    if (!tn || tn->loaded || !g_open) return;
    tn->loaded = 1;
    int added = 0;
    GUARD_BEGIN
        Inode dir;
        if (fs_resolve(&g_fs, tn->path, &dir) == 0 && in_isdir(&dir)) {
            dent_list dl = {0};
            fs_listdir(&g_fs, &dir, dent_cb, &dl);
            qsort(dl.v, dl.n, sizeof(dent), dent_cmp);
            for (int i = 0; i < dl.n; i++) {
                int isdir = dl.v[i].dtype == 4;                /* DT_DIR */
                if (dl.v[i].dtype == 0) {                      /* DT_UNKNOWN */
                    Inode ci; fs_inode(&g_fs, dl.v[i].ino, &ci); isdir = in_isdir(&ci);
                }
                if (!isdir) continue;
                char full[4096]; path_join(tn->path, dl.v[i].name, full, sizeof(full));
                tree_add(item, dl.v[i].name, full);
                added++;
            }
            free(dl.v);
        }
    GUARD_ERR
        log_printf("tree: %s\n", t_err);
    GUARD_END
    if (!added) {
        TVITEMW c = { TVIF_CHILDREN }; c.hItem = item; c.cChildren = 0;
        TreeView_SetItem(g_tree, &c);
    }
}
static void tree_reset(void) {
    TreeView_DeleteAllItems(g_tree);
    if (!g_open) return;
    HTREEITEM root = tree_add(TVI_ROOT, "/", "/");
    tree_load(root);
    TreeView_Expand(g_tree, root, TVE_EXPAND);
}
/* select the tree node matching g_cwd if it is already loaded (no reload) */
static int g_tree_syncing;
static void tree_sync(void) {
    HTREEITEM it = TreeView_GetRoot(g_tree);
    if (!it) return;
    char want[4096]; snprintf(want, sizeof(want), "%s", g_cwd);
    for (;;) {
        TVITEMW ti = { TVIF_PARAM }; ti.hItem = it; TreeView_GetItem(g_tree, &ti);
        tnode *tn = (tnode *)ti.lParam;
        if (!strcmp(tn->path, want)) break;
        size_t l = strlen(tn->path);
        int is_root = !strcmp(tn->path, "/");
        if (!is_root && (strncmp(want, tn->path, l) != 0 || want[l] != '/')) return;
        tree_load(it);
        TreeView_Expand(g_tree, it, TVE_EXPAND);
        HTREEITEM c = TreeView_GetChild(g_tree, it);
        HTREEITEM found = NULL;
        for (; c; c = TreeView_GetNextSibling(g_tree, c)) {
            TVITEMW ci = { TVIF_PARAM }; ci.hItem = c; TreeView_GetItem(g_tree, &ci);
            const char *p = ((tnode *)ci.lParam)->path;
            size_t pl = strlen(p);
            if (!strncmp(want, p, pl) && (want[pl] == 0 || want[pl] == '/')) { found = c; break; }
        }
        if (!found) return;
        it = found;
    }
    g_tree_syncing = 1;
    TreeView_SelectItem(g_tree, it);
    TreeView_EnsureVisible(g_tree, it);
    g_tree_syncing = 0;
}

/* ==========================================================================
 * open / close image
 * ======================================================================== */
static void close_image(void) {
    if (g_ci.f) fclose(g_ci.f);
    free(g_fs.zero_ind);
    for (int i = 0; i < IND_CACHE; i++) free(g_fs.ic_data[i]);
    memset(&g_ci, 0, sizeof(g_ci));
    memset(&g_fs, 0, sizeof(g_fs));
    g_open = 0;
    list_set_rows(NULL, 0);
    TreeView_DeleteAllItems(g_tree);
    SetWindowTextW(g_path, L"");
}

static void fill_part_combo(int keep_sel) {
    int sel = keep_sel;
    SendMessageW(g_part, CB_RESETCONTENT, 0, 0);
    SendMessageW(g_part, CB_ADDSTRING, 0, (LPARAM)L"Auto-detect (largest UFS2)");
    SendMessageW(g_part, CB_ADDSTRING, 0, (LPARAM)L"Bare partition image (offset 0)");
    for (int i = 0; i < g_nparts; i++) {
        wchar_t b[256], sz[32];
        human_w(g_parts[i].size, sz, 32);
        _snwprintf(b, 256, L"#%d  @ %llu  (%s)%s", g_parts[i].index,
                   (unsigned long long)g_parts[i].base, sz,
                   g_part_ufs2[i] == 1 ? L"  UFS2" : g_part_ufs2[i] == 2 ? L"  UFS2 (decrypted)" : L"");
        SendMessageW(g_part, CB_ADDSTRING, 0, (LPARAM)b);
    }
    if (sel < 0 || sel >= 2 + g_nparts) sel = 0;
    SendMessageW(g_part, CB_SETCURSEL, sel, 0);
}

/* returns 1 = key loaded, 0 = missing/invalid (message shown unless quiet) */
static int load_key(const char *path, int quiet) {
    memset(g_key, 0, sizeof(g_key));
    FILE *kf = fopen(path, "rb");
    if (!kf) { if (!quiet) error_box("Cannot open key file:\n%s", path); return 0; }
    size_t n = fread(g_key, 1, 32, kf);
    fclose(kf);
    if (n != 32) { if (!quiet) error_box("Key file must be 32 bytes (AES-128-XTS data+tweak key):\n%s", path); return 0; }
    return 1;
}

/* read the GPT and probe partitions (refreshes the combo) */
static int scan_parts(const char *img, int keep_sel) {
    FILE *f = fopen(img, "rb");
    if (!f) { error_box("Cannot open image:\n%s", img); return 0; }
    xts_ctx x; xts_init(&x, g_key);
    uint64_t iv = g_ivoff;
    g_nparts = gpt_read(f, g_parts, MAX_PARTS);
    for (int i = 0; i < g_nparts; i++)
        g_part_ufs2[i] = probe_ufs2(f, &x, g_parts[i].base, iv) ? 1 :
                         probe_ufs2_plain(f, g_parts[i].base) ? 2 : 0;
    fclose(f);
    fill_part_combo(keep_sel);
    return 1;
}

static void read_config(char *img, char *keys, size_t n) {
    get_text_u(g_imgedit, img, (int)n);
    get_text_u(g_keysedit, keys, (int)n);
    char iv[64]; get_text_u(g_ivedit, iv, sizeof(iv));
    g_ivoff = strtoull(iv, NULL, 0);
}

static void open_image(void) {
    if (g_busy) return;
    char img[4096], keys[4096];
    read_config(img, keys, sizeof(img));
    if (!img[0]) { error_box("Choose an image file first."); return; }
    save_settings();
    if (g_open) close_image();
    int have_key = load_key(keys, 1);

    int sel = (int)SendMessageW(g_part, CB_GETCURSEL, 0, 0);
    /* re-reading the GPT of a different image would make the old index meaningless */
    int same_img = !strcmp(img, g_imgpath);
    if (!scan_parts(img, same_img ? sel : (sel <= 1 ? sel : 0))) { update_ui(); return; }
    sel = (int)SendMessageW(g_part, CB_GETCURSEL, 0, 0);

    HCURSOR old = SetCursor(LoadCursor(NULL, IDC_WAIT));
    GUARD_BEGIN
        g_partidx = -1;
        g_plain = 0;
        FILE *pf = fopen(img, "rb");
        if (!pf) die("cannot open image: %s", img);
        if (sel == 1) g_partoff = 0;
        else if (sel >= 2) { g_partoff = g_parts[sel - 2].base; g_partidx = g_parts[sel - 2].index; }
        else if (probe_ufs2_plain(pf, 0)) {
            g_partoff = 0; g_plain = 1;        /* an individual, already-decrypted image */
        } else {
            xts_ctx x; xts_init(&x, g_key);
            int idx = -1;
            uint64_t b = gpt_find_ufs2(pf, &x, g_ivoff, &idx);
            if (b == (uint64_t)-1) g_partoff = 0; else { g_partoff = b; g_partidx = idx; }
        }
        /* like the CLI: a plaintext superblock at the chosen offset => plain mode */
        if (!g_plain && probe_ufs2_plain(pf, g_partoff)) g_plain = 1;
        fclose(pf);
        if (!g_plain && !have_key) {
            die("this image is encrypted and needs a 32-byte AES-XTS key file:\n%s", keys);
        }
        ci_open(&g_ci, img, g_key, g_ivoff, g_partoff, g_plain);
        fs_init(&g_fs, &g_ci, Button_GetCheck(g_pkgchk) == BST_CHECKED);
        g_open = 1;
        snprintf(g_imgpath, sizeof(g_imgpath), "%s", img);
        log_printf("opened %s  (%s @ %llu, %s, ivoffset %llu, bsize %d, fsize %d, %s)\n", img,
                   g_partidx >= 0 ? "GPT partition" : "partition offset",
                   (unsigned long long)g_partoff,
                   g_plain ? "already decrypted" : "AES-128-XTS", (unsigned long long)g_ivoff,
                   g_fs.sb.bsize, g_fs.sb.fsize,
                   human((uint64_t)g_fs.sb.size * g_fs.sb.fsize));
    GUARD_ERR
        if (g_ci.f) fclose(g_ci.f);
        memset(&g_ci, 0, sizeof(g_ci));
        free(g_fs.zero_ind);
        memset(&g_fs, 0, sizeof(g_fs));
        g_open = 0;
        error_box("Could not open the filesystem:\n%s\n\n"
                  "Check the key file, the partition selection and the IV offset.", t_err);
    GUARD_END
    SetCursor(old);
    update_ui();
    if (g_open) {
        tree_reset();
        navigate("/");
        tree_sync();
    }
}

/* ==========================================================================
 * dialogs
 * ======================================================================== */
static int pick_folder(const wchar_t *title, char *out, int n) {
    IFileOpenDialog *dlg = NULL;
    int ok = 0;
    if (FAILED(CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER,
                                &IID_IFileOpenDialog, (void **)&dlg))) return 0;
    DWORD opts;
    dlg->lpVtbl->GetOptions(dlg, &opts);
    dlg->lpVtbl->SetOptions(dlg, opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    dlg->lpVtbl->SetTitle(dlg, title);
    wchar_t last[4096];
    ini_get(L"LastOut", L"", last, 4096);
    if (last[0]) {
        IShellItem *si = NULL;
        if (SUCCEEDED(SHCreateItemFromParsingName(last, NULL, &IID_IShellItem, (void **)&si))) {
            dlg->lpVtbl->SetFolder(dlg, si);
            si->lpVtbl->Release(si);
        }
    }
    if (SUCCEEDED(dlg->lpVtbl->Show(dlg, g_hwnd))) {
        IShellItem *si = NULL;
        if (SUCCEEDED(dlg->lpVtbl->GetResult(dlg, &si))) {
            wchar_t *p = NULL;
            if (SUCCEEDED(si->lpVtbl->GetDisplayName(si, SIGDN_FILESYSPATH, &p))) {
                w2u(p, out, n);
                ini_set(L"LastOut", p);
                CoTaskMemFree(p);
                ok = 1;
            }
            si->lpVtbl->Release(si);
        }
    }
    dlg->lpVtbl->Release(dlg);
    return ok;
}
static void browse_file(HWND edit, const wchar_t *title, const wchar_t *filter) {
    wchar_t file[4096];
    GetWindowTextW(edit, file, 4096);
    OPENFILENAMEW of;
    memset(&of, 0, sizeof(of));
    of.lStructSize = sizeof(of); of.hwndOwner = g_hwnd;
    of.lpstrFilter = filter; of.lpstrFile = file; of.nMaxFile = 4096;
    of.lpstrTitle = title;
    of.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&of)) SetWindowTextW(edit, file);
}

/* ==========================================================================
 * extraction job
 * ======================================================================== */
typedef struct {
    char **src; int nsrc;          /* absolute fs paths */
    char   outdir[4096];
    int    skip_pkg;
    long long files, dirs, links, skipped, errors;
    int64_t bytes;
} xjob;

typedef struct { FILE *fp; int werr; } xsink;
static int xsink_cb(const uint8_t *buf, int64_t len, void *ud) {
    xsink *s = (xsink *)ud;
    if (fwrite(buf, 1, (size_t)len, s->fp) != (size_t)len) { s->werr = 1; return 1; }
    g_prog_done += len;
    return g_cancel ? 1 : 0;
}
static void set_mtime(FILE *fp, int64_t mtime, int64_t atime) {
    if (mtime <= 0) return;
    HANDLE h = (HANDLE)_get_osfhandle(_fileno(fp));
    ULARGE_INTEGER m, a;
    m.QuadPart = (ULONGLONG)mtime * 10000000ULL + 116444736000000000ULL;
    a.QuadPart = (ULONGLONG)(atime > 0 ? atime : mtime) * 10000000ULL + 116444736000000000ULL;
    FILETIME fm = { m.LowPart, m.HighPart }, fa = { a.LowPart, a.HighPart };
    fflush(fp);
    SetFileTime(h, NULL, &fa, &fm);
}

static int is_pkg_name(const char *n) { return ends_with_ci(n, ".pkg"); }

/* pass 1: total bytes to copy (for the progress bar) */
static void x_count(xjob *j, const Inode *in, const char *name, int depth) {
    if (g_cancel || depth > 128) return;
    if (in_isreg(in)) {
        if (!(j->skip_pkg && is_pkg_name(name))) g_prog_total += (int64_t)in->size;
    } else if (in_isdir(in)) {
        dent_list dl = {0};
        fs_listdir(&g_fs, in, dent_cb, &dl);
        for (int i = 0; i < dl.n && !g_cancel; i++) {
            if (dl.v[i].dtype != 0 && dl.v[i].dtype != 4 && dl.v[i].dtype != 8) continue; /* links etc: 0 bytes */
            Inode c; fs_inode(&g_fs, dl.v[i].ino, &c);
            x_count(j, &c, dl.v[i].name, depth + 1);
        }
        free(dl.v);
    }
}

static void x_file(xjob *j, const Inode *in, const char *name, const char *fspath, const char *out) {
    if (j->skip_pkg && is_pkg_name(name)) {
        j->skipped++;
        log_printf("  skip (pkg)  %s\n", fspath);
        return;
    }
    int plain = fs_is_plaintext_pkg(&g_fs, name, in);
    FILE *fp = fopen(out, "wb");
    if (!fp) { j->errors++; log_printf("  ERROR cannot create %s\n", out); return; }
    wchar_t wn[512]; u2w(name, wn, 512);
    prog_label(L"Extracting %s", wn);
    xsink s = { fp, 0 };
    pipe_extract(&g_fs, in, !plain, xsink_cb, &s);
    set_mtime(fp, in->mtime, in->atime);
    fclose(fp);
    if (s.werr) { j->errors++; log_printf("  ERROR writing %s (disk full?)\n", out); g_cancel = 1; return; }
    if (g_cancel) { remove(out); return; }
    j->files++; j->bytes += (int64_t)in->size;
    log_printf("  %10s  %s%s\n", human(in->size), fspath, plain ? "  [plaintext pkg]" : "");
}

static void x_walk(xjob *j, const Inode *in, const char *name, const char *fspath,
                   const char *outparent, int depth) {
    if (g_cancel) return;
    char safe[512], out[8192];
    win_safe_name(name, safe, sizeof(safe));
    snprintf(out, sizeof(out), "%s\\%s", outparent, safe);
    if (in_isreg(in)) {
        x_file(j, in, name, fspath, out);
    } else if (in_isdir(in)) {
        if (depth > 128) return;
        mkdirs(out);
        j->dirs++;
        dent_list dl = {0};
        fs_listdir(&g_fs, in, dent_cb, &dl);
        for (int i = 0; i < dl.n && !g_cancel; i++) {
            Inode c; char cp[4096];
            fs_inode(&g_fs, dl.v[i].ino, &c);
            path_join(fspath, dl.v[i].name, cp, sizeof(cp));
            x_walk(j, &c, dl.v[i].name, cp, out, depth + 1);
        }
        free(dl.v);
    } else if (in_islnk(in)) {
        char t[4096], lf[8300];
        fs_readlink(&g_fs, in, t, sizeof(t));
        snprintf(lf, sizeof(lf), "%s.symlink", out);
        FILE *f = fopen(lf, "w");
        if (f) { fprintf(f, "%s\n", t); fclose(f); j->links++; }
        else j->errors++;
        log_printf("  link        %s -> %s\n", fspath, t);
    }
}

static void xjob_run(void *arg) {
    xjob *j = (xjob *)arg;
    prog_label(L"Counting...");
    for (int i = 0; i < j->nsrc && !g_cancel; i++) {
        Inode in;
        if (fs_resolve(&g_fs, j->src[i], &in) != 0) continue;
        const char *nm = basename_of(j->src[i]);
        x_count(j, &in, nm[0] ? nm : "root", 0);
    }
    log_printf("extracting %d item(s) -> %s  (%s)\n", j->nsrc, j->outdir, human((uint64_t)g_prog_total));
    mkdirs(j->outdir);
    for (int i = 0; i < j->nsrc && !g_cancel; i++) {
        Inode in;
        if (fs_resolve(&g_fs, j->src[i], &in) != 0) {
            j->errors++; log_printf("  ERROR not found: %s\n", j->src[i]); continue;
        }
        const char *nm = basename_of(j->src[i]);
        x_walk(j, &in, nm[0] ? nm : "root", j->src[i], j->outdir, 0);
    }
}
static void xjob_done(void *arg, int failed) {
    xjob *j = (xjob *)arg;
    log_printf("%s: %lld files (%s), %lld folders, %lld symlinks, %lld skipped, %lld errors\n",
               failed ? "failed" : g_cancel ? "canceled" : "done",
               j->files, human((uint64_t)j->bytes), j->dirs, j->links, j->skipped, j->errors);
    for (int i = 0; i < j->nsrc; i++) free(j->src[i]);
    free(j->src);
    free(j);
}
static void extract_paths(char **src, int n) {
    if (n <= 0) { for (int i = 0; i < n; i++) free(src[i]); free(src); return; }
    xjob *j = (xjob *)calloc(1, sizeof(xjob));
    j->src = src; j->nsrc = n; j->skip_pkg = g_opt_skippkg;
    wchar_t title[128];
    _snwprintf(title, 128, L"Extract %d item(s) to folder", n);
    if (!pick_folder(title, j->outdir, sizeof(j->outdir))) { xjob_done(j, 0); return; }
    start_job(xjob_run, xjob_done, j, 0);
}
static void extract_selected(void) {
    int cnt = ListView_GetSelectedCount(g_list);
    if (cnt <= 0) { error_box("Select one or more files or folders in the list first\n"
                              "(or use Actions > Extract current folder)."); return; }
    char **src = (char **)calloc(cnt, sizeof(char *));
    int n = 0, it = -1;
    while ((it = ListView_GetNextItem(g_list, it, LVNI_SELECTED)) >= 0 && n < cnt) {
        LVITEMW li = { LVIF_PARAM }; li.iItem = it; ListView_GetItem(g_list, &li);
        src[n++] = _strdup(g_rows[li.lParam].path);
    }
    extract_paths(src, n);
}
static void extract_cwd(void) {
    char **src = (char **)calloc(1, sizeof(char *));
    src[0] = _strdup(g_cwd);
    extract_paths(src, 1);
}

/* ==========================================================================
 * find job
 * ======================================================================== */
typedef struct {
    char base[4096], needle[256];
    row_t *rows; int n, cap;
    long long visited;
} fjob;
static void f_walk(fjob *f, const char *path, const Inode *dir, int depth) {
    if (g_cancel || depth > 64) return;
    dent_list dl = {0};
    fs_listdir(&g_fs, dir, dent_cb, &dl);
    for (int i = 0; i < dl.n && !g_cancel; i++) {
        char full[4096]; path_join(path, dl.v[i].name, full, sizeof(full));
        char low[256]; size_t k;
        for (k = 0; dl.v[i].name[k] && k < 255; k++) low[k] = (char)tolower((unsigned char)dl.v[i].name[k]);
        low[k] = 0;
        f->visited++;
        g_prog_done = f->visited;
        int hit = strstr(low, f->needle) != NULL;
        int isdir = dl.v[i].dtype == 4;
        Inode c;
        if (hit || isdir || dl.v[i].dtype == 0) {
            fs_inode(&g_fs, dl.v[i].ino, &c);
            isdir = in_isdir(&c);
        }
        if (hit) {
            if (f->n >= f->cap) {
                f->cap = f->cap ? f->cap * 2 : 64;
                f->rows = (row_t *)realloc(f->rows, f->cap * sizeof(row_t));
                if (!f->rows) die("out of memory");
            }
            row_from_inode(&f->rows[f->n++], full, full, dl.v[i].name, &c);
            if (f->n % 32 == 0) prog_label(L"Searching... %d match(es)", f->n);
        }
        if (isdir) {
            if (!hit) { /* c already loaded above */ }
            f_walk(f, full, &c, depth + 1);
        }
    }
    free(dl.v);
}
static void fjob_run(void *arg) {
    fjob *f = (fjob *)arg;
    prog_label(L"Searching...");
    Inode root;
    if (fs_resolve(&g_fs, f->base, &root) != 0) die("path not found: %s", f->base);
    f_walk(f, strcmp(f->base, "/") ? f->base : "", &root, 0);
}
static void fjob_done(void *arg, int failed) {
    fjob *f = (fjob *)arg;
    if (!failed) {
        list_set_rows(f->rows, f->n);
        f->rows = NULL;
        g_search_mode = 1;
        wchar_t nd[256], bs[1024]; u2w(f->needle, nd, 256); u2w(f->base, bs, 1024);
        status_set(1, L"%d match(es) for \"%s\" under %s%s", f->n, nd, bs, g_cancel ? L" (canceled)" : L"");
        log_printf("find \"%s\" under %s: %d match(es), %lld entries scanned\n",
                   f->needle, f->base, f->n, f->visited);
        wchar_t t[1200]; _snwprintf(t, 1200, L"Search: \"%s\" in %s", nd, bs);
        SetWindowTextW(g_path, t);
    } else rows_free(f->rows, f->n);
    free(f);
}
static void do_find(void) {
    char q[256]; get_text_u(g_search, q, sizeof(q));
    if (!q[0]) { SetFocus(g_search); return; }
    fjob *f = (fjob *)calloc(1, sizeof(fjob));
    snprintf(f->base, sizeof(f->base), "%s", g_cwd);
    size_t k;
    for (k = 0; q[k] && k < 255; k++) f->needle[k] = (char)tolower((unsigned char)q[k]);
    f->needle[k] = 0;
    start_job(fjob_run, fjob_done, f, 1);
}

/* ==========================================================================
 * scan job (the CLI `scan`, output goes to the log)
 * ======================================================================== */
typedef struct { char out[4096]; int dry, defrag, geom; } sjob;
static void sjob_run(void *arg) {
    sjob *s = (sjob *)arg;
    prog_label(L"Scanning partition for .pkg packages...");
    cmd_scan(&g_fs, g_imgpath, s->out, g_key, g_ivoff, g_nthreads, s->dry, s->defrag, s->geom);
}
static void sjob_done(void *arg, int failed) { (void)failed; free(arg); }

/* recover: rebuild deleted .pkg files from surviving inode block maps */
typedef struct { char out[4096]; int dry; } rjob;
static void rjob_run(void *arg) {
    rjob *r = (rjob *)arg;
    prog_label(L"Recovering deleted packages from the inode table...");
    cmd_recover(&g_fs, r->out, 0x40000, r->dry, 0);
}
static void do_recover(void) {
    rjob *r = (rjob *)calloc(1, sizeof(rjob));
    r->dry = g_opt_recdry;
    if (!pick_folder(L"Recover: output folder for reconstructed .pkg files", r->out, sizeof(r->out))) { free(r); return; }
    wchar_t msg[700], wo[4096]; u2w(r->out, wo, 4096);
    _snwprintf(msg, 700, L"Walk every inode for deleted .pkg files whose block maps survive and\n"
               L"rebuild them (exact layout, no heuristics) into\n%s%s\n\nContinue?",
               wo, r->dry ? L"\n\n(dry run: list only, nothing is written)" : L"");
    if (MessageBoxW(g_hwnd, msg, L"Recover deleted packages", MB_OKCANCEL | MB_ICONQUESTION) != IDOK) { free(r); return; }
    start_job(rjob_run, sjob_done, r, 1);
}
static void do_scan(void) {
    sjob *s = (sjob *)calloc(1, sizeof(sjob));
    s->dry = g_opt_scandry; s->defrag = g_opt_defrag; s->geom = g_opt_geom;
    if (!pick_folder(L"Scan: output folder for carved .pkg files", s->out, sizeof(s->out))) { free(s); return; }
    wchar_t msg[600], wo[4096]; u2w(s->out, wo, 4096);
    _snwprintf(msg, 600, L"Carve every .pkg (CNT) package from the whole partition into\n%s\n\n"
               L"This reads the entire partition and can take a long time.%s%s\n\nContinue?",
               wo, s->dry ? L"\n(dry run: nothing is written)" : L"",
               s->geom ? L"\n(geom: reassemble across cylinder-group metadata)" :
               s->defrag ? L"\n(defrag: reassemble via the free-block bitmap)" : L"");
    if (MessageBoxW(g_hwnd, msg, L"Scan for packages", MB_OKCANCEL | MB_ICONQUESTION) != IDOK) { free(s); return; }
    start_job(sjob_run, sjob_done, s, 1);
}

/* ==========================================================================
 * info / properties / viewer
 * ======================================================================== */
static void show_info(void) {
    GUARD_BEGIN
        cmd_info(&g_fs);
        printf("  image        : %s\n", g_imgpath);
        printf("  part offset  : %llu%s\n", (unsigned long long)g_partoff,
               g_partidx >= 0 ? "" : " (manual/bare)");
        if (g_partidx >= 0) printf("  GPT entry    : %d\n", g_partidx);
        if (!g_plain) printf("  ivoffset     : %llu\n", (unsigned long long)g_ivoff);
        printf("  threads      : %d\n", g_nthreads);
    GUARD_ERR
        error_box("%s", t_err);
    GUARD_END
}
static void show_parts(void) {
    char img[4096], keys[4096];
    read_config(img, keys, sizeof(img));
    load_key(keys, 1);                       /* partitions decrypted already need none */
    int sel = (int)SendMessageW(g_part, CB_GETCURSEL, 0, 0);
    if (!scan_parts(img, sel)) return;
    if (!g_nparts) { log_printf("no GPT in %s (bare partition image?)\n", img); return; }
    log_printf("GPT partitions in %s:\n", img);
    for (int i = 0; i < g_nparts; i++)
        log_printf("  #%-3d  base %-16llu  %-10s %s\n", g_parts[i].index,
                   (unsigned long long)g_parts[i].base, human(g_parts[i].size),
                   g_part_ufs2[i] == 1 ? "UFS2" : g_part_ufs2[i] == 2 ? "UFS2 (decrypted)" : "");
    SendMessageW(g_part, CB_SHOWDROPDOWN, TRUE, 0);
}

static row_t *focused_row(void) {
    int it = ListView_GetNextItem(g_list, -1, LVNI_FOCUSED | LVNI_SELECTED);
    if (it < 0) it = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    if (it < 0) return NULL;
    LVITEMW li = { LVIF_PARAM }; li.iItem = it; ListView_GetItem(g_list, &li);
    return &g_rows[li.lParam];
}

static void show_props(row_t *r) {
    if (!r) return;
    char b[8192];
    wchar_t tm[64]; char tmu[64];
    fmt_time(r->mtime, tm, 64); w2u(tm, tmu, 64);
    int n = snprintf(b, sizeof(b),
        "Path:\t%s\nInode:\t%u\nMode:\t%s  (0%o)\nSize:\t%llu bytes (%s)\nModified:\t%s\n",
        r->path, r->ino, mode_str(r->mode), r->mode, (unsigned long long)r->size,
        human(r->size), tmu);
    GUARD_BEGIN
        Inode in;
        if (fs_resolve(&g_fs, r->path, &in) == 0) {
            n += snprintf(b + n, sizeof(b) - n, "Blocks:\t%llu (x512)\nUID/GID:\t%u / %u\nLinks:\t%d\nFlags:\t0x%x\n",
                          (unsigned long long)in.blocks, in.uid, in.gid, in.nlink, in.flags);
            if (in_isreg(&in) && n < (int)sizeof(b))
                n += snprintf(b + n, sizeof(b) - n, "Storage:\t%s\n",
                              fs_is_plaintext_pkg(&g_fs, basename_of(r->path), &in)
                                  ? "plaintext .pkg (passthrough)" : "XTS-encrypted (decrypted on read)");
        }
    GUARD_ERR
        n += snprintf(b + n, sizeof(b) - n, "(error: %s)\n", t_err);
    GUARD_END
    if (r->link && n < (int)sizeof(b)) snprintf(b + n, sizeof(b) - n, "Target:\t%s\n", r->link);
    wchar_t *w = u2w_dup(b), t[300];
    wchar_t nm[256]; u2w(basename_of(r->path), nm, 256);
    _snwprintf(t, 300, L"Properties - %s", nm);
    MessageBoxW(g_hwnd, w, t, MB_ICONINFORMATION);
    free(w);
}

/* viewer window: text or hex dump of the first VIEW_MAX bytes */
typedef struct { uint8_t *d; int64_t n, max; } vbuf;
static int vbuf_cb(const uint8_t *buf, int64_t len, void *ud) {
    vbuf *v = (vbuf *)ud;
    int64_t take = len; if (v->n + take > v->max) take = v->max - v->n;
    memcpy(v->d + v->n, buf, (size_t)take);
    v->n += take;
    return v->n >= v->max;
}
static LRESULT CALLBACK view_proc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_SIZE: {
        HWND e = GetWindow(h, GW_CHILD);
        if (e) MoveWindow(e, 0, 0, LOWORD(lp), HIWORD(lp), TRUE);
        return 0;
    }
    case WM_SETFOCUS: { HWND e = GetWindow(h, GW_CHILD); if (e) SetFocus(e); return 0; }
    case WM_KEYDOWN: if (wp == VK_ESCAPE) { DestroyWindow(h); return 0; } break;
    }
    return DefWindowProcW(h, m, wp, lp);
}
static wchar_t *hexdump(const uint8_t *d, int64_t n) {
    int64_t lines = (n + 15) / 16;
    wchar_t *o = (wchar_t *)malloc((size_t)(lines * 80 + 64) * sizeof(wchar_t)), *p = o;
    for (int64_t off = 0; off < n; off += 16) {
        p += swprintf(p, 16, L"%08llx  ", (unsigned long long)off);
        for (int k = 0; k < 16; k++) {
            if (off + k < n) p += swprintf(p, 8, L"%02x ", d[off + k]);
            else { wcscpy(p, L"   "); p += 3; }
            if (k == 7) *p++ = L' ';
        }
        *p++ = L' ';
        for (int k = 0; k < 16 && off + k < n; k++) {
            uint8_t c = d[off + k];
            *p++ = (c >= 0x20 && c < 0x7f) ? (wchar_t)c : L'.';
        }
        *p++ = L'\r'; *p++ = L'\n';
    }
    *p = 0;
    return o;
}
static wchar_t *textview(const uint8_t *d, int64_t n) {
    /* UTF-8 -> UTF-16 with LF -> CRLF */
    char *t = (char *)malloc((size_t)n * 2 + 1); int64_t o = 0;
    for (int64_t i = 0; i < n; i++) {
        if (d[i] == '\n' && (i == 0 || d[i-1] != '\r')) t[o++] = '\r';
        t[o++] = d[i] ? (char)d[i] : ' ';
    }
    t[o] = 0;
    wchar_t *w = u2w_dup(t);
    free(t);
    return w;
}
static void view_file(row_t *r) {
    if (!r || row_is_dir(r)) return;
    vbuf v = { (uint8_t *)malloc(VIEW_MAX), 0, VIEW_MAX };
    int ok = 0;
    GUARD_BEGIN
        Inode in;
        if (fs_resolve(&g_fs, r->path, &in) != 0) error_box("not found: %s", r->path);
        else if (!in_isreg(&in)) error_box("Not a regular file.");
        else {
            int plain = fs_is_plaintext_pkg(&g_fs, basename_of(r->path), &in);
            fs_read_file_iter(&g_fs, &in, !plain, vbuf_cb, &v);
            ok = 1;
        }
    GUARD_ERR
        error_box("%s", t_err);
    GUARD_END
    if (!ok) { free(v.d); return; }

    int64_t probe = v.n < 8192 ? v.n : 8192, bad = 0;
    for (int64_t i = 0; i < probe; i++) {
        uint8_t c = v.d[i];
        if (c == 0 || (c < 0x20 && c != '\n' && c != '\r' && c != '\t')) bad++;
    }
    int is_text = v.n > 0 && bad * 100 <= probe * 2;
    wchar_t *content = is_text ? textview(v.d, v.n) : hexdump(v.d, v.n);
    free(v.d);

    wchar_t title[700], nm[512], sz[32];
    u2w(r->path, nm, 512); human_w(r->size, sz, 32);
    _snwprintf(title, 700, L"%s  (%s%s, %s)", nm, sz,
               r->size > VIEW_MAX ? L", first 512K shown" : L"", is_text ? L"text" : L"hex");
    HWND w = CreateWindowExW(0, L"PS4UFSView", title, WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             CW_USEDEFAULT, CW_USEDEFAULT, S(860), S(620), NULL, NULL, g_inst, NULL);
    HWND e = CreateWindowExW(0, L"EDIT", L"",
                             WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                             ES_READONLY | ES_AUTOHSCROLL | ES_AUTOVSCROLL | ES_NOHIDESEL,
                             0, 0, 10, 10, w, NULL, g_inst, NULL);
    SendMessageW(e, EM_SETLIMITTEXT, 0, 0);
    SendMessageW(e, WM_SETFONT, (WPARAM)g_mono, TRUE);
    SetWindowTextW(e, content);
    free(content);
    RECT rc; GetClientRect(w, &rc);
    MoveWindow(e, 0, 0, rc.right, rc.bottom, TRUE);
    SetFocus(e);
}

static void open_row(row_t *r) {
    if (!r) return;
    if (row_is_dir(r)) { navigate(r->path); tree_sync(); return; }
    if (r->link) {
        Inode in; char real[4096]; int isdir = 0;
        GUARD_BEGIN
            isdir = resolve_follow(r->path, &in, real, sizeof(real)) == 0 && in_isdir(&in);
        GUARD_ERR
        GUARD_END
        if (isdir) { navigate(real); tree_sync(); return; }
    }
    view_file(r);
}

static void copy_path(row_t *r) {
    const char *p = r ? r->path : g_cwd;
    wchar_t *w = u2w_dup(p);
    size_t n = (wcslen(w) + 1) * sizeof(wchar_t);
    if (OpenClipboard(g_hwnd)) {
        EmptyClipboard();
        HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, n);
        if (g) { memcpy(GlobalLock(g), w, n); GlobalUnlock(g); SetClipboardData(CF_UNICODETEXT, g); }
        CloseClipboard();
    }
    free(w);
}

static void list_context_menu(int x, int y) {
    row_t *r = focused_row();
    HMENU m = CreatePopupMenu();
    if (r) {
        AppendMenuW(m, MF_STRING, ID_CTX_OPEN, row_is_dir(r) ? L"&Open\tEnter" : L"&View\tEnter");
        if (!row_is_dir(r) && r->link) AppendMenuW(m, MF_STRING, ID_CTX_VIEW, L"View link &file");
        AppendMenuW(m, MF_SEPARATOR, 0, NULL);
        AppendMenuW(m, MF_STRING, ID_CTX_EXTRACT, L"&Extract to...\tCtrl+E");
        AppendMenuW(m, MF_STRING, ID_CTX_COPY, L"&Copy path");
        AppendMenuW(m, MF_SEPARATOR, 0, NULL);
        AppendMenuW(m, MF_STRING, ID_CTX_PROPS, L"P&roperties\tAlt+Enter");
    } else {
        AppendMenuW(m, MF_STRING, ID_ACT_EXTRACT_CWD, L"&Extract this folder...");
        AppendMenuW(m, MF_STRING, ID_ACT_REFRESH, L"&Refresh\tF5");
        AppendMenuW(m, MF_STRING, ID_CTX_COPY, L"&Copy path");
    }
    if (x == -1 && y == -1) { POINT p; GetCursorPos(&p); x = p.x; y = p.y; }
    TrackPopupMenu(m, TPM_RIGHTBUTTON, x, y, 0, g_hwnd, NULL);
    DestroyMenu(m);
}

/* ==========================================================================
 * layout
 * ======================================================================== */
#define ROWH  S(24)
#define GAP   S(6)
#define SPLW  S(6)

static int row3_y(void) { return GAP + 2 * (ROWH + GAP); }
static void layout(void) {
    if (IsIconic(g_hwnd)) return;
    RECT rc; GetClientRect(g_hwnd, &rc);
    int W = rc.right, H = rc.bottom;
    SendMessageW(g_status, WM_SIZE, 0, 0);
    RECT sr; GetWindowRect(g_status, &sr);
    int sh = sr.bottom - sr.top;
    {
        int parts[3] = { S(330), W - S(230), -1 };
        SendMessageW(g_status, SB_SETPARTS, 3, (LPARAM)parts);
    }
    HDWP d = BeginDeferWindowPos(32);
#define PUT(id, x, y, w, h) d = DeferWindowPos(d, GetDlgItem(g_hwnd, id), NULL, x, y, w, h, SWP_NOZORDER)
    int x = GAP, y = GAP, lw = S(64), bw = S(30), ty = S(3);
    /* row 1: image + keys */
    int avail = W - 2 * GAP - 2 * (lw + bw + GAP * 2);
    int imgw = avail * 62 / 100, keyw = avail - imgw;
    PUT(IDC_LBL_IMG, x, y + ty, lw, ROWH);            x += lw;
    PUT(IDC_IMG, x, y, imgw, ROWH);                   x += imgw + 2;
    PUT(IDC_IMG_BR, x, y, bw, ROWH);                  x += bw + GAP * 2;
    PUT(IDC_LBL_KEYS, x, y + ty, lw, ROWH);           x += lw;
    PUT(IDC_KEYS, x, y, keyw, ROWH);                  x += keyw + 2;
    PUT(IDC_KEYS_BR, x, y, bw, ROWH);
    /* row 2: partition, ivoffset, passthrough, open/close */
    y += ROWH + GAP; x = GAP;
    PUT(IDC_LBL_PART, x, y + ty, lw, ROWH);           x += lw;
    int pw = W - 2 * GAP - lw - S(70) - S(100) - S(150) - 2 * S(80) - 5 * GAP;
    if (pw < S(200)) pw = S(200);
    PUT(IDC_PART, x, y, pw, S(300));                  x += pw + GAP;
    PUT(IDC_LBL_IV, x, y + ty, S(70), ROWH);          x += S(70);
    PUT(IDC_IVOFF, x, y, S(100), ROWH);               x += S(100) + GAP;
    PUT(IDC_PKGPLAIN, x, y, S(150), ROWH);            x += S(150) + GAP;
    PUT(IDC_OPEN, x, y, S(80), ROWH);                 x += S(80) + GAP;
    PUT(IDC_CLOSE, x, y, S(80), ROWH);
    /* row 3: navigation + actions */
    y = row3_y(); x = GAP;
    int actw = S(90);
    int navw = W - 2 * GAP - S(40) - S(44) - S(180) - S(54) - 3 * actw - 8 * GAP;
    if (navw < S(150)) navw = S(150);
    PUT(IDC_UP, x, y, S(40), ROWH);                   x += S(40) + GAP;
    PUT(IDC_PATH, x, y, navw, ROWH);                  x += navw + 2;
    PUT(IDC_GO, x, y, S(44), ROWH);                   x += S(44) + GAP * 2;
    PUT(IDC_SEARCH, x, y, S(180), ROWH);              x += S(180) + 2;
    PUT(IDC_FIND, x, y, S(54), ROWH);                 x += S(54) + GAP * 2;
    PUT(IDC_EXTRACT, x, y, actw, ROWH);               x += actw + GAP;
    PUT(IDC_SCAN, x, y, actw, ROWH);                  x += actw + GAP;
    PUT(IDC_INFO, x, y, actw, ROWH);
    /* main area */
    int top = y + ROWH + GAP;
    int progh = S(22);
    int bottom = H - sh - GAP - progh - GAP;      /* log bottom */
    /* clamp local copies only: a small/minimized window must not destroy the
     * user's splitter positions */
    int logh = g_logh, split = g_split;
    if (logh > bottom - top - S(80)) logh = bottom - top - S(80);
    if (logh < S(40)) logh = S(40);
    int logtop = bottom - logh;
    int mainb = logtop - SPLW;
    if (split > W - S(200)) split = W - S(200);
    if (split < S(120)) split = S(120);
    d = DeferWindowPos(d, g_tree, NULL, GAP, top, split - GAP, mainb - top, SWP_NOZORDER);
    d = DeferWindowPos(d, g_list, NULL, split + SPLW, top, W - split - SPLW - GAP, mainb - top, SWP_NOZORDER);
    d = DeferWindowPos(d, g_log, NULL, GAP, logtop, W - 2 * GAP, logh, SWP_NOZORDER);
    if (g_drag) { g_split = split; g_logh = logh; }   /* while dragging, stop at the limits */
    int py = bottom + GAP;
    d = DeferWindowPos(d, g_prog, NULL, GAP, py, W - 3 * GAP - S(90), progh, SWP_NOZORDER);
    PUT(IDC_CANCEL, W - GAP - S(90), py - 1, S(90), progh + 2);
#undef PUT
    EndDeferWindowPos(d);
}
/* splitter hit-test in client coords: 1 = tree|list, 2 = main|log */
static int split_hit(int x, int y) {
    RECT t, l;
    GetWindowRect(g_tree, &t); MapWindowPoints(NULL, g_hwnd, (POINT *)&t, 2);
    GetWindowRect(g_log, &l);  MapWindowPoints(NULL, g_hwnd, (POINT *)&l, 2);
    if (y >= t.top && y < t.bottom && x >= t.right && x < t.right + SPLW + GAP) return 1;
    if (y >= t.bottom && y < l.top && x >= l.left && x < l.right) return 2;
    return 0;
}

/* ==========================================================================
 * window creation
 * ======================================================================== */
static HWND mk(const wchar_t *cls, const wchar_t *txt, DWORD style, DWORD ex, int id) {
    HWND h = CreateWindowExW(ex, cls, txt, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                             g_hwnd, (HMENU)(INT_PTR)id, g_inst, NULL);
    SendMessageW(h, WM_SETFONT, (WPARAM)g_font, TRUE);
    return h;
}
static void add_tip(HWND tip, int id, const wchar_t *text) {
    TOOLINFOW ti;
    memset(&ti, 0, sizeof(ti));
    ti.cbSize = sizeof(ti); ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    ti.hwnd = g_hwnd; ti.uId = (UINT_PTR)GetDlgItem(g_hwnd, id); ti.lpszText = (LPWSTR)text;
    SendMessageW(tip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
}

static HMENU build_menu(void) {
    HMENU bar = CreateMenu(), f = CreatePopupMenu(), a = CreatePopupMenu(),
          o = CreatePopupMenu(), h = CreatePopupMenu();
    AppendMenuW(f, MF_STRING, ID_FILE_OPEN, L"&Open image\tCtrl+O");
    AppendMenuW(f, MF_STRING, ID_FILE_CLOSE, L"&Close image");
    AppendMenuW(f, MF_SEPARATOR, 0, NULL);
    AppendMenuW(f, MF_STRING, ID_FILE_EXIT, L"E&xit");
    AppendMenuW(a, MF_STRING, ID_ACT_EXTRACT, L"&Extract selected...\tCtrl+E");
    AppendMenuW(a, MF_STRING, ID_ACT_EXTRACT_CWD, L"Extract &current folder...");
    AppendMenuW(a, MF_SEPARATOR, 0, NULL);
    AppendMenuW(a, MF_STRING, ID_ACT_FIND_FOCUS, L"&Find...\tCtrl+F");
    AppendMenuW(a, MF_STRING, ID_ACT_SCAN, L"&Scan for packages (carve .pkg)...");
    AppendMenuW(a, MF_STRING, ID_ACT_RECOVER, L"Reco&ver deleted packages (inode maps)...");
    AppendMenuW(a, MF_SEPARATOR, 0, NULL);
    AppendMenuW(a, MF_STRING, ID_ACT_UP, L"&Up one level\tAlt+Up");
    AppendMenuW(a, MF_STRING, ID_ACT_REFRESH, L"&Refresh\tF5");
    AppendMenuW(a, MF_SEPARATOR, 0, NULL);
    AppendMenuW(a, MF_STRING, ID_ACT_INFO, L"Filesystem &info");
    AppendMenuW(a, MF_STRING, ID_ACT_PARTS, L"List GPT &partitions");
    AppendMenuW(a, MF_STRING, ID_ACT_CLEARLOG, L"C&lear log");
    AppendMenuW(o, MF_STRING, ID_OPT_SKIPPKG, L"&Skip .pkg files when extracting");
    AppendMenuW(o, MF_SEPARATOR, 0, NULL);
    AppendMenuW(o, MF_STRING, ID_OPT_SCANDRY, L"Scan: &dry run (list only)");
    AppendMenuW(o, MF_STRING, ID_OPT_SCANDEFRAG, L"Scan: de&frag via free-block bitmap");
    AppendMenuW(o, MF_STRING, ID_OPT_SCANGEOM, L"Scan: reassemble by cg &geometry (overrides defrag)");
    AppendMenuW(o, MF_SEPARATOR, 0, NULL);
    AppendMenuW(o, MF_STRING, ID_OPT_RECDRY, L"Recover: d&ry run (list only)");
    AppendMenuW(h, MF_STRING, ID_HELP_ABOUT, L"&About");
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)f, L"&File");
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)a, L"&Actions");
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)o, L"&Options");
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)h, L"&Help");
    return bar;
}

static void create_children(void) {
    mk(L"STATIC", L"Image:", 0, 0, IDC_LBL_IMG);
    g_imgedit  = mk(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, IDC_IMG);
    mk(L"BUTTON", L"...", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_IMG_BR);
    mk(L"STATIC", L"Keys:", 0, 0, IDC_LBL_KEYS);
    g_keysedit = mk(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, IDC_KEYS);
    mk(L"BUTTON", L"...", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_KEYS_BR);

    mk(L"STATIC", L"Partition:", 0, 0, IDC_LBL_PART);
    g_part   = mk(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, 0, IDC_PART);
    mk(L"STATIC", L"IV offset:", 0, 0, IDC_LBL_IV);
    g_ivedit = mk(L"EDIT", L"0", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, IDC_IVOFF);
    g_pkgchk = mk(L"BUTTON", L".pkg passthrough", BS_AUTOCHECKBOX | WS_TABSTOP, 0, IDC_PKGPLAIN);
    mk(L"BUTTON", L"Open", BS_DEFPUSHBUTTON | WS_TABSTOP, 0, IDC_OPEN);
    mk(L"BUTTON", L"Close", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_CLOSE);

    mk(L"BUTTON", L"\x2191 Up", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_UP);
    g_path   = mk(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, IDC_PATH);
    mk(L"BUTTON", L"Go", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_GO);
    g_search = mk(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, IDC_SEARCH);
    SendMessageW(g_search, EM_SETCUEBANNER, TRUE, (LPARAM)L"Find in this folder...");
    mk(L"BUTTON", L"Find", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_FIND);
    mk(L"BUTTON", L"Extract...", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_EXTRACT);
    mk(L"BUTTON", L"Scan PKGs...", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_SCAN);
    mk(L"BUTTON", L"FS Info", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_INFO);

    SHFILEINFOW sfi;
    HIMAGELIST sys = (HIMAGELIST)SHGetFileInfoW(L"C:\\", 0, &sfi, sizeof(sfi),
                                                SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
    g_tree = mk(WC_TREEVIEWW, L"", TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS |
                TVS_HASLINES | WS_TABSTOP, WS_EX_CLIENTEDGE, IDC_TREE);
    TreeView_SetExtendedStyle(g_tree, TVS_EX_DOUBLEBUFFER, TVS_EX_DOUBLEBUFFER);
    TreeView_SetImageList(g_tree, sys, TVSIL_NORMAL);

    g_list = mk(WC_LISTVIEWW, L"", LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SHAREIMAGELISTS | WS_TABSTOP,
                WS_EX_CLIENTEDGE, IDC_LIST);
    ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER |
                                      LVS_EX_HEADERDRAGDROP | LVS_EX_LABELTIP);
    ListView_SetImageList(g_list, sys, LVSIL_SMALL);
    static const struct { const wchar_t *t; int w, fmt; } cols[] = {
        { L"Name", 300, LVCFMT_LEFT }, { L"Size", 80, LVCFMT_RIGHT }, { L"Type", 130, LVCFMT_LEFT },
        { L"Modified", 140, LVCFMT_LEFT }, { L"Mode", 120, LVCFMT_LEFT }, { L"Inode", 70, LVCFMT_RIGHT } };
    for (int i = 0; i < 6; i++) {
        LVCOLUMNW c;
        memset(&c, 0, sizeof(c));
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        c.pszText = (LPWSTR)cols[i].t; c.cx = S(cols[i].w); c.fmt = cols[i].fmt;
        ListView_InsertColumn(g_list, i, &c);
    }

    g_log = mk(L"EDIT", L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_HSCROLL |
               ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, IDC_LOG);
    SendMessageW(g_log, EM_SETLIMITTEXT, 0, 0);
    SendMessageW(g_log, WM_SETFONT, (WPARAM)g_mono, TRUE);

    g_prog = mk(PROGRESS_CLASSW, L"", PBS_SMOOTH, 0, IDC_PROG);
    mk(L"BUTTON", L"Cancel", BS_PUSHBUTTON | WS_TABSTOP, 0, IDC_CANCEL);
    g_status = mk(STATUSCLASSNAMEW, L"", SBARS_SIZEGRIP, 0, IDC_STATUS);

    HWND tip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, NULL, TTS_ALWAYSTIP | TTS_NOPREFIX,
                               0, 0, 0, 0, g_hwnd, NULL, g_inst, NULL);
    SendMessageW(tip, TTM_SETMAXTIPWIDTH, 0, S(400));
    add_tip(tip, IDC_IMG, L"Whole-disk image (GPT) or bare partition dump. You can also drop a file on the window.");
    add_tip(tip, IDC_KEYS, L"32-byte keys.bin (AES-128-XTS data key + tweak key). Not needed for an already-decrypted image.");
    add_tip(tip, IDC_PART, L"Which partition holds the UFS2 filesystem (refreshed when the image is opened)");
    add_tip(tip, IDC_IVOFF, L"Partition-relative XTS tweak base (sector number), normally 0");
    add_tip(tip, IDC_PKGPLAIN, L"Installed .pkg files are stored unencrypted inside the volume; read them raw");
    add_tip(tip, IDC_PATH, L"Type a path and press Enter");
    add_tip(tip, IDC_SEARCH, L"Case-insensitive name search below the current folder");
    add_tip(tip, IDC_EXTRACT, L"Extract the selected files/folders to a folder on disk");
    add_tip(tip, IDC_SCAN, L"Carve all .pkg (CNT) packages from the raw partition, including deleted ones (see Options; Actions > Recover for inode-based rebuild)");
}

static void load_settings(void) {
    wchar_t b[4096];
    ini_get(L"Image", L"C:\\hdd\\hdd.img", b, 4096); SetWindowTextW(g_imgedit, b);
    ini_get(L"Keys", L"C:\\hdd\\keys.bin", b, 4096); SetWindowTextW(g_keysedit, b);
    ini_get(L"IvOffset", L"0", b, 4096);             SetWindowTextW(g_ivedit, b);
    Button_SetCheck(g_pkgchk, ini_int(L"PkgPlain", 1) ? BST_CHECKED : BST_UNCHECKED);
    g_opt_skippkg = ini_int(L"SkipPkg", 0);
    g_opt_scandry = ini_int(L"ScanDryRun", 0);
    g_opt_defrag  = ini_int(L"ScanDefrag", 0);
    g_opt_geom    = ini_int(L"ScanGeom", 0);
    g_opt_recdry  = ini_int(L"RecoverDryRun", 0);
    g_split = S(ini_int(L"Split", 260));
    g_logh  = S(ini_int(L"LogHeight", 150));
    g_nparts = 0;
    fill_part_combo(ini_int(L"Partition", 0) <= 1 ? ini_int(L"Partition", 0) : 0);
}

/* ==========================================================================
 * window procedure
 * ======================================================================== */
static void on_command(int id, int code) {
    switch (id) {
    case IDC_IMG_BR:
        browse_file(g_imgedit, L"Select disk / partition image",
                    L"Disk images (*.img;*.bin;*.raw)\0*.img;*.bin;*.raw\0All files\0*.*\0");
        break;
    case IDC_KEYS_BR:
        browse_file(g_keysedit, L"Select keys.bin (32 bytes)",
                    L"Key files (*.bin;*.key)\0*.bin;*.key\0All files\0*.*\0");
        break;
    case IDC_OPEN: case ID_FILE_OPEN: open_image(); break;
    case IDC_CLOSE: case ID_FILE_CLOSE:
        if (!g_busy) { close_image(); update_ui(); status_set(1, L""); }
        break;
    case IDC_PART:
        if (code == CBN_SELCHANGE && g_open && !g_busy) open_image();
        break;
    case IDC_PKGPLAIN:
        if (code == BN_CLICKED && g_open && !g_busy) {
            g_fs.pkg_plaintext = Button_GetCheck(g_pkgchk) == BST_CHECKED;
            if (!g_search_mode) refresh();
        }
        break;
    case ID_FILE_EXIT: PostMessageW(g_hwnd, WM_CLOSE, 0, 0); break;
    case IDC_UP: case ID_ACT_UP: go_up(); tree_sync(); break;
    case IDC_GO: {
        char p[4096]; get_text_u(g_path, p, sizeof(p));
        if (p[0] != '/') { char t[4096]; snprintf(t, sizeof(t), "%s/%s", g_cwd, p); norm_path(t, p, sizeof(p)); }
        navigate(p); tree_sync();
        break;
    }
    case IDC_FIND: do_find(); break;
    case ID_ACT_FIND_FOCUS: SetFocus(g_search); SendMessageW(g_search, EM_SETSEL, 0, -1); break;
    case IDC_EXTRACT: case ID_ACT_EXTRACT: case ID_CTX_EXTRACT:
        if (g_open && !g_busy) extract_selected();
        break;
    case ID_ACT_EXTRACT_CWD: if (g_open && !g_busy) extract_cwd(); break;
    case IDC_SCAN: case ID_ACT_SCAN: if (g_open && !g_busy) do_scan(); break;
    case ID_ACT_RECOVER: if (g_open && !g_busy) do_recover(); break;
    case IDC_INFO: case ID_ACT_INFO: if (g_open && !g_busy) show_info(); break;
    case ID_ACT_PARTS: if (!g_busy) show_parts(); break;
    case ID_ACT_REFRESH: if (!g_search_mode) refresh(); break;
    case ID_ACT_CLEARLOG: SetWindowTextW(g_log, L""); g_log_linestart = 0; break;
    case IDC_CANCEL:
        if (g_busy) { g_cancel = 1; g_abort = 1; status_set(1, L"Canceling..."); }
        break;
    case ID_OPT_SKIPPKG:    g_opt_skippkg ^= 1; update_ui(); break;
    case ID_OPT_SCANDRY:    g_opt_scandry ^= 1; update_ui(); break;
    case ID_OPT_SCANDEFRAG: g_opt_defrag  ^= 1; update_ui(); break;
    case ID_OPT_SCANGEOM:   g_opt_geom    ^= 1; update_ui(); break;
    case ID_OPT_RECDRY:     g_opt_recdry  ^= 1; update_ui(); break;
    case ID_CTX_OPEN:  if (!g_busy) open_row(focused_row()); break;
    case ID_CTX_VIEW:  if (!g_busy) view_file(focused_row()); break;
    case ID_CTX_PROPS: if (!g_busy) show_props(focused_row()); break;
    case ID_CTX_COPY:  copy_path(focused_row()); break;
    case ID_HELP_ABOUT:
        MessageBoxW(g_hwnd,
            L"ps4ufs GUI\n\n"
            L"Browse an AES-128-XTS encrypted PS4 UFS2 disk image, decrypting on the fly\n"
            L"(already-decrypted images are detected and opened without a key).\n"
            L"Installed .pkg files are stored plaintext inside the volume and are passed\n"
            L"through unmodified.\n\n"
            L"Double-click: open folder / view file      Backspace / Alt+Up: up\n"
            L"Ctrl+E: extract selection      Ctrl+F: find      F5: refresh\n"
            L"Alt+Enter: properties      Drop an image file on the window to select it.",
            L"About ps4ufs", MB_ICONINFORMATION);
        break;
    }
}

static LRESULT on_notify(NMHDR *nh) {
    if (nh->hwndFrom == g_list) {
        switch (nh->code) {
        case LVN_GETDISPINFOW: on_list_dispinfo((NMLVDISPINFOW *)nh); return 0;
        case NM_DBLCLK: case NM_RETURN: if (!g_busy) open_row(focused_row()); return 0;
        case LVN_COLUMNCLICK: {
            NMLISTVIEW *lv = (NMLISTVIEW *)nh;
            if (lv->iSubItem == g_sort_col) g_sort_desc ^= 1;
            else { g_sort_col = lv->iSubItem; g_sort_desc = (g_sort_col == 1 || g_sort_col == 3); }
            list_sort();
            return 0;
        }
        case LVN_KEYDOWN: {
            NMLVKEYDOWN *k = (NMLVKEYDOWN *)nh;
            if (k->wVKey == VK_BACK) { go_up(); tree_sync(); }
            else if (k->wVKey == 'A' && GetKeyState(VK_CONTROL) < 0)
                ListView_SetItemState(g_list, -1, LVIS_SELECTED, LVIS_SELECTED);
            return 0;
        }
        case LVN_ITEMCHANGED: {
            NMLISTVIEW *lv = (NMLISTVIEW *)nh;
            if ((lv->uChanged & LVIF_STATE) && ((lv->uNewState ^ lv->uOldState) & LVIS_SELECTED)) {
                int cnt = ListView_GetSelectedCount(g_list);
                if (cnt > 0 && !g_busy) {
                    uint64_t tot = 0; int it = -1;
                    while ((it = ListView_GetNextItem(g_list, it, LVNI_SELECTED)) >= 0) {
                        LVITEMW li = { LVIF_PARAM }; li.iItem = it; ListView_GetItem(g_list, &li);
                        if (!row_is_dir(&g_rows[li.lParam])) tot += g_rows[li.lParam].size;
                    }
                    wchar_t t[32]; human_w(tot, t, 32);
                    status_set(2, L"%d selected, %s", cnt, t);
                }
            }
            return 0;
        }
        }
    } else if (nh->hwndFrom == g_tree) {
        switch (nh->code) {
        case TVN_ITEMEXPANDINGW: {
            NMTREEVIEWW *tv = (NMTREEVIEWW *)nh;
            if (tv->action == TVE_EXPAND && !g_busy) tree_load(tv->itemNew.hItem);
            return 0;
        }
        case TVN_SELCHANGEDW: {
            NMTREEVIEWW *tv = (NMTREEVIEWW *)nh;
            if (!g_tree_syncing && tv->itemNew.lParam && !g_busy)
                navigate(((tnode *)tv->itemNew.lParam)->path);
            return 0;
        }
        case TVN_DELETEITEMW: {
            NMTREEVIEWW *tv = (NMTREEVIEWW *)nh;
            tnode *tn = (tnode *)tv->itemOld.lParam;
            if (tn) { free(tn->path); free(tn); }
            return 0;
        }
        }
    }
    return 0;
}

static LRESULT CALLBACK wnd_proc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE: {
        g_hwnd = h;
        HDC dc = GetDC(h); g_dpi = GetDeviceCaps(dc, LOGPIXELSY); ReleaseDC(h, dc);
        NONCLIENTMETRICSW ncm = { sizeof(ncm) };
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
        g_font = CreateFontIndirectW(&ncm.lfMessageFont);
        g_mono = CreateFontW(-MulDiv(9, g_dpi, 72), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                             0, 0, CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");
        SetMenu(h, build_menu());
        create_children();
        load_settings();
        DragAcceptFiles(h, TRUE);
        update_ui();
        layout();
        log_printf("ps4ufs GUI ready. Choose the image + keys and press Open. (%d decrypt threads)\n", g_nthreads);
        return 0;
    }
    case WM_SIZE: layout(); return 0;
    case WM_GETMINMAXINFO: ((MINMAXINFO *)lp)->ptMinTrackSize.x = S(900);
                           ((MINMAXINFO *)lp)->ptMinTrackSize.y = S(500); return 0;
    case WM_SETCURSOR:
        if ((HWND)wp == h && LOWORD(lp) == HTCLIENT) {
            POINT p; GetCursorPos(&p); ScreenToClient(h, &p);
            int s = g_drag ? g_drag : split_hit(p.x, p.y);
            if (s) { SetCursor(LoadCursor(NULL, s == 1 ? IDC_SIZEWE : IDC_SIZENS)); return TRUE; }
        }
        break;
    case WM_LBUTTONDOWN:
        g_drag = split_hit(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
        if (g_drag) SetCapture(h);
        return 0;
    case WM_MOUSEMOVE:
        if (g_drag) {
            RECT rc; GetClientRect(h, &rc);
            if (g_drag == 1) g_split = GET_X_LPARAM(lp) - SPLW / 2;
            else {
                RECT pr; GetWindowRect(g_prog, &pr); MapWindowPoints(NULL, h, (POINT *)&pr, 2);
                g_logh = pr.top - GAP - GET_Y_LPARAM(lp) - SPLW / 2;
            }
            layout();
        }
        return 0;
    case WM_LBUTTONUP:
        if (g_drag) { g_drag = 0; ReleaseCapture(); }
        return 0;
    case WM_COMMAND: on_command(LOWORD(wp), HIWORD(wp)); return 0;
    case WM_NOTIFY: return on_notify((NMHDR *)lp);
    case WM_CONTEXTMENU:
        if ((HWND)wp == g_list && g_open && !g_busy) { list_context_menu(GET_X_LPARAM(lp), GET_Y_LPARAM(lp)); return 0; }
        break;
    case WM_DROPFILES: {
        wchar_t f[4096];
        if (DragQueryFileW((HDROP)wp, 0, f, 4096)) {
            const wchar_t *dot = wcsrchr(f, L'.');
            DWORD sz = 0;
            HANDLE fh = CreateFileW(f, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (fh != INVALID_HANDLE_VALUE) { sz = GetFileSize(fh, NULL); CloseHandle(fh); }
            /* a 32-byte file is the key, anything else the image */
            if (sz == 32 || (dot && !_wcsicmp(dot, L".key"))) SetWindowTextW(g_keysedit, f);
            else { SetWindowTextW(g_imgedit, f); if (!g_busy) open_image(); }
        }
        DragFinish((HDROP)wp);
        return 0;
    }
    case WM_TIMER: if (wp == TIMER_PROG) on_progress_timer(); return 0;
    case WM_APP_LOG: { wchar_t *w = (wchar_t *)lp; log_append(w); free(w); return 0; }
    case WM_APP_JOBDONE: on_job_done(); return 0;
    case WM_CLOSE:
        if (g_busy && MessageBoxW(h, L"An operation is still running. Quit anyway?",
                                  L"ps4ufs", MB_YESNO | MB_ICONWARNING) != IDYES) return 0;
        save_settings();
        if (g_busy) ExitProcess(0);          /* worker owns the fs; don't wait for it */
        DestroyWindow(h);
        return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}

/* ==========================================================================
 * entry point
 * ======================================================================== */
int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmd, int show) {
    (void)prev; (void)cmd;
    g_inst = inst;
    build_inv_sbox();
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_WIN95_CLASSES | ICC_PROGRESS_CLASS | ICC_BAR_CLASSES };
    InitCommonControlsEx(&icc);
    redirect_stdio();

    g_nthreads = cpu_count();
    if (g_nthreads > 256) g_nthreads = 256;
    if (g_nthreads > 1) pool_init(g_nthreads);

    GetModuleFileNameW(NULL, g_ini, MAX_PATH);
    wchar_t *sl = wcsrchr(g_ini, L'\\');
    if (sl) wcscpy(sl + 1, L"ps4ufs_gui.ini");

    HICON icon = LoadIconW(inst, MAKEINTRESOURCEW(1));
    if (!icon) icon = LoadIconW(NULL, IDI_APPLICATION);
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc); wc.lpfnWndProc = wnd_proc; wc.hInstance = inst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"PS4UFSMain"; wc.hIcon = icon; wc.hIconSm = icon;
    RegisterClassExW(&wc);
    wc.lpfnWndProc = view_proc; wc.lpszClassName = L"PS4UFSView";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassExW(&wc);

    int x = CW_USEDEFAULT, y = CW_USEDEFAULT, w = 1200, hgt = 800, maxed = 0;
    wchar_t wp[128];
    GetPrivateProfileStringW(L"ps4ufs", L"Window", L"", wp, 128, g_ini);
    long l, t, r, b;
    int have_pos = swscanf(wp, L"%ld %ld %ld %ld %d", &l, &t, &r, &b, &maxed) == 5 && r - l > 300 && b - t > 200;
    HWND hw = CreateWindowExW(WS_EX_ACCEPTFILES, L"PS4UFSMain", L"ps4ufs - PS4 UFS2 image browser",
                              WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                              x, y, w, hgt, NULL, NULL, inst, NULL);
    if (!hw) return 1;
    if (have_pos) {
        WINDOWPLACEMENT pl = { sizeof(pl) };
        GetWindowPlacement(hw, &pl);
        SetRect(&pl.rcNormalPosition, l, t, r, b);
        pl.showCmd = maxed ? SW_SHOWMAXIMIZED : show;
        SetWindowPlacement(hw, &pl);
    } else {
        SetWindowPos(hw, NULL, 0, 0, S(1200), S(800), SWP_NOMOVE | SWP_NOZORDER);
        ShowWindow(hw, show);
    }
    UpdateWindow(hw);

    ACCEL acc[] = {
        { FVIRTKEY | FCONTROL, 'O', ID_FILE_OPEN },
        { FVIRTKEY | FCONTROL, 'E', ID_ACT_EXTRACT },
        { FVIRTKEY | FCONTROL, 'F', ID_ACT_FIND_FOCUS },
        { FVIRTKEY,            VK_F5, ID_ACT_REFRESH },
        { FVIRTKEY | FALT,     VK_UP, ID_ACT_UP },
        { FVIRTKEY | FALT,     VK_RETURN, ID_CTX_PROPS },
    };
    g_accel = CreateAcceleratorTableW(acc, (int)(sizeof(acc) / sizeof(acc[0])));

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            if (msg.hwnd == g_path)   { on_command(IDC_GO, 0); continue; }
            if (msg.hwnd == g_search) { on_command(IDC_FIND, 0); continue; }
            if (msg.hwnd == g_list && !g_busy) { open_row(focused_row()); continue; }
            if (msg.hwnd == g_imgedit || msg.hwnd == g_keysedit || msg.hwnd == g_ivedit) {
                on_command(IDC_OPEN, 0); continue;
            }
        }
        if (GetAncestor(msg.hwnd, GA_ROOT) == g_hwnd && TranslateAcceleratorW(g_hwnd, g_accel, &msg)) continue;
        if (GetAncestor(msg.hwnd, GA_ROOT) == g_hwnd && IsDialogMessageW(g_hwnd, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (g_nthreads > 1) pool_shutdown();
    CoUninitialize();
    return 0;
}
