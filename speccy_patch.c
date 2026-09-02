#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#pragma comment(linker, "/NODEFAULTLIB")
#pragma comment(linker, "/ENTRY:DllMain")
#pragma function(memcpy, memset, memcmp)

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
    return dst;
}

#ifdef _WIN64
static __forceinline void *peb_ptr(void)
{
    return (void *)__readgsqword(0x60);
}
#else
static __forceinline void *peb_ptr(void)
{
    return (void *)(uintptr_t)__readfsdword(0x30);
}
#endif

static unsigned hmix(unsigned h, unsigned char b)
{
    h ^= (unsigned)b;
    h = ((h << 7) | (h >> 25)) + 0x6D2B79F5u;
    h ^= h >> 11;
    return h;
}

static unsigned h_fnv(const char *s)
{
    unsigned h = 0xA5A5C3E1u;
    while (*s)
        h = hmix(h, (unsigned char)*s++);
    return h;
}

static unsigned h_wfnv(const wchar_t *s, unsigned nbytes)
{
    unsigned h = 0xA5A5C3E1u;
    unsigned n, i;
    if (!s || nbytes < 2)
        return 0;
    n = nbytes / 2u;
    for (i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)(s[i] & 0xFF);
        if (c >= 'A' && c <= 'Z')
            c = (unsigned char)(c + 32);
        h = hmix(h, c);
    }
    return h;
}

static void *find_exp(HMODULE mod, unsigned hash)
{
    unsigned char *base = (unsigned char *)mod;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *dd;
    IMAGE_EXPORT_DIRECTORY *exp;
    DWORD *names, *funcs, i;
    WORD *ords;

    if (!mod)
        return 0;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->Size)
        return 0;
    exp = (IMAGE_EXPORT_DIRECTORY *)(base + dd->VirtualAddress);
    names = (DWORD *)(base + exp->AddressOfNames);
    ords = (WORD *)(base + exp->AddressOfNameOrdinals);
    funcs = (DWORD *)(base + exp->AddressOfFunctions);
    for (i = 0; i < exp->NumberOfNames; ++i) {
        if (h_fnv((const char *)(base + names[i])) == hash)
            return (void *)(base + funcs[ords[i]]);
    }
    return 0;
}

typedef struct _USTR {
    USHORT Length;
    USHORT MaximumLength;
#ifdef _WIN64
    ULONG Unused;
#endif
    PWSTR Buffer;
} USTR;

typedef struct _LDR {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
#ifdef _WIN64
    ULONG Unused;
#endif
    USTR FullDllName;
    USTR BaseDllName;
} LDR;

typedef struct _PEBLDR {
    ULONG Length;
    BOOLEAN Initialized;
#ifdef _WIN64
    BYTE Pad[3];
#endif
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEBLDR;

typedef struct _XPEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
#ifdef _WIN64
    BYTE Pad[4];
#endif
    PVOID Reserved3[2];
    PEBLDR *Ldr;
} XPEB;

#define HM_K32 0x41E1A17Eu
#define H_VP   0xB611D5B9u
#define H_LLW  0x090A1A52u
#define H_GSD  0x1304CBEFu
#define H_DTL  0x8D0585B2u
#define H_FIC  0x30E92C05u
#define H_VSA  0x47BD4F1Au
#define H_VIA  0x9442E02Fu
#define H_VQA  0x91AF4C8Cu
#define H_VIW  0x9442FF2Cu
#define H_VSW  0x47BD5818u
#define H_VQW  0x91AFB393u

static HMODULE mod_by_hash(unsigned want)
{
    XPEB *peb = (XPEB *)peb_ptr();
    LIST_ENTRY *head, *cur;
    if (!peb || !peb->Ldr)
        return 0;
    head = &peb->Ldr->InLoadOrderModuleList;
    cur = head->Flink;
    while (cur && cur != head) {
        LDR *e = (LDR *)cur;
        if (e->DllBase && e->BaseDllName.Buffer && e->BaseDllName.Length >= 2) {
            if (h_wfnv(e->BaseDllName.Buffer, e->BaseDllName.Length) == want)
                return (HMODULE)e->DllBase;
        }
        cur = cur->Flink;
    }
    return 0;
}

static void *k32_fn(unsigned hash)
{
    static HMODULE m;
    if (!m)
        m = mod_by_hash(HM_K32);
    return m ? find_exp(m, hash) : 0;
}

static int bcmp(const BYTE *a, const BYTE *b, DWORD n)
{
    DWORD i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i])
            return 1;
    }
    return 0;
}

static void bcpy(BYTE *d, const BYTE *s, DWORD n)
{
    DWORD i;
    for (i = 0; i < n; i++)
        d[i] = s[i];
}

static const BYTE *find_mask(const BYTE *buf, DWORD n, const BYTE *sig, DWORD sigN, DWORD wild)
{
    DWORD i, k;
    if (n < sigN)
        return 0;
    for (i = 0; i + sigN <= n; i++) {
        for (k = 0; k < sigN; k++) {
            if (k == wild)
                continue;
            if (buf[i + k] != sig[k])
                break;
        }
        if (k == sigN)
            return buf + i;
    }
    return 0;
}

typedef BOOL(WINAPI *fn_vp)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI *fn_fic)(HANDLE, LPCVOID, SIZE_T);

static int protect_write(BYTE *p, DWORD n, const BYTE *src)
{
    fn_vp vp = (fn_vp)k32_fn(H_VP);
    fn_fic fic = (fn_fic)k32_fn(H_FIC);
    DWORD old = 0;
    ULONG_PTR page;
    if (!vp || !p || !src || !n)
        return 0;
    if (!bcmp(p, src, n))
        return 1;
    page = (ULONG_PTR)p & ~(ULONG_PTR)0xFFF;
    if (!vp((LPVOID)page, 0x2000, PAGE_EXECUTE_READWRITE, &old))
        return 0;
    bcpy(p, src, n);
    vp((LPVOID)page, 0x2000, old, &old);
    if (fic)
        fic((HANDLE)(LONG_PTR)-1, p, n);
    return 1;
}

static const BYTE kTail64[] = {
    0xB9, 0x01, 0x00, 0x00, 0x00, 0x3B, 0xC1, 0x00, 0x02, 0x32, 0xC9,
    0x8A, 0xC1, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3
};
static const unsigned kTailWild = 7;
static const unsigned kTailToFn = 0x2B;
static const BYTE kFn64[] = { 0x48, 0x89, 0x4C, 0x24, 0x08 };
static const BYTE kStub64[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

typedef struct {
    BYTE off[8];
    BYTE on[8];
    DWORD n;
} FlagPair;

static const FlagPair kFlags[] = {
    { { 0x44, 0x88, 0xBF, 0x9C, 0x08, 0x00, 0x00 },
      { 0xC6, 0x87, 0x9C, 0x08, 0x00, 0x00, 0x01 }, 7 },
    { { 0xC6, 0x87, 0x9C, 0x08, 0x00, 0x00, 0x00 },
      { 0xC6, 0x87, 0x9C, 0x08, 0x00, 0x00, 0x01 }, 7 },
    { { 0x44, 0x88, 0xBF, 0x3C, 0x09, 0x00, 0x00 },
      { 0xC6, 0x87, 0x3C, 0x09, 0x00, 0x00, 0x01 }, 7 },
    { { 0xC6, 0x87, 0x3C, 0x09, 0x00, 0x00, 0x00 },
      { 0xC6, 0x87, 0x3C, 0x09, 0x00, 0x00, 0x01 }, 7 },
};

static void apply_img(BYTE *base, DWORD n)
{
    const BYTE *hit;
    DWORD fn, i;

    for (i = 0; i < sizeof(kFlags) / sizeof(kFlags[0]); i++) {
        hit = find_mask(base, n, kFlags[i].off, kFlags[i].n, (DWORD)-1);
        if (!hit)
            hit = find_mask(base, n, kFlags[i].on, kFlags[i].n, (DWORD)-1);
        if (hit)
            protect_write((BYTE *)hit, kFlags[i].n, kFlags[i].on);
    }

    hit = find_mask(base, n, kTail64, sizeof(kTail64), kTailWild);
    if (!hit)
        return;
    fn = (DWORD)(hit - base);
    if (fn < kTailToFn)
        return;
    fn -= kTailToFn;
    if (bcmp(base + fn, kStub64, sizeof(kStub64)) &&
        bcmp(base + fn, kFn64, sizeof(kFn64)))
        return;
    protect_write(base + fn, sizeof(kStub64), kStub64);
}

static void apply_host(void)
{
    XPEB *peb = (XPEB *)peb_ptr();
    BYTE *base;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    DWORD n;

    if (!peb || !peb->Reserved3[1])
        return;
    base = (BYTE *)peb->Reserved3[1];
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return;
    n = nt->OptionalHeader.SizeOfImage;
    if (n < 0x1000 || n > 64u * 1024u * 1024u)
        return;
    apply_img(base, n);
}

static void dec_wn(wchar_t *out, unsigned cap, const unsigned char *enc, unsigned n)
{
    unsigned char key;
    unsigned i, m;
    if (!out || cap < 2)
        return;
    key = enc[0];
    m = n - 1;
    if (m >= cap)
        m = cap - 1;
    for (i = 0; i < m; ++i)
        out[i] = (wchar_t)(enc[i + 1] ^ (unsigned char)(key + (unsigned char)(i * 13u) + (unsigned char)(i >> 2)));
    out[m] = 0;
}

typedef UINT(WINAPI *fn_gsd)(LPWSTR, UINT);
typedef HMODULE(WINAPI *fn_llw)(LPCWSTR);

static const unsigned char kNameEnc[] = {
    0x5A, 0x2C, 0x02, 0x06, 0xF2, 0xE6, 0xF3, 0xC7, 0x98, 0xA0, 0xBD, 0xB2
};

static HMODULE g_real;
static DWORD(WINAPI *g_vsa)(LPCSTR, LPDWORD);
static BOOL(WINAPI *g_via)(LPCSTR, DWORD, DWORD, LPVOID);
static BOOL(WINAPI *g_vqa)(LPCVOID, LPCSTR, LPVOID *, PUINT);
static DWORD(WINAPI *g_vsw)(LPCWSTR, LPDWORD);
static BOOL(WINAPI *g_viw)(LPCWSTR, DWORD, DWORD, LPVOID);
static BOOL(WINAPI *g_vqw)(LPCVOID, LPCWSTR, LPVOID *, PUINT);
static int g_boot;

static int load_real(void);

static void boot(void)
{
    if (g_boot)
        return;
    g_boot = 1;
    load_real();
    apply_host();
}

static int load_real(void)
{
    fn_gsd gsd;
    fn_llw llw;
    wchar_t path[MAX_PATH];
    wchar_t name[16];
    UINT n, i;

    if (g_real)
        return 1;
    gsd = (fn_gsd)k32_fn(H_GSD);
    llw = (fn_llw)k32_fn(H_LLW);
    if (!gsd || !llw)
        return 0;
    n = gsd(path, MAX_PATH);
    if (!n || n >= MAX_PATH - 16)
        return 0;
    if (path[n - 1] != L'\\' && path[n - 1] != L'/') {
        path[n++] = L'\\';
        path[n] = 0;
    }
    dec_wn(name, 16, kNameEnc, sizeof(kNameEnc));
    for (i = 0; name[i] && n + 1 < MAX_PATH; i++)
        path[n++] = name[i];
    path[n] = 0;
    for (i = 0; i < 16; i++)
        name[i] = 0;
    g_real = llw(path);
    for (i = 0; i < n; i++)
        path[i] = 0;
    if (!g_real)
        return 0;
    g_vsa = (DWORD(WINAPI *)(LPCSTR, LPDWORD))find_exp(g_real, H_VSA);
    g_via = (BOOL(WINAPI *)(LPCSTR, DWORD, DWORD, LPVOID))find_exp(g_real, H_VIA);
    g_vqa = (BOOL(WINAPI *)(LPCVOID, LPCSTR, LPVOID *, PUINT))find_exp(g_real, H_VQA);
    g_vsw = (DWORD(WINAPI *)(LPCWSTR, LPDWORD))find_exp(g_real, H_VSW);
    g_viw = (BOOL(WINAPI *)(LPCWSTR, DWORD, DWORD, LPVOID))find_exp(g_real, H_VIW);
    g_vqw = (BOOL(WINAPI *)(LPCVOID, LPCWSTR, LPVOID *, PUINT))find_exp(g_real, H_VQW);
    return (g_vsa && g_via && g_vqa && g_vsw && g_viw && g_vqw) ? 1 : 0;
}

DWORD WINAPI FwdGetFileVersionInfoSizeA(LPCSTR f, LPDWORD h)
{
    boot();
    if (!g_vsa)
        return 0;
    return g_vsa(f, h);
}

BOOL WINAPI FwdGetFileVersionInfoA(LPCSTR f, DWORD a, DWORD b, LPVOID c)
{
    boot();
    if (!g_via)
        return FALSE;
    return g_via(f, a, b, c);
}

BOOL WINAPI FwdVerQueryValueA(LPCVOID a, LPCSTR b, LPVOID *c, PUINT d)
{
    boot();
    if (!g_vqa)
        return FALSE;
    return g_vqa(a, b, c, d);
}

DWORD WINAPI FwdGetFileVersionInfoSizeW(LPCWSTR f, LPDWORD h)
{
    boot();
    if (!g_vsw)
        return 0;
    return g_vsw(f, h);
}

BOOL WINAPI FwdGetFileVersionInfoW(LPCWSTR f, DWORD a, DWORD b, LPVOID c)
{
    boot();
    if (!g_viw)
        return FALSE;
    return g_viw(f, a, b, c);
}

BOOL WINAPI FwdVerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID *c, PUINT d)
{
    boot();
    if (!g_vqw)
        return FALSE;
    return g_vqw(a, b, c, d);
}

BOOL WINAPI DllMain(HINSTANCE hi, DWORD reason, LPVOID reserved)
{
    typedef BOOL(WINAPI *fn_dtl)(HMODULE);
    fn_dtl dtl;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        dtl = (fn_dtl)k32_fn(H_DTL);
        if (dtl)
            dtl(hi);
    }
    return TRUE;
}
