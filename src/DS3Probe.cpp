// ============================================================================
// DS3Probe v3 - прокси dinput8.dll для Dead Space 3. Ничего не чинит: собирает данные и (по F9)
// подменяет вход игры, чтобы локализовать причину "отрицательного ускорения".
//
// Что нового относительно v2 (все пункты - из аудита 2026-10-07, раздел 6):
//  1. Профиль сборки по MD5 exe зашит в DLL (сейчас 1.0.0.1): cfg для неё НЕ нужен. cfg ищется как
//     ds3probe_<md5>.cfg, затем ds3probe.cfg; он может переопределять профиль. Строгий разбор:
//     любая ошибка в cfg (опечатка в адресе, неизвестный ключ) = exe-хуки не ставятся вообще.
//  2. Хук ставится только если .bytes заданы и совпали с памятью (без байт - хук пропущен).
//     Данные (AccDX/AccDY) проверяются на принадлежность образу exe и читаемость.
//  3. Версионно-независимый якорь: экспорт ?Init@Mouse@Windows@EARS@@YAXXZ (тело = mov [slot], Mouse_GetState)
//     даёт Mouse_GetState и адрес аккумулятора БЕЗ cfg; с профилем/cfg сверяется (расхождение = хук пропущен).
//  4. F9 переключает режим на входе Mouse_GetState: PASS (как есть) -> RAW (аккумулятор := Raw Input * RawScale)
//     -> ZERO (аккумулятор := 0). В CSV пишутся и "что дала игра" (game_*), и "что мы подставили" (out_*).
//  5. Пары raw/game сняты в один момент: raw снимается в хуке Mouse_WndMsg на WM_MOUSEMOVE (тот же
//     момент, когда игра считает дельту курсора), а не позже в Mouse_GetState. Если хук WndMsg не работает -
//     запасной вариант "direct" (как в v2), он отмечается в CSV.
//  6. InputMapper_Update: ловим this=ecx, читаем [this+offSens] и MouseState=[this+offMouseState]
//     (lookX/lookY). Это одновременно самопроверка смещений: если значения непохожи на правду, проба
//     сама отключает эту часть и пишет почему. Видно ли равенство MouseState == [mgr]+0x540 - в логе.
//  7. Условия опыта пишутся в лог и в шапку каждого CSV: клиентская область, разрешение/частота рабочего
//     стола, "повышенная точность" и скорость указателя Windows, DPI-режим, g_virtW/H, строки mouse/smooth
//     из general.txt, FPS (по интервалам Mouse_GetState), режим F9.
//  8. Каждая сессия пишет в свою папку ds3probe_logs\ГГГГММДД_ЧЧММСС\ (лог, CSV): ничего не затирается.
//     В лог пишутся версия DLL (git SHA), MD5 и PE TimeDateStamp exe, источник каждого адреса.
//  9. Звук: F7 - 1 писк, F8 - 2 писка, F9 - 1/2/3 писка (PASS/RAW/ZERO), ошибка - низкий тон.
//
// Хоткеи (работают, только когда окно игры в фокусе):
//   F6 - маркер + таблица "кто вызывает user32"    F7/F8 - начало/конец захвата (CSV + итоги в лог)
//   F9 - режим PASS/RAW/ZERO                       F10   - записать условия опыта в лог
//
// Сборка: GitHub Actions (см. CMakeLists.txt и .github/workflows/build.yml). MSVC, Win32, статический CRT.
// ВНИМАНИЕ: автор не мог собрать этот файл (в его среде нет Windows-тулчейна); проверен только разбор
// clang -fsyntax-only с самодельными заглушками заголовков. Если Actions выдаст ошибку - пришли текст.
// ============================================================================
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX
#include <Windows.h>
#include <wincrypt.h>
#include <intrin.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "safetyhook/safetyhook.hpp"
#include "dllmain.hpp" // из MarkerPatch/src: struct dinput8 + naked-переходники (экспорты)

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#ifndef DS3PROBE_GIT_SHA
#define DS3PROBE_GIT_SHA "unknown"
#endif
#define DS3PROBE_VERSION "v3"

namespace opt
{
	constexpr int kVkMarker = VK_F6;
	constexpr int kVkStart  = VK_F7;
	constexpr int kVkStop   = VK_F8;
	constexpr int kVkMode   = VK_F9;
	constexpr int kVkInfo   = VK_F10;
	constexpr int kMaxFirstLogs = 12;      // сколько первых вызовов каждого API писать подробно
	constexpr int kWaitD3D9MaxMs = 30000;  // задержка перед mid-хуками exe: ждём d3d9 (+1.5 с)
	constexpr int kMapperGiveUp = 240;     // столько вызовов InputMapper без единого правдоподобного MouseState -> отключить
	constexpr double kModeAutoRevertMs = 120000.0; // RAW/ZERO сами возвращаются в PASS через 2 минуты
}

// ----------------------------------------------------------------------------
// Общие утилиты
// ----------------------------------------------------------------------------
static HMODULE   g_self = nullptr;
static uintptr_t g_exeBase = 0, g_imageBase = 0;
static uint32_t  g_timeDateStamp = 0, g_sizeOfImage = 0;
static LARGE_INTEGER g_freq, g_t0;
static FILE* g_log = nullptr;
static std::mutex g_logMu;
static std::wstring g_exePath, g_exeDir, g_sessionDir;
static std::string g_md5; // нижний регистр, заполняется в потоке пробы

static double NowMs()
{
	LARGE_INTEGER c;
	QueryPerformanceCounter(&c);
	return double(c.QuadPart - g_t0.QuadPart) * 1000.0 / double(g_freq.QuadPart);
}

static void Log(const char* fmt, ...)
{
	std::lock_guard<std::mutex> lk(g_logMu);
	if (!g_log) return;
	fprintf(g_log, "[%9.3f] ", NowMs() / 1000.0);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(g_log, fmt, ap);
	va_end(ap);
	fputc('\n', g_log);
	fflush(g_log);
}

static std::wstring SessionPath(const wchar_t* name) { return g_sessionDir + L"\\" + name; }
static std::wstring ExePath(const wchar_t* name) { return g_exeDir + L"\\" + name; }

static bool MakeDir(const std::wstring& p) { return CreateDirectoryW(p.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS; }

// Папка сессии: <exe>\ds3probe_logs\ГГГГММДД_ЧЧММСС (если нельзя писать в папку игры - %TEMP%)
static void OpenSession()
{
	wchar_t exe[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, exe, MAX_PATH);
	g_exePath = exe;
	const size_t p = g_exePath.find_last_of(L'\\');
	g_exeDir = (p == std::wstring::npos) ? L"." : g_exePath.substr(0, p);

	SYSTEMTIME st;
	GetLocalTime(&st);
	wchar_t stamp[64];
	swprintf(stamp, 64, L"%04d%02d%02d_%02d%02d%02d", (int)st.wYear, (int)st.wMonth, (int)st.wDay, (int)st.wHour, (int)st.wMinute, (int)st.wSecond);

	auto tryBase = [&](const std::wstring& base) -> bool
	{
		const std::wstring root = base + L"\\ds3probe_logs";
		if (!MakeDir(root)) return false;
		const std::wstring dir = root + L"\\" + stamp;
		if (!MakeDir(dir)) return false;
		FILE* f = nullptr;
		_wfopen_s(&f, (dir + L"\\ds3probe.log").c_str(), L"wt");
		if (!f) return false;
		g_log = f;
		g_sessionDir = dir;
		// указатель на последнюю сессию - чтобы не искать папку глазами
		FILE* l = nullptr;
		_wfopen_s(&l, (root + L"\\latest.txt").c_str(), L"wt");
		if (l) { fprintf(l, "%ls\n", dir.c_str()); fclose(l); }
		return true;
	};
	if (tryBase(g_exeDir)) return;
	wchar_t t[MAX_PATH] = {};
	GetTempPathW(MAX_PATH, t);
	std::wstring tmp = t;
	while (!tmp.empty() && (tmp.back() == L'\\' || tmp.back() == L'/')) tmp.pop_back();
	tryBase(tmp);
}

// Единственные функции с SEH (в них нельзя держать объекты с деструкторами)
static bool ReadBytes(uintptr_t addr, void* out, size_t n)
{
	__try { memcpy(out, reinterpret_cast<const void*>(addr), n); return true; }
	__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static bool WriteBytes(uintptr_t addr, const void* in, size_t n)
{
	__try { memcpy(reinterpret_cast<void*>(addr), in, n); return true; }
	__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
template <class T> static bool ReadT(uintptr_t addr, T* out) { return ReadBytes(addr, out, sizeof(T)); }
template <class T> static bool WriteT(uintptr_t addr, const T& v) { return WriteBytes(addr, &v, sizeof(T)); }

// Адрес из Ghidra-проекта (база образа + RVA) -> адрес в процессе. Верно для нерелоцируемого exe (у DS3 так).
static uintptr_t Rebase(uintptr_t ghidraAddr) { return g_exeBase + (ghidraAddr - g_imageBase); }
static bool InImage(uintptr_t runtimeAddr) { return runtimeAddr >= g_exeBase && runtimeAddr < g_exeBase + g_sizeOfImage; }
static bool PlausiblePtr(uint32_t p) { return p >= 0x10000u && p < 0x7FFE0000u; }
static bool FiniteF(float f, float lim = 1.0e7f) { return std::isfinite(f) && std::fabs(f) < lim; }

// "exe+0x... [ghidra 0040CC20]" или "d3d9.dll+0x..."
static std::string Where(const void* addr)
{
	char buf[320];
	HMODULE m = nullptr;
	const uintptr_t a = reinterpret_cast<uintptr_t>(addr);
	if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		reinterpret_cast<LPCWSTR>(addr), &m) && m)
	{
		if (reinterpret_cast<uintptr_t>(m) == g_exeBase)
			snprintf(buf, sizeof(buf), "exe+0x%X [ghidra %08X]", (unsigned)(a - g_exeBase), (unsigned)(a - g_exeBase + g_imageBase));
		else
		{
			wchar_t name[MAX_PATH] = {};
			GetModuleFileNameW(m, name, MAX_PATH);
			const wchar_t* b = wcsrchr(name, L'\\');
			snprintf(buf, sizeof(buf), "%ls+0x%X", b ? b + 1 : name, (unsigned)(a - reinterpret_cast<uintptr_t>(m)));
		}
	}
	else
		snprintf(buf, sizeof(buf), "%08X [unknown module]", (unsigned)a);
	return buf;
}

static bool GameFocused()
{
	DWORD pid = 0;
	GetWindowThreadProcessId(GetForegroundWindow(), &pid);
	return pid == GetCurrentProcessId();
}

struct Config; // ниже; Tone читает флаг Beeps
static bool BeepsEnabled();

static void Tone(int n, int freq)
{
	if (!BeepsEnabled()) return;
	for (int i = 0; i < n; ++i)
	{
		Beep((DWORD)freq, 70);
		if (i + 1 < n) Sleep(60);
	}
}

// ----------------------------------------------------------------------------
// MD5 файла exe (CryptoAPI): идентификатор сборки, по нему выбирается профиль
// ----------------------------------------------------------------------------
static std::string ComputeFileMd5(const std::wstring& path)
{
	std::string res;
	HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
	if (h == INVALID_HANDLE_VALUE) return res;
	HCRYPTPROV prov = 0;
	HCRYPTHASH hash = 0;
	if (CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) && CryptCreateHash(prov, CALG_MD5, 0, 0, &hash))
	{
		std::vector<BYTE> buf(1u << 20);
		DWORD n = 0;
		bool ok = true;
		while (ReadFile(h, buf.data(), (DWORD)buf.size(), &n, nullptr) && n)
			if (!CryptHashData(hash, buf.data(), n, 0)) { ok = false; break; }
		BYTE d[16] = {};
		DWORD len = sizeof(d);
		if (ok && CryptGetHashParam(hash, HP_HASHVAL, d, &len, 0) && len == 16)
		{
			char s[40] = {};
			for (int i = 0; i < 16; ++i) snprintf(s + i * 2, 3, "%02x", (unsigned)d[i]);
			res = s;
		}
	}
	if (hash) CryptDestroyHash(hash);
	if (prov) CryptReleaseContext(prov, 0);
	CloseHandle(h);
	return res;
}

// ----------------------------------------------------------------------------
// Профили сборок (адреса в системе координат Ghidra этой же сборки) и конфиг
// ----------------------------------------------------------------------------
struct Resolved
{
	uintptr_t mgs = 0, poll = 0, wnd = 0, mapper = 0;                 // функции
	std::string bMgs, bPoll, bWnd, bMapper;                          // ожидаемые байты начала (обязательны для хука)
	uintptr_t accDX = 0, accDY = 0, flagCap = 0, flagRc = 0;         // данные
	uintptr_t virtW = 0, virtH = 0;                                  // g_virtW/H (рабочие имена; только для лога)
	uintptr_t mgrPtr = 0;                                            // указатель на менеджер устройств (DAT_011ac914 в 1.0.0.0)
	const char* profile = "none";
};

// 1.0.0.1, MD5 1802f17a2cc1c2797323632862c6fb1f. Функции: ds3_sigs_found.txt; аккумуляторы: fild [011D1DD0] в
// Mouse_GetState; g_virtW/H: декомпиляция FUN_0040cfe0; mgrPtr: DAT_011d1914 виден в FUN_0040e080 (сдвиг +0x25000).
static Resolved MakeProfile1001()
{
	Resolved r;
	r.profile = "1.0.0.1";
	r.mgs = 0x0040A820;    r.bMgs    = "55 8B EC DB 05 D0 1D 1D 01 8B 45 08";
	r.poll = 0x0040CE30;   r.bPoll   = "55 8B EC 83 EC 28 56 8B 35 F4 1D 1D";
	r.wnd = 0x0040D270;    r.bWnd    = "55 8B EC 8B 45 08 83 EC 28 53 8B 5D";
	r.mapper = 0x00ACB780; r.bMapper = "55 8B EC 83 EC 18 53 56 57 8B 7D 10";
	r.accDX = 0x011D1DD0;  r.accDY = 0x011D1DD4;
	r.flagCap = 0x011D1DCE; r.flagRc = 0x011D1DEE;
	r.virtW = 0x0133B0A8;  r.virtH = 0x0133B0AC;
	r.mgrPtr = 0x011D1914;
	return r;
}

struct Profile { const char* name; const char* md5; Resolved (*make)(); };
static const Profile kProfiles[] =
{
	{ "1.0.0.1", "1802f17a2cc1c2797323632862c6fb1f", &MakeProfile1001 },
};

struct CfgAddr  { bool set = false; uintptr_t v = 0; };
struct CfgBytes { bool set = false; std::string v; };
struct Config
{
	std::wstring file;           // какой файл прочитан
	int errors = 0;
	bool hasBuild = false; uint32_t build = 0; std::string md5;
	bool exeHooks = true, anchor = true, beeps = true;
	double rawScale = 1.0;
	uintptr_t offSens = 0x17C, offMouseState = 0x18C;
	CfgAddr mgs, poll, wnd, mapper, accDX, accDY, flagCap, flagRc, virtW, virtH, mgrPtr;
	CfgBytes bMgs, bPoll, bWnd, bMapper;
};
static Config g_cfg;
static Resolved g_r;
static bool g_anchorConflict = false;
static bool BeepsEnabled() { return g_cfg.beeps; }

static std::string Trim(const std::string& s)
{
	const size_t a = s.find_first_not_of(" \t\r\n");
	if (a == std::string::npos) return "";
	return s.substr(a, s.find_last_not_of(" \t\r\n") - a + 1);
}
static std::string Lower(std::string s) { for (char& c : s) c = (char)tolower((unsigned char)c); return s; }
static int HexVal(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}
// Строгий разбор: только hex-цифры, 1..8 знаков, допустим префикс 0x ("0040A82O" с буквой O - ошибка, а не 0x40A82)
static bool ParseHex32(std::string s, uintptr_t* out)
{
	if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.erase(0, 2);
	if (s.empty() || s.size() > 8) return false;
	uint32_t v = 0;
	for (char c : s) { const int d = HexVal(c); if (d < 0) return false; v = v * 16 + (uint32_t)d; }
	*out = v;
	return true;
}
static bool ParseBool(const std::string& s, bool* out)
{
	const std::string l = Lower(s);
	if (l == "1" || l == "on" || l == "yes" || l == "true") { *out = true; return true; }
	if (l == "0" || l == "off" || l == "no" || l == "false") { *out = false; return true; }
	return false;
}
static bool ParseDouble(const std::string& s, double* out)
{
	char* end = nullptr;
	const double d = strtod(s.c_str(), &end);
	if (end == s.c_str() || *end != '\0' || !std::isfinite(d)) return false;
	*out = d;
	return true;
}
// "55 8B EC ?? 8B" -> {0x55,0x8B,0xEC,-1,0x8B}; строго по два hex-знака или ?/??
static bool ParsePattern(const std::string& s, std::vector<int>& pat)
{
	pat.clear();
	std::istringstream is(s);
	std::string t;
	while (is >> t)
	{
		if (t == "?" || t == "??") { pat.push_back(-1); continue; }
		if (t.size() != 2 || HexVal(t[0]) < 0 || HexVal(t[1]) < 0) return false;
		pat.push_back(HexVal(t[0]) * 16 + HexVal(t[1]));
	}
	return !pat.empty();
}

static bool ReadWholeFile(const std::wstring& path, std::string& out)
{
	FILE* f = nullptr;
	_wfopen_s(&f, path.c_str(), L"rb");
	if (!f) return false;
	char buf[4096];
	size_t n;
	out.clear();
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
	fclose(f);
	if (out.size() >= 3 && (uint8_t)out[0] == 0xEF && (uint8_t)out[1] == 0xBB && (uint8_t)out[2] == 0xBF) out.erase(0, 3); // BOM
	return true;
}

static void CfgErr(int line, const std::string& key, const char* why)
{
	++g_cfg.errors;
	Log("cfg line %d, key '%s': %s", line, key.c_str(), why);
}

// ds3probe_<md5>.cfg -> ds3probe.cfg. Формат "ключ = значение", '#' - комментарий. Числа - hex.
//   MD5 = <32 hex>     Build = <TimeDateStamp hex>   (необязательно; при несовпадении exe-хуки не ставятся)
//   MouseGetState / PollMouseCursor / WndMsg / InputMapper = адрес НАЧАЛА функции;   <имя>.bytes = байты (?? - любой)
//   AccDX AccDY FlagCaptured FlagRecenter VirtW VirtH MgrPtr = адреса данных
//   ExeHooks = 0/1   Anchor = 0/1   Beeps = 0/1   RawScale = 1.0   OffSens = 17C   OffMouseState = 18C
static void LoadConfig()
{
	std::string text;
	std::wstring path = ExePath((L"ds3probe_" + std::wstring(g_md5.begin(), g_md5.end()) + L".cfg").c_str());
	if (!ReadWholeFile(path, text))
	{
		path = ExePath(L"ds3probe.cfg");
		if (!ReadWholeFile(path, text)) { Log("cfg: none (looked for ds3probe_<md5>.cfg and ds3probe.cfg next to the exe) - using built-in profile only"); return; }
	}
	g_cfg.file = path;
	Log("cfg: reading %ls", path.c_str());

	std::istringstream is(text);
	std::string raw;
	int ln = 0;
	while (std::getline(is, raw))
	{
		++ln;
		std::string s = raw;
		const size_t h = s.find('#');
		if (h != std::string::npos) s.erase(h);
		s = Trim(s);
		if (s.empty()) continue;
		const size_t eq = s.find('=');
		if (eq == std::string::npos) { CfgErr(ln, s, "no '=' in the line"); continue; }
		const std::string k = Lower(Trim(s.substr(0, eq))), v = Trim(s.substr(eq + 1));
		if (k.empty() || v.empty()) { CfgErr(ln, k, "empty key or value"); continue; }

		auto addr = [&](CfgAddr& a) { uintptr_t n = 0; if (ParseHex32(v, &n)) { a.set = true; a.v = n; } else CfgErr(ln, k, "expected a hex address (1-8 hex digits)"); };
		auto bytes = [&](CfgBytes& b) { std::vector<int> p; if (ParsePattern(v, p)) { b.set = true; b.v = v; } else CfgErr(ln, k, "expected bytes like '55 8B EC ?? 8B'"); };
		auto flag = [&](bool& b) { if (!ParseBool(v, &b)) CfgErr(ln, k, "expected 0 or 1"); };

		if (k == "md5") { if (v.size() == 32) g_cfg.md5 = Lower(v); else CfgErr(ln, k, "expected 32 hex digits"); }
		else if (k == "build") { uintptr_t n = 0; if (ParseHex32(v, &n)) { g_cfg.hasBuild = true; g_cfg.build = (uint32_t)n; } else CfgErr(ln, k, "expected TimeDateStamp in hex"); }
		else if (k == "mousegetstate") addr(g_cfg.mgs);
		else if (k == "pollmousecursor") addr(g_cfg.poll);
		else if (k == "wndmsg") addr(g_cfg.wnd);
		else if (k == "inputmapper") addr(g_cfg.mapper);
		else if (k == "mousegetstate.bytes") bytes(g_cfg.bMgs);
		else if (k == "pollmousecursor.bytes") bytes(g_cfg.bPoll);
		else if (k == "wndmsg.bytes") bytes(g_cfg.bWnd);
		else if (k == "inputmapper.bytes") bytes(g_cfg.bMapper);
		else if (k == "accdx") addr(g_cfg.accDX);
		else if (k == "accdy") addr(g_cfg.accDY);
		else if (k == "flagcaptured") addr(g_cfg.flagCap);
		else if (k == "flagrecenter") addr(g_cfg.flagRc);
		else if (k == "virtw") addr(g_cfg.virtW);
		else if (k == "virth") addr(g_cfg.virtH);
		else if (k == "mgrptr") addr(g_cfg.mgrPtr);
		else if (k == "exehooks") flag(g_cfg.exeHooks);
		else if (k == "anchor") flag(g_cfg.anchor);
		else if (k == "beeps") flag(g_cfg.beeps);
		else if (k == "rawscale") { double d = 0; if (ParseDouble(v, &d) && d > 0.0 && d < 100.0) g_cfg.rawScale = d; else CfgErr(ln, k, "expected a number in (0,100)"); }
		else if (k == "offsens") { uintptr_t n = 0; if (ParseHex32(v, &n) && n < 0x10000) g_cfg.offSens = n; else CfgErr(ln, k, "expected hex offset < 0x10000"); }
		else if (k == "offmousestate") { uintptr_t n = 0; if (ParseHex32(v, &n) && n < 0x10000) g_cfg.offMouseState = n; else CfgErr(ln, k, "expected hex offset < 0x10000"); }
		else CfgErr(ln, k, "unknown key");
	}
	Log("cfg: parsed, %d error(s)%s", g_cfg.errors, g_cfg.errors ? " -> exe hooks will NOT be installed until the cfg is fixed" : "");
}

static void ApplyCfg(Resolved& r)
{
	auto fn = [](const CfgAddr& a, uintptr_t& dst, std::string& by, const CfgBytes& cb)
	{
		if (a.set) { if (dst != a.v) by.clear(); dst = a.v; } // новый адрес: старые байты относились к другому месту
		if (cb.set) by = cb.v;
	};
	fn(g_cfg.mgs, r.mgs, r.bMgs, g_cfg.bMgs);
	fn(g_cfg.poll, r.poll, r.bPoll, g_cfg.bPoll);
	fn(g_cfg.wnd, r.wnd, r.bWnd, g_cfg.bWnd);
	fn(g_cfg.mapper, r.mapper, r.bMapper, g_cfg.bMapper);
	auto d = [](const CfgAddr& a, uintptr_t& dst) { if (a.set) dst = a.v; };
	d(g_cfg.accDX, r.accDX); d(g_cfg.accDY, r.accDY); d(g_cfg.flagCap, r.flagCap); d(g_cfg.flagRc, r.flagRc);
	d(g_cfg.virtW, r.virtW); d(g_cfg.virtH, r.virtH); d(g_cfg.mgrPtr, r.mgrPtr);
}

// ----------------------------------------------------------------------------
// Якорь, не зависящий от сборки: экспорт ?Init@Mouse@Windows@EARS@@YAXXZ
//   тело: C7 05 <slot> <Mouse_GetState> C3  (mov [g_pfnMouseGetState], Mouse_GetState; ret)
//   Mouse_GetState начинается с  55 8B EC DB 05 <addr g_mouseDX>  (fild dword [g_mouseDX])
// ----------------------------------------------------------------------------
struct Anchor { bool ok = false; uintptr_t mgs = 0, accDX = 0; std::string note; };

static uint32_t Rd32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }

static Anchor ResolveAnchor()
{
	Anchor a;
	FARPROC init = GetProcAddress(reinterpret_cast<HMODULE>(g_exeBase), "?Init@Mouse@Windows@EARS@@YAXXZ");
	if (!init) { a.note = "export ?Init@Mouse@Windows@EARS@@YAXXZ not found"; return a; }
	uint8_t b[24] = {};
	if (!ReadBytes(reinterpret_cast<uintptr_t>(init), b, sizeof(b))) { a.note = "Init unreadable"; return a; }
	char hex[24 * 3 + 1] = {};
	for (int i = 0; i < 24; ++i) snprintf(hex + i * 3, 4, "%02X ", (unsigned)b[i]);
	size_t o = (b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC) ? 3 : 0;
	if (b[o] != 0xC7 || b[o + 1] != 0x05) { a.note = std::string("Init body is not 'mov [slot],func': ") + hex; return a; }
	const uint32_t slot = Rd32(b + o + 2), func = Rd32(b + o + 6);
	if (!InImage(slot) || !InImage(func)) { a.note = std::string("slot/func outside the exe image: ") + hex; return a; }
	uint8_t f[12] = {};
	if (!ReadBytes(func, f, sizeof(f))) { a.note = "Mouse_GetState candidate unreadable"; return a; }
	if (!(f[0] == 0x55 && f[1] == 0x8B && f[2] == 0xEC && f[3] == 0xDB && f[4] == 0x05)) { a.note = "candidate does not start with '55 8B EC DB 05' (fild [acc])"; return a; }
	const uint32_t acc = Rd32(f + 5);
	if (!InImage(acc)) { a.note = "accumulator address outside the exe image"; return a; }
	a.ok = true;
	a.mgs = func - g_exeBase + g_imageBase;
	a.accDX = acc - g_exeBase + g_imageBase;
	char n[160];
	snprintf(n, sizeof(n), "Init=%08X slot=%08X -> Mouse_GetState=%08X, g_mouseDX=%08X", (unsigned)(reinterpret_cast<uintptr_t>(init) - g_exeBase + g_imageBase),
		(unsigned)(slot - g_exeBase + g_imageBase), (unsigned)a.mgs, (unsigned)a.accDX);
	a.note = n;
	return a;
}

static void ResolveTargets()
{
	g_r = Resolved{};
	for (const Profile& p : kProfiles)
		if (!g_md5.empty() && g_md5 == p.md5) { g_r = p.make(); Log("profile: %s selected by MD5", p.name); }
	if (std::string(g_r.profile) == "none") Log("profile: none (MD5 %s is not in the built-in table)", g_md5.empty() ? "?" : g_md5.c_str());
	ApplyCfg(g_r);

	if (g_cfg.anchor)
	{
		const Anchor a = ResolveAnchor();
		Log("anchor: %s%s", a.ok ? "OK: " : "FAILED: ", a.note.c_str());
		if (a.ok)
		{
			if (g_r.mgs && g_r.mgs != a.mgs) { g_anchorConflict = true; Log("anchor: MISMATCH with profile/cfg Mouse_GetState=%08X -> Mouse_GetState hook and Acc* disabled", (unsigned)g_r.mgs); }
			else if (!g_r.mgs) { g_r.mgs = a.mgs; g_r.bMgs = "55 8B EC DB 05 ?? ?? ?? ?? 8B 45 08"; Log("anchor: Mouse_GetState taken from the anchor"); }
			else Log("anchor: confirms Mouse_GetState=%08X independently of the profile", (unsigned)g_r.mgs);
			if (!g_anchorConflict)
			{
				if (!g_r.accDX) { g_r.accDX = a.accDX; g_r.accDY = a.accDX + 4; Log("anchor: AccDX=%08X from fild operand; AccDY assumed = AccDX+4 (not verified)", (unsigned)a.accDX); }
				else if (g_r.accDX != a.accDX) { g_anchorConflict = true; Log("anchor: MISMATCH AccDX profile/cfg=%08X vs fild operand=%08X -> Acc* disabled", (unsigned)g_r.accDX, (unsigned)a.accDX); }
				else Log("anchor: confirms AccDX=%08X", (unsigned)g_r.accDX);
			}
		}
	}
	if (g_anchorConflict) { g_r.mgs = 0; g_r.accDX = g_r.accDY = 0; }

	Log("targets (Ghidra address space; every hook also requires its .bytes to match memory):");
	Log("  Mouse_GetState=%08X  PollMouseCursor=%08X  WndMsg=%08X  InputMapper=%08X", (unsigned)g_r.mgs, (unsigned)g_r.poll, (unsigned)g_r.wnd, (unsigned)g_r.mapper);
	Log("  AccDX=%08X AccDY=%08X FlagCaptured=%08X FlagRecenter=%08X VirtW=%08X VirtH=%08X MgrPtr=%08X",
		(unsigned)g_r.accDX, (unsigned)g_r.accDY, (unsigned)g_r.flagCap, (unsigned)g_r.flagRc, (unsigned)g_r.virtW, (unsigned)g_r.virtH, (unsigned)g_r.mgrPtr);
}

// ----------------------------------------------------------------------------
// Счётчики
// ----------------------------------------------------------------------------
enum Counter
{
	C_MouseGetState, C_WndMsgAll, C_WndMouseMove, C_PollMouseCursor, C_InputMapper,
	C_GetCursorPos, C_SetCursorPos, C_ClipCursor, C_ShowCursor,
	C_DI_Create, C_DI_MouseState, C_DI_MouseData, C_DI_MouseEvents, C_DI_OtherState, C_DI_OtherData,
	C_RawEvents,
	C_COUNT
};
static const char* kCounterName[C_COUNT] =
{
	"MouseGetState", "WndMsg", "WndMouseMove", "PollMouseCursor", "InputMapper",
	"GetCursorPos", "SetCursorPos", "ClipCursor", "ShowCursor",
	"DI8Create", "DI_mouse_State", "DI_mouse_Data", "DI_mouse_events", "DI_other_State", "DI_other_Data",
	"raw_events"
};
static std::atomic<uint64_t> g_cnt[C_COUNT];
static std::atomic<int> g_firstLogged[C_COUNT];
static uint64_t g_cntPrev[C_COUNT];

static std::mutex g_callMu;
static std::unordered_map<uintptr_t, uint64_t> g_callers[C_COUNT];

static void Count(Counter id, uint64_t n = 1) { g_cnt[id].fetch_add(n, std::memory_order_relaxed); }
static bool FirstN(Counter id) { return g_firstLogged[id].fetch_add(1, std::memory_order_relaxed) < opt::kMaxFirstLogs; }
static void NoteCaller(Counter id, void* ra)
{
	std::lock_guard<std::mutex> lk(g_callMu);
	++g_callers[id][reinterpret_cast<uintptr_t>(ra)];
}

// ----------------------------------------------------------------------------
// Режим подмены входа (F9)
// ----------------------------------------------------------------------------
enum Mode { M_PASS = 0, M_RAW = 1, M_ZERO = 2 };
static const char* kModeName[3] = { "PASS", "RAW", "ZERO" };
static std::atomic<int> g_mode{ M_PASS };
static std::atomic<double> g_modeSince{ 0.0 };

// ----------------------------------------------------------------------------
// Сырой ввод (эталон) и захват
// ----------------------------------------------------------------------------
// Счёты Raw Input, пришедшие в поток пробы, но ещё не "отданные" ни одному кадру
static std::atomic<LONG> g_rawPairAccX{ 0 }, g_rawPairAccY{ 0 };
// Счёты, снятые в момент WM_MOUSEMOVE (в хуке Mouse_WndMsg): именно они парятся с аккумулятором игры
static std::atomic<LONG> g_pendRawX{ 0 }, g_pendRawY{ 0 };
static std::atomic<bool> g_wmMoveEver{ false };
static std::atomic<LONG> g_rawPairDiX{ 0 }, g_rawPairDiY{ 0 }; // для _di.csv
static std::atomic<LONG> g_rawRepX{ 0 }, g_rawRepY{ 0 };       // секундная сводка
static std::atomic<LONG> g_rawCapX{ 0 }, g_rawCapY{ 0 };       // за время захвата
static std::atomic<LONG> g_diCapX{ 0 }, g_diCapY{ 0 };

struct Sample
{
	double t = 0;
	LONG rx = 0, ry = 0;      // Raw Input, спаренный с кадром
	int gx = 0, gy = 0;       // что игра накопила (аккумулятор до подмены)
	int ox = 0, oy = 0;       // что игра получила на самом деле (после подмены; в PASS = g*)
	int mode = 0;
	bool lookValid = false;
	float lx = 0, ly = 0, sens = 0;
	uint8_t cap = 255, rc = 255;
};
static std::atomic<bool> g_capturing{ false };
static std::mutex g_capMu;
static std::vector<Sample> g_samplesAcc, g_samplesDi;
static int g_capIndex = 0;
static double g_capStart = 0;
static std::string g_capMeta;           // строки "# ..." для шапки CSV
static int g_capClientW = 0, g_capClientH = 0;

static LRESULT CALLBACK RawWndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
	if (m == WM_INPUT)
	{
		UINT size = 0;
		GetRawInputData(reinterpret_cast<HRAWINPUT>(l), RID_INPUT, nullptr, &size, sizeof(RAWINPUTHEADER));
		if (size && size <= 256)
		{
			alignas(8) BYTE buf[256];
			if (GetRawInputData(reinterpret_cast<HRAWINPUT>(l), RID_INPUT, buf, &size, sizeof(RAWINPUTHEADER)) != (UINT)-1)
			{
				const RAWINPUT* ri = reinterpret_cast<const RAWINPUT*>(buf);
				if (ri->header.dwType == RIM_TYPEMOUSE && !(ri->data.mouse.usFlags & MOUSE_MOVE_ABSOLUTE) && GameFocused())
				{
					const LONG x = ri->data.mouse.lLastX, y = ri->data.mouse.lLastY;
					if (x || y)
					{
						Count(C_RawEvents);
						g_rawPairAccX += x; g_rawPairAccY += y;
						g_rawPairDiX += x;  g_rawPairDiY += y;
						g_rawRepX += x;     g_rawRepY += y;
						if (g_capturing.load()) { g_rawCapX += x; g_rawCapY += y; }
					}
				}
			}
		}
	}
	return DefWindowProcW(h, m, w, l); // для WM_INPUT вызов обязателен
}

static DWORD WINAPI RawThread(LPVOID)
{
	WNDCLASSEXW wc = {};
	wc.cbSize = sizeof(wc);
	wc.lpfnWndProc = RawWndProc;
	wc.hInstance = g_self;
	wc.lpszClassName = L"DS3ProbeRaw";
	RegisterClassExW(&wc);
	// Скрытое окно верхнего уровня (не показываем): надёжнее, чем message-only
	HWND hw = CreateWindowExW(WS_EX_TOOLWINDOW, wc.lpszClassName, L"", WS_POPUP, 0, 0, 0, 0, nullptr, nullptr, g_self, nullptr);
	RAWINPUTDEVICE rid = {};
	rid.usUsagePage = 0x01;
	rid.usUsage = 0x02;
	rid.dwFlags = RIDEV_INPUTSINK;
	rid.hwndTarget = hw;
	const BOOL ok = hw && RegisterRawInputDevices(&rid, 1, sizeof(rid));
	Log("RawInput thread: hwnd=%p register=%d", (void*)hw, (int)ok);
	MSG msg;
	while (GetMessageW(&msg, nullptr, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
	return 0;
}

// ----------------------------------------------------------------------------
// Условия опыта: без них отношение acc/raw не интерпретируется (аудит, п. 6.4)
// ----------------------------------------------------------------------------
struct WinInfo { HWND h = nullptr; int cw = 0, ch = 0; DWORD style = 0; };

static BOOL CALLBACK EnumWinProc(HWND h, LPARAM lp)
{
	DWORD pid = 0;
	GetWindowThreadProcessId(h, &pid);
	if (pid != GetCurrentProcessId() || !IsWindowVisible(h) || GetWindow(h, GW_OWNER)) return TRUE;
	RECT rc;
	if (!GetClientRect(h, &rc)) return TRUE;
	WinInfo* w = reinterpret_cast<WinInfo*>(lp);
	const int cw = rc.right - rc.left, ch = rc.bottom - rc.top;
	if ((long long)cw * ch > (long long)w->cw * w->ch)
	{
		w->h = h; w->cw = cw; w->ch = ch;
		w->style = (DWORD)GetWindowLongW(h, GWL_STYLE);
	}
	return TRUE;
}

// строки general.txt с интересными ключами (путь по PCGamingWiki: %LOCALAPPDATA%\EA Games\Dead Space 3\general.txt)
static std::string GeneralTxtLines()
{
	wchar_t la[MAX_PATH] = {};
	if (!GetEnvironmentVariableW(L"LOCALAPPDATA", la, MAX_PATH)) return "LOCALAPPDATA not set";
	const std::wstring path = std::wstring(la) + L"\\EA Games\\Dead Space 3\\general.txt";
	std::string text;
	if (!ReadWholeFile(path, text)) return "general.txt not found (" + std::string("EA Games\\Dead Space 3") + ")";
	std::istringstream is(text);
	std::string line, out;
	int n = 0;
	while (std::getline(is, line))
	{
		const std::string l = Lower(line);
		if (l.find("mouse") == std::string::npos && l.find("smooth") == std::string::npos && l.find("vsync") == std::string::npos &&
			l.find("fps") == std::string::npos && l.find("framerate") == std::string::npos && l.find("frame") == std::string::npos) continue;
		line = Trim(line);
		if (line.size() > 100) line.resize(100);
		out += (n ? " | " : "") + line;
		if (++n >= 8) break;
	}
	return n ? out : "general.txt: no mouse/smooth/vsync/fps lines";
}

// собирает условия в одну строку; client размеры возвращает отдельно
static std::string BuildConditions(int* clientW, int* clientH)
{
	char b[512];
	std::string s;
	WinInfo w;
	EnumWindows(EnumWinProc, reinterpret_cast<LPARAM>(&w));
	if (clientW) *clientW = w.cw;
	if (clientH) *clientH = w.ch;
	snprintf(b, sizeof(b), "client=%dx%d window=%s", w.cw, w.ch, w.h ? ((w.style & WS_CAPTION) == WS_CAPTION ? "with-caption" : "no-caption(borderless/fullscreen)") : "not-found");
	s += b;

	DEVMODEW dm = {};
	dm.dmSize = sizeof(dm);
	if (EnumDisplaySettingsW(nullptr, ENUM_CURRENT_SETTINGS, &dm))
	{
		snprintf(b, sizeof(b), "; desktop=%lux%lu@%luHz", (unsigned long)dm.dmPelsWidth, (unsigned long)dm.dmPelsHeight, (unsigned long)dm.dmDisplayFrequency);
		s += b;
	}
	int m[3] = {};
	int speed = 0;
	SystemParametersInfoW(SPI_GETMOUSE, 0, m, 0);
	SystemParametersInfoW(SPI_GETMOUSESPEED, 0, &speed, 0);
	snprintf(b, sizeof(b), "; winmouse(thr1,thr2,enhance_precision)=(%d,%d,%d) speed=%d/20 (10 = slider 6/11) dpi_aware=%d", m[0], m[1], m[2], speed, (int)IsProcessDPIAware());
	s += b;

	if (g_r.virtW && g_r.virtH)
	{
		int vw = 0, vh = 0;
		if (ReadT(Rebase(g_r.virtW), &vw) && ReadT(Rebase(g_r.virtH), &vh) && vw > 100 && vw < 20000 && vh > 100 && vh < 20000)
			snprintf(b, sizeof(b), "; g_virt=(%d,%d)[working name]", vw, vh);
		else
			snprintf(b, sizeof(b), "; g_virt=n/a(%d,%d)", vw, vh);
		s += b;
	}
	s += "; general.txt: " + GeneralTxtLines();
	return s;
}

static void LogConditions(const char* why)
{
	int cw = 0, ch = 0;
	const std::string c = BuildConditions(&cw, &ch);
	Log("conditions (%s): %s", why, c.c_str());
}

// ----------------------------------------------------------------------------
// MouseState из InputMapper_Update (this=ecx): самопроверка смещений + lookX/lookY
// ----------------------------------------------------------------------------
static float g_lookX = 0, g_lookY = 0, g_sens = 0;   // пишет и читает только поток игры (читает ещё сводка - гонка безвредна)
static bool  g_lookValid = false;
static int   g_mapperBad = 0, g_mapperGood = 0;
static bool  g_mapperDead = false;

static void MgrSelfCheck(uintptr_t self, uint32_t msPtr)
{
	if (!g_r.mgrPtr) return;
	uint32_t mgr = 0;
	if (!ReadT(Rebase(g_r.mgrPtr), &mgr) || !PlausiblePtr(mgr)) { Log("  mgr: [%08X] = %08X is not a plausible pointer (MgrPtr wrong?)", (unsigned)g_r.mgrPtr, (unsigned)mgr); return; }
	uint32_t at540 = 0, slotObj = 0;
	uint8_t id574 = 0xFF, id575 = 0xFF;
	ReadT(static_cast<uintptr_t>(mgr) + 0x540, &at540);
	ReadT(static_cast<uintptr_t>(mgr) + 0x574, &id574);
	ReadT(static_cast<uintptr_t>(mgr) + 0x575, &id575);
	ReadT(static_cast<uintptr_t>(mgr) + 0x4EC + (uintptr_t)id574 * 4, &slotObj);
	Log("  mgr=%08X: [mgr+0x540]=%08X vs MouseState=%08X (%s); id574=%u id575=%u; slot[id574]=%08X vs this=%08X (%s)",
		(unsigned)mgr, (unsigned)at540, (unsigned)msPtr, at540 == msPtr ? "EQUAL" : "different",
		(unsigned)id574, (unsigned)id575, (unsigned)slotObj, (unsigned)self, slotObj == self ? "this IS the device object" : "this is another object");
}

static void OnInputMapper(uintptr_t self)
{
	Count(C_InputMapper);
	if (g_mapperDead) return;
	uint32_t msp = 0;
	float st[3] = {}, sens = 0;
	bool ok = ReadT(self + g_cfg.offMouseState, &msp) && PlausiblePtr(msp) && ReadBytes(msp, st, sizeof(st)) && ReadT(self + g_cfg.offSens, &sens);
	// sens = слайдер*1.8+0.1 -> [0.1; 1.9]; look - счёты за кадр, по модулю далеко меньше 1e5
	ok = ok && FiniteF(st[0], 1.0e5f) && FiniteF(st[1], 1.0e5f) && FiniteF(st[2], 1.0e5f) && sens >= 0.05f && sens <= 2.5f;
	if (!ok)
	{
		g_lookValid = false;
		if (++g_mapperBad >= opt::kMapperGiveUp && g_mapperGood == 0)
		{
			g_mapperDead = true;
			Log("InputMapper: this=%08X [this+%X]=%08X [this+%X]=%.4f never looked like MouseState/sens in %d calls -> MouseState capture DISABLED (check OffSens/OffMouseState or `this`)",
				(unsigned)self, (unsigned)g_cfg.offMouseState, (unsigned)msp, (unsigned)g_cfg.offSens, (double)sens, g_mapperBad);
		}
		return;
	}
	++g_mapperGood;
	g_lookX = st[0]; g_lookY = st[1]; g_sens = sens; g_lookValid = true;
	if (g_mapperGood <= 3)
	{
		Log("InputMapper #%d: this=%08X sens@+%X=%.4f MouseState=%08X look=(%.4f,%.4f) wheel=%.4f", g_mapperGood, (unsigned)self, (unsigned)g_cfg.offSens,
			(double)sens, (unsigned)msp, (double)st[0], (double)st[1], (double)st[2]);
		if (g_mapperGood == 1) MgrSelfCheck(self, msp);
	}
}

// ----------------------------------------------------------------------------
// Хуки exe: Mouse_WndMsg (момент WM_MOUSEMOVE) и Mouse_GetState (парная выборка + подмена режима)
// ----------------------------------------------------------------------------
static bool g_accOk = false;        // данные AccDX/AccDY проверены
static bool g_mgsHooked = false;
static double g_remX = 0, g_remY = 0;
static int g_lastModeSeen = M_PASS;
static bool g_writeFailed = false;

// [esp]=ret, [esp+4]=param_1, [esp+8]=hWnd, [esp+0xC]=msg (раскладка Mouse_WndMsg в обеих сборках)
static void OnWndMsg(uintptr_t esp)
{
	uint32_t msg = 0;
	ReadT(esp + 0xC, &msg);
	Count(C_WndMsgAll);
	static std::atomic<int> nShown{ 0 };
	if (nShown.fetch_add(1) < 10) Log("WndMsg #%d: msg=0x%X (layout check: should look like WM_* values, e.g. 0x200 = WM_MOUSEMOVE)", nShown.load(), (unsigned)msg);
	if (msg == 0x200) // WM_MOUSEMOVE: игра сейчас посчитает дельту курсора - снимаем raw в этот же момент
	{
		Count(C_WndMouseMove);
		g_wmMoveEver = true;
		g_pendRawX += g_rawPairAccX.exchange(0);
		g_pendRawY += g_rawPairAccY.exchange(0);
	}
}

static void OnMouseGetState()
{
	Count(C_MouseGetState);
	LONG rx, ry;
	if (g_wmMoveEver.load()) { rx = g_pendRawX.exchange(0); ry = g_pendRawY.exchange(0); }
	else                     { rx = g_rawPairAccX.exchange(0); ry = g_rawPairAccY.exchange(0); } // "direct": WndMsg-хук не сработал

	int dx = 0, dy = 0;
	if (g_accOk) { ReadT(Rebase(g_r.accDX), &dx); ReadT(Rebase(g_r.accDY), &dy); }
	int ox = dx, oy = dy;

	const int mode = g_mode.load();
	if (mode != g_lastModeSeen) { g_remX = g_remY = 0; g_lastModeSeen = mode; }
	if (g_accOk && mode != M_PASS)
	{
		if (mode == M_ZERO) { ox = 0; oy = 0; }
		else // M_RAW: счёты мыши как есть (с дробным остатком, чтобы медленные движения не терялись)
		{
			g_remX += (double)rx * g_cfg.rawScale;
			g_remY += (double)ry * g_cfg.rawScale;
			ox = (int)g_remX; oy = (int)g_remY;
			g_remX -= ox; g_remY -= oy;
		}
		if (!WriteT(Rebase(g_r.accDX), ox) || !WriteT(Rebase(g_r.accDY), oy))
		{
			if (!g_writeFailed) { g_writeFailed = true; Log("ERROR: writing the accumulator failed -> mode forced to PASS"); }
			g_mode = M_PASS;
			ox = dx; oy = dy;
		}
	}

	if (!g_capturing.load() || !g_accOk) return;
	Sample s;
	s.t = NowMs() - g_capStart;
	s.rx = rx; s.ry = ry; s.gx = dx; s.gy = dy; s.ox = ox; s.oy = oy; s.mode = mode;
	s.lookValid = g_lookValid; s.lx = g_lookX; s.ly = g_lookY; s.sens = g_sens;
	if (g_r.flagCap) ReadT(Rebase(g_r.flagCap), &s.cap);
	if (g_r.flagRc) ReadT(Rebase(g_r.flagRc), &s.rc);
	std::lock_guard<std::mutex> lk(g_capMu);
	g_samplesAcc.push_back(s);
}

static void MidMouseGetState(safetyhook::Context&) { OnMouseGetState(); }
static void MidPoll(safetyhook::Context&) { Count(C_PollMouseCursor); }
static void MidMapper(safetyhook::Context& ctx) { OnInputMapper(static_cast<uintptr_t>(ctx.ecx)); }
static void MidWndMsg(safetyhook::Context& ctx) { OnWndMsg(static_cast<uintptr_t>(ctx.esp)); }

// ----------------------------------------------------------------------------
// Захват
// ----------------------------------------------------------------------------
static void StartCapture()
{
	if (g_capturing.load()) return;
	{
		std::lock_guard<std::mutex> lk(g_capMu);
		g_samplesAcc.clear();
		g_samplesDi.clear();
	}
	g_rawCapX = 0; g_rawCapY = 0; g_diCapX = 0; g_diCapY = 0;
	g_rawPairAccX = 0; g_rawPairAccY = 0; g_pendRawX = 0; g_pendRawY = 0; g_rawPairDiX = 0; g_rawPairDiY = 0;
	++g_capIndex;

	int cw = 0, ch = 0;
	const std::string cond = BuildConditions(&cw, &ch);
	g_capClientW = cw; g_capClientH = ch;
	char b[512];
	g_capMeta.clear();
	snprintf(b, sizeof(b), "# ds3probe %s sha=%s capture=%d\n", DS3PROBE_VERSION, DS3PROBE_GIT_SHA, g_capIndex); g_capMeta += b;
	snprintf(b, sizeof(b), "# exe md5=%s TimeDateStamp=%08X profile=%s\n", g_md5.c_str(), (unsigned)g_timeDateStamp, g_r.profile); g_capMeta += b;
	snprintf(b, sizeof(b), "# client=%dx%d half=%d,%d\n", cw, ch, cw / 2 - 1, ch / 2 - 1); g_capMeta += b;
	snprintf(b, sizeof(b), "# pairing=%s mapper=%s mode_at_start=%s rawscale=%.4f\n", g_wmMoveEver.load() ? "wm_mousemove" : "direct(WndMsg hook not seen)",
		g_mapperDead ? "dead" : (g_mapperGood ? "ok" : "no-calls-yet"), kModeName[g_mode.load()], g_cfg.rawScale); g_capMeta += b;
	g_capMeta += "# conditions: " + cond + "\n";

	g_capStart = NowMs();
	g_capturing = true;
	Log("=== CAPTURE %d START === mode=%s", g_capIndex, kModeName[g_mode.load()]);
	Log("conditions: %s", cond.c_str());
	if (!g_mgsHooked || !g_accOk) Log("  NOTE: Mouse_GetState hook or Acc addresses unavailable -> no _acc.csv will be produced (only _di)");
	Tone(1, 1200);
}

static double Median(std::vector<double> v)
{
	if (v.empty()) return 0;
	std::sort(v.begin(), v.end());
	return v[v.size() / 2];
}

static void DumpAcc(int idx, const std::vector<Sample>& v)
{
	if (v.empty()) { Log("  [acc] no samples (hook not installed or Mouse_GetState was not called)"); return; }
	wchar_t wname[96];
	swprintf(wname, 96, L"ds3probe_cap_%03d_acc.csv", idx);
	const std::wstring path = SessionPath(wname);
	FILE* f = nullptr;
	_wfopen_s(&f, path.c_str(), L"wt");
	if (f)
	{
		fputs(g_capMeta.c_str(), f);
		fputs("t_ms,raw_dx,raw_dy,game_dx,game_dy,mode,out_dx,out_dy,look_x,look_y,sens,cap,rc\n", f);
	}
	const int halfW = g_capClientW / 2 - 1, halfH = g_capClientH / 2 - 1;
	double pathRaw = 0, pathGame = 0, pathOut = 0, netRX = 0, netRY = 0, netGX = 0, netGY = 0;
	int nSatX = 0, nSatY = 0, nRawOverX = 0, nRawOverY = 0, modeFrames[3] = { 0, 0, 0 }, nLook = 0;
	std::vector<double> dts;
	for (size_t i = 0; i < v.size(); ++i)
	{
		const Sample& s = v[i];
		if (f)
		{
			fprintf(f, "%.3f,%ld,%ld,%d,%d,%d,%d,%d,", s.t, s.rx, s.ry, s.gx, s.gy, s.mode, s.ox, s.oy);
			if (s.lookValid) fprintf(f, "%.5f,%.5f,%.5f,", (double)s.lx, (double)s.ly, (double)s.sens); else fputs(",,,", f);
			fprintf(f, "%u,%u\n", (unsigned)s.cap, (unsigned)s.rc);
		}
		if (i) dts.push_back(s.t - v[i - 1].t);
		pathRaw += std::hypot((double)s.rx, (double)s.ry);
		pathGame += std::hypot((double)s.gx, (double)s.gy);
		pathOut += std::hypot((double)s.ox, (double)s.oy);
		netRX += s.rx; netRY += s.ry; netGX += s.gx; netGY += s.gy;
		if (halfW > 0 && std::abs(s.gx) >= (int)(0.9 * halfW)) ++nSatX;
		if (halfH > 0 && std::abs(s.gy) >= (int)(0.9 * halfH)) ++nSatY;
		if (halfW > 0 && std::abs(s.rx) > halfW) ++nRawOverX;
		if (halfH > 0 && std::abs(s.ry) > halfH) ++nRawOverY;
		if (s.mode >= 0 && s.mode < 3) ++modeFrames[s.mode];
		if (s.lookValid) ++nLook;
	}
	if (f) fclose(f);
	const double dt = Median(dts);
	Log("  [acc] %zu frames, median dt=%.2f ms (~%.0f FPS; min %.2f max %.2f)", v.size(), dt, dt > 0 ? 1000.0 / dt : 0.0,
		dts.empty() ? 0.0 : *std::min_element(dts.begin(), dts.end()), dts.empty() ? 0.0 : *std::max_element(dts.begin(), dts.end()));
	Log("  [acc] raw net=(%.0f,%.0f) path=%.0f | game net=(%.0f,%.0f) path=%.0f | out path=%.0f | game/raw path=%.3f",
		netRX, netRY, pathRaw, netGX, netGY, pathGame, pathOut, pathRaw > 0 ? pathGame / pathRaw : 0.0);
	Log("  [acc] frames by mode: PASS=%d RAW=%d ZERO=%d | look valid in %d frames", modeFrames[0], modeFrames[1], modeFrames[2], nLook);
	Log("  [acc] CEILING check (half client = %d,%d): game>=90%% of half: X=%d Y=%d frames | raw>half: X=%d Y=%d frames  <- raw>half with game stuck at half = saturation before the accumulator",
		halfW, halfH, nSatX, nSatY, nRawOverX, nRawOverY);
	if (netRX != 0 && netGX != 0 && (netRX > 0) != (netGX > 0)) Log("  [acc] WARNING: net X of raw and game have OPPOSITE signs - check the axis direction before trusting ratios");
	Log("  [acc] csv: %ls", path.c_str());
}

static void DumpDi(int idx, const std::vector<Sample>& v)
{
	if (v.empty()) { Log("  [di] no samples (the game does not read the DirectInput mouse via GetDeviceState)"); return; }
	wchar_t wname[96];
	swprintf(wname, 96, L"ds3probe_cap_%03d_di.csv", idx);
	const std::wstring path = SessionPath(wname);
	FILE* f = nullptr;
	_wfopen_s(&f, path.c_str(), L"wt");
	double pathRaw = 0, pathGame = 0;
	if (f) { fputs(g_capMeta.c_str(), f); fputs("t_ms,raw_dx,raw_dy,game_dx,game_dy\n", f); }
	for (const Sample& s : v)
	{
		if (f) fprintf(f, "%.3f,%ld,%ld,%d,%d\n", s.t, s.rx, s.ry, s.gx, s.gy);
		pathRaw += std::hypot((double)s.rx, (double)s.ry);
		pathGame += std::hypot((double)s.gx, (double)s.gy);
	}
	if (f) fclose(f);
	Log("  [di] %zu samples: raw path=%.0f | DI path=%.0f | ratio=%.3f", v.size(), pathRaw, pathGame, pathRaw > 0 ? pathGame / pathRaw : 0.0);
	Log("  [di] csv: %ls", path.c_str());
}

static void StopCapture()
{
	if (!g_capturing.exchange(false)) return;
	std::vector<Sample> acc, di;
	{
		std::lock_guard<std::mutex> lk(g_capMu);
		acc.swap(g_samplesAcc);
		di.swap(g_samplesDi);
	}
	Log("=== CAPTURE %d STOP (%.1f s) ===", g_capIndex, (NowMs() - g_capStart) / 1000.0);
	Log("  Raw Input total while focused: net=(%ld,%ld)", g_rawCapX.load(), g_rawCapY.load());
	Log("  DirectInput mouse total: net=(%ld,%ld)", g_diCapX.load(), g_diCapY.load());
	DumpAcc(g_capIndex, acc);
	DumpDi(g_capIndex, di);
	Log("  next: python analyze_samples.py <session folder>\\ds3probe_cap_%03d_acc.csv", g_capIndex);
	Tone(2, 1200);
}

// ----------------------------------------------------------------------------
// user32-хуки
// ----------------------------------------------------------------------------
static safetyhook::InlineHook hkGetCursorPos, hkSetCursorPos, hkClipCursor, hkShowCursor;

static BOOL WINAPI GetCursorPos_H(LPPOINT p)
{
	void* ra = _ReturnAddress();
	const BOOL r = hkGetCursorPos.unsafe_stdcall<BOOL>(p);
	Count(C_GetCursorPos);
	NoteCaller(C_GetCursorPos, ra);
	if (FirstN(C_GetCursorPos)) Log("GetCursorPos -> (%ld,%ld) from %s", p ? p->x : 0, p ? p->y : 0, Where(ra).c_str());
	return r;
}

static BOOL WINAPI SetCursorPos_H(int x, int y)
{
	void* ra = _ReturnAddress();
	Count(C_SetCursorPos);
	NoteCaller(C_SetCursorPos, ra);
	if (FirstN(C_SetCursorPos)) Log("SetCursorPos(%d,%d) from %s", x, y, Where(ra).c_str());
	return hkSetCursorPos.unsafe_stdcall<BOOL>(x, y);
}

static BOOL WINAPI ClipCursor_H(const RECT* r)
{
	void* ra = _ReturnAddress();
	Count(C_ClipCursor);
	NoteCaller(C_ClipCursor, ra);
	if (FirstN(C_ClipCursor))
	{
		if (r) Log("ClipCursor(%ld,%ld,%ld,%ld) from %s", r->left, r->top, r->right, r->bottom, Where(ra).c_str());
		else   Log("ClipCursor(NULL) from %s", Where(ra).c_str());
	}
	return hkClipCursor.unsafe_stdcall<BOOL>(r);
}

static int WINAPI ShowCursor_H(BOOL show)
{
	void* ra = _ReturnAddress();
	Count(C_ShowCursor);
	NoteCaller(C_ShowCursor, ra);
	if (FirstN(C_ShowCursor)) Log("ShowCursor(%d) from %s", (int)show, Where(ra).c_str());
	return hkShowCursor.unsafe_stdcall<int>(show);
}

static void InstallUser32Hooks()
{
	HMODULE u = GetModuleHandleW(L"user32.dll");
	if (!u) { Log("user32.dll not loaded?!"); return; }
	auto mk = [&](safetyhook::InlineHook& h, const char* name, void* dst)
	{
		void* t = reinterpret_cast<void*>(GetProcAddress(u, name));
		if (!t) { Log("hook %s: GetProcAddress failed", name); return; }
		h = safetyhook::create_inline(t, dst);
		Log("hook user32!%s at %p: %s", name, t, h ? "ok" : "FAILED");
	};
	mk(hkGetCursorPos, "GetCursorPos", reinterpret_cast<void*>(&GetCursorPos_H));
	mk(hkSetCursorPos, "SetCursorPos", reinterpret_cast<void*>(&SetCursorPos_H));
	mk(hkClipCursor,   "ClipCursor",   reinterpret_cast<void*>(&ClipCursor_H));
	mk(hkShowCursor,   "ShowCursor",   reinterpret_cast<void*>(&ShowCursor_H));
}

// ----------------------------------------------------------------------------
// DirectInput8 (без dinput.h: работаем через vtable и сырые указатели)
// ----------------------------------------------------------------------------
static const GUID kSysMouse     = { 0x6F1D2B60, 0xD5A0, 0x11CF, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
static const GUID kSysKeyboard  = { 0x6F1D2B61, 0xD5A0, 0x11CF, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
static const GUID kSysMouseEm   = { 0x6F1D2B80, 0xD5A0, 0x11CF, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };
static const GUID kSysMouseEm2  = { 0x6F1D2B81, 0xD5A0, 0x11CF, { 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 } };

static safetyhook::InlineHook hkDI8Create, hkCreateDevice, hkSetCoop, hkSetFmt, hkAcquire, hkGetState, hkGetData;
static std::mutex g_diMu;
static std::vector<void*> g_mouseDevs;

static bool IsMouseDev(void* d)
{
	std::lock_guard<std::mutex> lk(g_diMu);
	return std::find(g_mouseDevs.begin(), g_mouseDevs.end(), d) != g_mouseDevs.end();
}

static void HookOnce(safetyhook::InlineHook& h, void* target, void* dst, const char* name)
{
	if (h) return;
	h = safetyhook::create_inline(target, dst);
	Log("hook DI %s at %p: %s", name, target, h ? "ok" : "FAILED");
}

static HRESULT WINAPI SetCoop_H(void* self, HWND hwnd, DWORD flags)
{
	const HRESULT hr = hkSetCoop.unsafe_stdcall<HRESULT>(self, hwnd, flags);
	Log("SetCooperativeLevel dev=%p mouse=%d hwnd=%p flags=0x%X [%s%s%s%s] hr=0x%08X", self, (int)IsMouseDev(self), (void*)hwnd, (unsigned)flags,
		(flags & 1) ? "EXCLUSIVE " : "", (flags & 2) ? "NONEXCLUSIVE " : "", (flags & 4) ? "FOREGROUND " : "", (flags & 8) ? "BACKGROUND" : "", (unsigned)hr);
	return hr;
}

static HRESULT WINAPI SetFmt_H(void* self, const void* fmt)
{
	const HRESULT hr = hkSetFmt.unsafe_stdcall<HRESULT>(self, fmt);
	Log("SetDataFormat dev=%p mouse=%d fmt=%p hr=0x%08X", self, (int)IsMouseDev(self), fmt, (unsigned)hr);
	return hr;
}

static HRESULT WINAPI Acquire_H(void* self)
{
	const HRESULT hr = hkAcquire.unsafe_stdcall<HRESULT>(self);
	static std::atomic<int> n{ 0 };
	if (n.fetch_add(1) < 20) Log("Acquire dev=%p mouse=%d hr=0x%08X", self, (int)IsMouseDev(self), (unsigned)hr);
	return hr;
}

static HRESULT WINAPI GetState_H(void* self, DWORD cb, void* data)
{
	const HRESULT hr = hkGetState.unsafe_stdcall<HRESULT>(self, cb, data);
	if (IsMouseDev(self))
	{
		Count(C_DI_MouseState);
		if (SUCCEEDED(hr) && data && (cb == 16 || cb == 20)) // DIMOUSESTATE / DIMOUSESTATE2
		{
			const LONG* p = static_cast<const LONG*>(data);
			static std::atomic<int> nShown{ 0 };
			if (nShown.fetch_add(1) < 8) Log("DI mouse state: cb=%u lX=%ld lY=%ld lZ=%ld", (unsigned)cb, p[0], p[1], p[2]);
			const LONG rx = g_rawPairDiX.exchange(0), ry = g_rawPairDiY.exchange(0);
			if (g_capturing.load())
			{
				g_diCapX += p[0]; g_diCapY += p[1];
				Sample s;
				s.t = NowMs() - g_capStart; s.rx = rx; s.ry = ry; s.gx = (int)p[0]; s.gy = (int)p[1];
				std::lock_guard<std::mutex> lk(g_capMu);
				g_samplesDi.push_back(s);
			}
		}
	}
	else Count(C_DI_OtherState);
	return hr;
}

static HRESULT WINAPI GetData_H(void* self, DWORD cb, void* rgdod, DWORD* pdw, DWORD flags)
{
	const HRESULT hr = hkGetData.unsafe_stdcall<HRESULT>(self, cb, rgdod, pdw, flags);
	if (IsMouseDev(self))
	{
		Count(C_DI_MouseData);
		if (SUCCEEDED(hr) && rgdod && pdw && !(flags & 1)) // 1 = DIGDD_PEEK
		{
			const DWORD n = *pdw;
			Count(C_DI_MouseEvents, n);
			for (DWORD i = 0; i < n && cb >= 8; ++i)
			{
				const BYTE* e = static_cast<const BYTE*>(rgdod) + size_t(i) * cb;
				const DWORD ofs = *reinterpret_cast<const DWORD*>(e);
				const LONG val = static_cast<LONG>(*reinterpret_cast<const DWORD*>(e + 4));
				if (g_capturing.load()) { if (ofs == 0) g_diCapX += val; else if (ofs == 4) g_diCapY += val; }
			}
		}
	}
	else Count(C_DI_OtherData);
	return hr;
}

static std::string GuidStr(const GUID* g)
{
	if (!g) return "(null)";
	char b[64];
	snprintf(b, sizeof(b), "{%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X}", g->Data1, g->Data2, g->Data3,
		g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3], g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
	return b;
}

static HRESULT WINAPI CreateDevice_H(void* self, const GUID* rguid, void** ppDev, void* outer)
{
	const HRESULT hr = hkCreateDevice.unsafe_stdcall<HRESULT>(self, rguid, ppDev, outer);
	void* dev = (SUCCEEDED(hr) && ppDev) ? *ppDev : nullptr;
	const bool isMouse = rguid && (IsEqualGUID(*rguid, kSysMouse) || IsEqualGUID(*rguid, kSysMouseEm) || IsEqualGUID(*rguid, kSysMouseEm2));
	const char* kind = !rguid ? "?" : isMouse ? "SysMouse" : IsEqualGUID(*rguid, kSysKeyboard) ? "SysKeyboard" : "other(gamepad?)";
	Log("CreateDevice guid=%s (%s) -> dev=%p hr=0x%08X", GuidStr(rguid).c_str(), kind, dev, (unsigned)hr);
	if (dev)
	{
		if (isMouse) { std::lock_guard<std::mutex> lk(g_diMu); g_mouseDevs.push_back(dev); }
		void** vt = *reinterpret_cast<void***>(dev);
		HookOnce(hkAcquire,  vt[7],  reinterpret_cast<void*>(&Acquire_H),  "Acquire");
		HookOnce(hkGetState, vt[9],  reinterpret_cast<void*>(&GetState_H), "GetDeviceState");
		HookOnce(hkGetData,  vt[10], reinterpret_cast<void*>(&GetData_H),  "GetDeviceData");
		HookOnce(hkSetFmt,   vt[11], reinterpret_cast<void*>(&SetFmt_H),   "SetDataFormat");
		HookOnce(hkSetCoop,  vt[13], reinterpret_cast<void*>(&SetCoop_H),  "SetCooperativeLevel");
	}
	return hr;
}

static HRESULT WINAPI DI8Create_H(HINSTANCE h, DWORD ver, REFIID riid, LPVOID* out, LPUNKNOWN outer)
{
	// riid - ссылка; передаём указателем (ABI тот же), иначе шаблон хука скопирует GUID по значению
	const HRESULT hr = hkDI8Create.unsafe_stdcall<HRESULT>(h, ver, &riid, out, outer);
	Count(C_DI_Create);
	Log("DirectInput8Create ver=0x%X riid=%s hr=0x%08X", (unsigned)ver, GuidStr(&riid).c_str(), (unsigned)hr);
	if (SUCCEEDED(hr) && out && *out)
	{
		void** vt = *reinterpret_cast<void***>(*out);
		HookOnce(hkCreateDevice, vt[3], reinterpret_cast<void*>(&CreateDevice_H), "CreateDevice");
	}
	return hr;
}

// ----------------------------------------------------------------------------
// Установка mid-хуков exe: только с проверкой байтов, сборки и данных
// ----------------------------------------------------------------------------
static SafetyHookMid mhMouseGetState, mhWndMsg, mhPoll, mhMapper;
static bool g_exeHooked = false;

static void DumpBytes(const char* name, uintptr_t ghidraAddr)
{
	uint8_t b[16] = {};
	if (!ReadBytes(Rebase(ghidraAddr), b, sizeof(b))) { Log("  %-18s %08X: UNREADABLE", name, (unsigned)ghidraAddr); return; }
	char s[64] = {};
	for (int i = 0; i < 16; ++i) snprintf(s + i * 3, 4, "%02X ", b[i]);
	Log("  %-18s %08X: %s", name, (unsigned)ghidraAddr, s);
}

// Хук разрешён только если .bytes заданы, достаточно конкретны (>=8 байт, из них >=5 не маски) и совпали с памятью
static bool FuncReady(const char* name, uintptr_t ghidraAddr, const std::string& bytes)
{
	if (!ghidraAddr) { Log("  %s: no address -> skipped", name); return false; }
	DumpBytes(name, ghidraAddr);
	std::vector<int> pat;
	if (!ParsePattern(bytes, pat)) { Log("  %s: no .bytes for this address -> hook skipped (blind hooks are forbidden since v3)", name); return false; }
	int fixedBytes = 0;
	for (int p : pat) if (p >= 0) ++fixedBytes;
	if (pat.size() < 8 || fixedBytes < 5) { Log("  %s: .bytes too weak (%zu bytes, %d fixed; need >=8 and >=5) -> hook skipped", name, pat.size(), fixedBytes); return false; }
	if (!InImage(Rebase(ghidraAddr))) { Log("  %s: address outside the exe image -> hook skipped", name); return false; }
	std::vector<uint8_t> mem(pat.size());
	if (!ReadBytes(Rebase(ghidraAddr), mem.data(), mem.size())) { Log("  %s: unreadable -> hook skipped", name); return false; }
	for (size_t i = 0; i < pat.size(); ++i)
		if (pat[i] >= 0 && pat[i] != mem[i]) { Log("  %s: expected bytes MISMATCH at +%zu -> hook skipped", name, i); return false; }
	return true;
}

static bool DataReady(const char* name, uintptr_t ghidraAddr)
{
	int v = 0;
	if (!ghidraAddr || !InImage(Rebase(ghidraAddr)) || !ReadT(Rebase(ghidraAddr), &v)) { Log("  data %s=%08X: not usable", name, (unsigned)ghidraAddr); return false; }
	return true;
}

static void InstallExeHooks()
{
	g_exeHooked = true;
	if (!g_cfg.exeHooks) { Log("exe hooks disabled by cfg (ExeHooks = 0)"); return; }
	if (g_cfg.errors) { Log("exe hooks SKIPPED: the cfg has %d error(s), see lines above", g_cfg.errors); return; }
	if (g_cfg.hasBuild && g_cfg.build != g_timeDateStamp)
	{
		Log("cfg Build=%08X != exe TimeDateStamp=%08X -> exe hooks SKIPPED (addresses are for another build)", (unsigned)g_cfg.build, (unsigned)g_timeDateStamp);
		return;
	}
	if (!g_cfg.md5.empty() && g_cfg.md5 != g_md5)
	{
		Log("cfg MD5=%s != exe MD5=%s -> exe hooks SKIPPED (cfg is for another build)", g_cfg.md5.c_str(), g_md5.c_str());
		return;
	}
	if (g_anchorConflict) Log("anchor conflict -> Mouse_GetState hook disabled; other hooks still checked by their own bytes");

	g_accOk = DataReady("AccDX", g_r.accDX) && DataReady("AccDY", g_r.accDY);
	if (!g_accOk) Log("  Acc addresses not usable -> no _acc.csv and no F9 modes");

	if (FuncReady("Mouse_GetState", g_r.mgs, g_r.bMgs))
	{
		mhMouseGetState = safetyhook::create_mid(reinterpret_cast<void*>(Rebase(g_r.mgs)), &MidMouseGetState);
		g_mgsHooked = static_cast<bool>(mhMouseGetState);
		Log("  Mouse_GetState hook: %s", g_mgsHooked ? "ok" : "FAILED");
	}
	if (FuncReady("Mouse_WndMsg", g_r.wnd, g_r.bWnd))
	{
		mhWndMsg = safetyhook::create_mid(reinterpret_cast<void*>(Rebase(g_r.wnd)), &MidWndMsg);
		Log("  Mouse_WndMsg hook: %s", mhWndMsg ? "ok" : "FAILED");
	}
	if (FuncReady("PollMouseCursor", g_r.poll, g_r.bPoll))
	{
		mhPoll = safetyhook::create_mid(reinterpret_cast<void*>(Rebase(g_r.poll)), &MidPoll);
		Log("  PollMouseCursor hook: %s", mhPoll ? "ok" : "FAILED");
	}
	if (FuncReady("InputMapper_Update", g_r.mapper, g_r.bMapper))
	{
		mhMapper = safetyhook::create_mid(reinterpret_cast<void*>(Rebase(g_r.mapper)), &MidMapper);
		Log("  InputMapper_Update hook: %s", mhMapper ? "ok" : "FAILED");
	}
	Log("exe hooks done: Mouse_GetState=%d acc=%d F9-modes=%s", (int)g_mgsHooked, (int)g_accOk, (g_mgsHooked && g_accOk) ? "available" : "UNAVAILABLE");
	LogConditions("after hooks");
}

// ----------------------------------------------------------------------------
// Секундная сводка, хоткеи, главный цикл
// ----------------------------------------------------------------------------
static void PrintSecond()
{
	static int idleSecs = 0;
	uint64_t d[C_COUNT];
	bool any = false;
	for (int i = 0; i < C_COUNT; ++i)
	{
		const uint64_t v = g_cnt[i].load();
		d[i] = v - g_cntPrev[i];
		g_cntPrev[i] = v;
		any = any || d[i] != 0;
	}
	const LONG rx = g_rawRepX.exchange(0), ry = g_rawRepY.exchange(0);
	if (!any)
	{
		// сердцебиение: если лог оборвался, а процесс жив - поток пробы пишет "alive", значит завис именно поток игры
		if (++idleSecs % 5 == 0) Log("alive (no counted events for %d s) fg=%d", idleSecs, (int)GameFocused());
		return;
	}
	idleSecs = 0;

	std::string s;
	char b[160];
	for (int i = 0; i < C_COUNT; ++i)
		if (d[i]) { snprintf(b, sizeof(b), "%s=%llu ", kCounterName[i], (unsigned long long)d[i]); s += b; }
	snprintf(b, sizeof(b), "| raw=(%ld,%ld) fg=%d mode=%s", rx, ry, (int)GameFocused(), kModeName[g_mode.load()]);
	s += b;
	if (g_accOk)
	{
		int ax = 0, ay = 0;
		ReadT(Rebase(g_r.accDX), &ax);
		ReadT(Rebase(g_r.accDY), &ay);
		snprintf(b, sizeof(b), " acc=(%d,%d)", ax, ay);
		s += b;
	}
	if (g_r.flagCap && g_r.flagRc)
	{
		uint8_t cap = 0xFF, rc = 0xFF;
		ReadT(Rebase(g_r.flagCap), &cap);
		ReadT(Rebase(g_r.flagRc), &rc);
		snprintf(b, sizeof(b), " cap=%u rc=%u", (unsigned)cap, (unsigned)rc);
		s += b;
	}
	if (g_lookValid)
	{
		snprintf(b, sizeof(b), " look=(%.3f,%.3f) sens=%.3f", (double)g_lookX, (double)g_lookY, (double)g_sens);
		s += b;
	}
	Log("1s: %s", s.c_str());
}

static void DumpCallers()
{
	static const Counter apis[] = { C_GetCursorPos, C_SetCursorPos, C_ClipCursor, C_ShowCursor };
	std::lock_guard<std::mutex> lk(g_callMu);
	for (Counter id : apis)
	{
		auto& m = g_callers[id];
		if (m.empty()) continue;
		std::vector<std::pair<uintptr_t, uint64_t>> v(m.begin(), m.end());
		std::sort(v.begin(), v.end(), [](const std::pair<uintptr_t, uint64_t>& a, const std::pair<uintptr_t, uint64_t>& b) { return a.second > b.second; });
		Log("  callers of %s:", kCounterName[id]);
		for (size_t i = 0; i < v.size() && i < 12; ++i)
			Log("    %8llu x  %s", (unsigned long long)v[i].second, Where(reinterpret_cast<void*>(v[i].first)).c_str());
		m.clear();
	}
}

static bool KeyDown(int vk) { return (GetAsyncKeyState(vk) & 0x8000) != 0; }

static void SetMode(int m, const char* why)
{
	g_mode = m;
	g_modeSince = NowMs();
	Log("=== MODE -> %s (%s). PASS = game input untouched; RAW = accumulator := Raw Input * %.3f; ZERO = accumulator := 0 ===", kModeName[m], why, g_cfg.rawScale);
}

static void CycleMode()
{
	if (!(g_mgsHooked && g_accOk))
	{
		Log("F9: mode switch UNAVAILABLE (Mouse_GetState hook or Acc addresses missing, see 'exe hooks done' line)");
		Tone(1, 250);
		return;
	}
	const int m = (g_mode.load() + 1) % 3;
	SetMode(m, "F9");
	Tone(m + 1, m == 0 ? 600 : (m == 1 ? 1000 : 1500));
}

static DWORD WINAPI WorkerThread(LPVOID)
{
	CreateThread(nullptr, 0, RawThread, nullptr, 0, nullptr);
	InstallUser32Hooks();

	// идентификатор сборки, профиль, cfg, якорь - всё тут, а не в DllMain (под блокировкой загрузчика не работаем)
	g_md5 = ComputeFileMd5(g_exePath);
	Log("exe: %ls", g_exePath.c_str());
	Log("exe MD5=%s PE TimeDateStamp=%08X SizeOfImage=%08X imageBase=%08X loadBase=%08X", g_md5.empty() ? "(failed)" : g_md5.c_str(),
		(unsigned)g_timeDateStamp, (unsigned)g_sizeOfImage, (unsigned)g_imageBase, (unsigned)g_exeBase);
	if (g_exeBase != g_imageBase) Log("WARNING: exe is loaded at %08X, not at its preferred base %08X; Rebase() assumes fixed addresses are shifted by the same delta", (unsigned)g_exeBase, (unsigned)g_imageBase);
	LoadConfig();
	ResolveTargets();

	const double t0 = NowMs();
	double nextSec = t0 + 1000.0, d3d9Seen = -1.0;
	bool k6 = false, k7 = false, k8 = false, k9 = false, k10 = false;
	int marker = 0;

	for (;;)
	{
		Sleep(10);
		const double now = NowMs();

		// mid-хуки по адресам exe ставим не сразу, а через 1.5 с после появления d3d9
		if (!g_exeHooked)
		{
			if (d3d9Seen < 0 && GetModuleHandleW(L"d3d9.dll")) { d3d9Seen = now; Log("d3d9.dll is loaded"); }
			if ((d3d9Seen >= 0 && now - d3d9Seen > 1500.0) || now - t0 > opt::kWaitD3D9MaxMs) InstallExeHooks();
		}

		if (g_mode.load() != M_PASS && now - g_modeSince.load() > opt::kModeAutoRevertMs) { SetMode(M_PASS, "auto-revert after 2 min"); Tone(1, 300); }

		const bool fg = GameFocused();
		const bool n6 = fg && KeyDown(opt::kVkMarker), n7 = fg && KeyDown(opt::kVkStart), n8 = fg && KeyDown(opt::kVkStop);
		const bool n9 = fg && KeyDown(opt::kVkMode), n10 = fg && KeyDown(opt::kVkInfo);
		if (n6 && !k6) { Log("=== MARKER %d ===", ++marker); DumpCallers(); }
		if (n7 && !k7) StartCapture();
		if (n8 && !k8) StopCapture();
		if (n9 && !k9) CycleMode();
		if (n10 && !k10) LogConditions("F10");
		k6 = n6; k7 = n7; k8 = n8; k9 = n9; k10 = n10;

		if (now >= nextSec) { nextSec += 1000.0; PrintSecond(); }
	}
}

// ----------------------------------------------------------------------------
// DllMain
// ----------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		g_self = hModule;
		DisableThreadLibraryCalls(hModule);
		QueryPerformanceFrequency(&g_freq);
		QueryPerformanceCounter(&g_t0);

		g_exeBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
		const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_exeBase);
		const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(g_exeBase + dos->e_lfanew);
		g_imageBase = nt->OptionalHeader.ImageBase;
		g_timeDateStamp = nt->FileHeader.TimeDateStamp;
		g_sizeOfImage = nt->OptionalHeader.SizeOfImage;

		OpenSession();
		Log("DS3Probe %s sha=%s attach. pid=%lu", DS3PROBE_VERSION, DS3PROBE_GIT_SHA, GetCurrentProcessId());
		Log("session folder: %ls", g_sessionDir.c_str());

		// настоящий dinput8.dll из System32 (экспорты-переходники лежат в dllmain.hpp)
		wchar_t sys[MAX_PATH] = {};
		GetSystemDirectoryW(sys, MAX_PATH);
		lstrcatW(sys, L"\\dinput8.dll");
		HMODULE real = LoadLibraryW(sys);
		if (real && dinput8.ProxySetup(real) && dinput8.DirectInput8Create)
		{
			hkDI8Create = safetyhook::create_inline(reinterpret_cast<void*>(dinput8.DirectInput8Create), reinterpret_cast<void*>(&DI8Create_H));
			Log("hook DirectInput8Create: %s", hkDI8Create ? "ok" : "FAILED");
		}
		else Log("could not load the real dinput8.dll!");

		CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
	}
	return TRUE;
}
