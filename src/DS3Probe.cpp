// ============================================================================
// DS3Probe - прокси dinput8.dll для Dead Space 3.
// НИЧЕГО НЕ ЧИНИТ. Только собирает данные, чтобы проверять гипотезы без отладчика.
//
// Что делает:
//  1. Хукает user32: GetCursorPos / SetCursorPos / ClipCursor / ShowCursor
//     (счётчики + таблица "кто вызывает" с адресами в формате Ghidra).
//  2. Оборачивает DirectInput8: какие устройства создаёт игра (мышь или нет),
//     режим SetCooperativeLevel, читается ли мышь через GetDeviceState/Data.
//  3. Ставит mid-хуки по адресам из Ghidra (Mouse_GetState, Mouse_WndMsg,
//     PollMouseCursor, InputMapper_Update) - только считает, ничего не меняет.
//  4. В своём потоке слушает Raw Input (эталон: сколько счётов отдала мышь на самом деле).
//  5. Раз в секунду пишет сводку, по хоткеям - захват сэмплов в CSV.
//
// Хоткеи (работают, только когда окно игры в фокусе):
//   F6 - маркер в логе + таблица "кто вызывает" (и сброс этой таблицы)
//   F7 - начать захват (сэмплы raw vs game)
//   F8 - закончить захват, записать ds3probe_cap_NNN.csv и итоги в лог
//
// Сборка: см. README.md. Требует safetyhook (из репозитория MarkerPatch) и его dllmain.hpp.
// Этот файл НЕ компилировался автором (нет Windows-тулчейна) - возможны мелкие правки.
// ============================================================================
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX
#include <Windows.h>
#include <intrin.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "safetyhook/safetyhook.hpp"
#include "dllmain.hpp" // из MarkerPatch/src: struct dinput8 + naked-переходники (экспорты)

// ----------------------------------------------------------------------------
// Настройки. Адреса - ровно как в Ghidra (база образа берётся из PE-заголовка).
// ----------------------------------------------------------------------------
namespace cfg
{
	constexpr uintptr_t kMouseGetState   = 0x0040A620; // Mouse_GetState  (то, что лежит в g_pfnMouseGetState)
	constexpr uintptr_t kPollMouseCursor = 0x0040CC20; // PollMouseCursor
	constexpr uintptr_t kWndMsg          = 0x0040D060; // Mouse_WndMsg    (WM_MOUSEMOVE и т.д.)
	constexpr uintptr_t kInputMapper     = 0x00AC8210; // InputMapper_Update
	constexpr uintptr_t kAccDX           = 0x011ACDD0; // g_mouseDX (аккумулятор, int)
	constexpr uintptr_t kAccDY           = 0x011ACDD4; // g_mouseDY
	constexpr uintptr_t kFlagCaptured    = 0x011ACDCE; // byte, рабочее имя g_mouseCaptured?
	constexpr uintptr_t kFlagRecenter    = 0x011ACDEE; // byte, рабочее имя g_cursorRecenterDisabled

	constexpr int kVkMarker = VK_F6;
	constexpr int kVkStart  = VK_F7;
	constexpr int kVkStop   = VK_F8;

	constexpr int kMaxFirstLogs = 12;      // сколько первых вызовов каждого API писать подробно
	constexpr int kWaitD3D9MaxMs = 30000;  // ждать загрузки d3d9.dll перед mid-хуками по адресам exe
}

// ----------------------------------------------------------------------------
// Общие утилиты
// ----------------------------------------------------------------------------
static HMODULE   g_self = nullptr;
static uintptr_t g_exeBase = 0, g_imageBase = 0;
static LARGE_INTEGER g_freq, g_t0;
static FILE* g_log = nullptr;
static std::mutex g_logMu;
static std::wstring g_dir;

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

static std::wstring MakePath(const wchar_t* name) { return g_dir + L"\\" + name; }

static void OpenLog()
{
	wchar_t exe[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, exe, MAX_PATH);
	std::wstring d = exe;
	const size_t p = d.find_last_of(L'\\');
	g_dir = (p == std::wstring::npos) ? L"." : d.substr(0, p);

	_wfopen_s(&g_log, MakePath(L"ds3probe.log").c_str(), L"wt");
	if (!g_log) // папка игры может быть недоступна для записи
	{
		wchar_t t[MAX_PATH] = {};
		GetTempPathW(MAX_PATH, t);
		g_dir = t;
		while (!g_dir.empty() && (g_dir.back() == L'\\' || g_dir.back() == L'/')) g_dir.pop_back();
		_wfopen_s(&g_log, MakePath(L"ds3probe.log").c_str(), L"wt");
	}
}

// Единственная функция с SEH (в ней нельзя держать объекты с деструкторами)
static bool ReadBytes(uintptr_t addr, void* out, size_t n)
{
	__try { memcpy(out, reinterpret_cast<const void*>(addr), n); return true; }
	__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
template <class T> static bool ReadT(uintptr_t addr, T* out) { return ReadBytes(addr, out, sizeof(T)); }

static uintptr_t Rebase(uintptr_t ghidraAddr) { return g_exeBase + (ghidraAddr - g_imageBase); }

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
static bool FirstN(Counter id) { return g_firstLogged[id].fetch_add(1, std::memory_order_relaxed) < cfg::kMaxFirstLogs; }
static void NoteCaller(Counter id, void* ra)
{
	std::lock_guard<std::mutex> lk(g_callMu);
	++g_callers[id][reinterpret_cast<uintptr_t>(ra)];
}

// ----------------------------------------------------------------------------
// Сырой ввод (эталон) и захват
// ----------------------------------------------------------------------------
static std::atomic<LONG> g_rawPairX{ 0 }, g_rawPairY{ 0 }; // обнуляются в Mouse_GetState (парные с сэмплом)
static std::atomic<LONG> g_rawRepX{ 0 }, g_rawRepY{ 0 };   // обнуляются в секундной сводке
static std::atomic<LONG> g_rawCapX{ 0 }, g_rawCapY{ 0 };   // за время захвата
static std::atomic<LONG> g_diCapX{ 0 }, g_diCapY{ 0 };     // сумма DirectInput-мыши за захват

struct Sample { double t; LONG rx, ry; int gx, gy; };
static std::atomic<bool> g_capturing{ false };
static std::mutex g_capMu;
static std::vector<Sample> g_samples;
static int g_capIndex = 0;
static double g_capStart = 0;

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
						g_rawPairX += x; g_rawPairY += y;
						g_rawRepX += x;  g_rawRepY += y;
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
	Log("RawInput thread: hwnd=%p register=%d", hw, (int)ok);
	MSG msg;
	while (GetMessageW(&msg, nullptr, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
	return 0;
}

// Вызывается из mid-хука на Mouse_GetState: в этот момент аккумуляторы игры ещё не обнулены
static void OnMouseGetState()
{
	Count(C_MouseGetState);
	int dx = 0, dy = 0;
	ReadT(Rebase(cfg::kAccDX), &dx);
	ReadT(Rebase(cfg::kAccDY), &dy);
	const LONG rx = g_rawPairX.exchange(0), ry = g_rawPairY.exchange(0);
	if (!g_capturing.load()) return;
	Sample s;
	s.t = NowMs() - g_capStart; s.rx = rx; s.ry = ry; s.gx = dx; s.gy = dy;
	std::lock_guard<std::mutex> lk(g_capMu);
	g_samples.push_back(s);
}

static void StartCapture()
{
	if (g_capturing.load()) return;
	{
		std::lock_guard<std::mutex> lk(g_capMu);
		g_samples.clear();
	}
	g_rawCapX = 0; g_rawCapY = 0; g_diCapX = 0; g_diCapY = 0;
	++g_capIndex;
	g_capStart = NowMs();
	g_capturing = true;
	Log("=== CAPTURE %d START ===", g_capIndex);
}

static void StopCapture()
{
	if (!g_capturing.exchange(false)) return;
	std::vector<Sample> v;
	{
		std::lock_guard<std::mutex> lk(g_capMu);
		v.swap(g_samples);
	}
	wchar_t wname[64];
	swprintf(wname, 64, L"ds3probe_cap_%03d.csv", g_capIndex);
	FILE* f = nullptr;
	_wfopen_s(&f, MakePath(wname).c_str(), L"wt");
	double pathRaw = 0, pathGame = 0, netRX = 0, netRY = 0, netGX = 0, netGY = 0;
	if (f) fprintf(f, "t_ms,raw_dx,raw_dy,game_dx,game_dy\n");
	for (const Sample& s : v)
	{
		if (f) fprintf(f, "%.3f,%ld,%ld,%d,%d\n", s.t, s.rx, s.ry, s.gx, s.gy);
		pathRaw += std::hypot((double)s.rx, (double)s.ry);
		pathGame += std::hypot((double)s.gx, (double)s.gy);
		netRX += s.rx; netRY += s.ry; netGX += s.gx; netGY += s.gy;
	}
	if (f) fclose(f);
	Log("=== CAPTURE %d STOP: %zu frames (Mouse_GetState calls), %.1f s ===", g_capIndex, v.size(), (NowMs() - g_capStart) / 1000.0);
	Log("  raw (Raw Input, all events while focused): net=(%ld,%ld)", g_rawCapX.load(), g_rawCapY.load());
	Log("  paired by frame: raw net=(%.0f,%.0f) path=%.0f | game net=(%.0f,%.0f) path=%.0f",
		netRX, netRY, pathRaw, netGX, netGY, pathGame);
	if (pathRaw > 0) Log("  game/raw path ratio = %.3f   (смотри не на абсолют, а на зависимость от скорости: analyze_samples.py)", pathGame / pathRaw);
	Log("  DirectInput mouse sum during capture: (%ld,%ld)", g_diCapX.load(), g_diCapY.load());
	if (v.empty()) Log("  !!! нет ни одного сэмпла: Mouse_GetState не вызывался (или mid-хук не встал). Смотри секундные сводки.");
	Log("  csv: %ls", MakePath(wname).c_str());
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
	Log("SetCooperativeLevel dev=%p mouse=%d hwnd=%p flags=0x%X [%s%s%s%s] hr=0x%08X", self, (int)IsMouseDev(self), hwnd, (unsigned)flags,
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
			if (g_capturing.load()) { g_diCapX += p[0]; g_diCapY += p[1]; }
		}
	}
	else Count(C_DI_OtherState);
	return hr;
}

static HRESULT WINAPI GetData_H(void* self, DWORD cb, void* rgdod, DWORD* pdw, DWORD flags)
{
	const DWORD before = pdw ? *pdw : 0;
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
	(void)before;
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
// mid-хуки по адресам exe (только счётчики, поведение игры не меняется)
// ----------------------------------------------------------------------------
static SafetyHookMid mhMouseGetState, mhWndMsg, mhPoll, mhMapper;
static bool g_exeHooked = false;

static void DumpBytes(const char* name, uintptr_t ghidraAddr)
{
	uint8_t b[16] = {};
	if (!ReadBytes(Rebase(ghidraAddr), b, sizeof(b))) { Log("  %-18s %08X: UNREADABLE", name, (unsigned)ghidraAddr); return; }
	char s[64] = {};
	for (int i = 0; i < 16; ++i) snprintf(s + i * 3, 4, "%02X ", b[i]);
	Log("  %-18s %08X: %s  <- сверь с листингом Ghidra", name, (unsigned)ghidraAddr, s);
}

static void InstallExeHooks()
{
	g_exeHooked = true;
	Log("exe base=%08X imageBase(PE)=%08X  (если база != imageBase, адреса пересчитываются автоматически)", (unsigned)g_exeBase, (unsigned)g_imageBase);
	struct Entry { const char* n; uintptr_t a; };
	const Entry t[] = {
		{ "Mouse_GetState",   cfg::kMouseGetState },   { "PollMouseCursor",  cfg::kPollMouseCursor },
		{ "Mouse_WndMsg",     cfg::kWndMsg },          { "InputMapper_Update", cfg::kInputMapper } };
	for (const Entry& e : t) DumpBytes(e.n, e.a);

	mhMouseGetState = safetyhook::create_mid(reinterpret_cast<void*>(Rebase(cfg::kMouseGetState)),
		[](safetyhook::Context&) { OnMouseGetState(); });
	mhPoll = safetyhook::create_mid(reinterpret_cast<void*>(Rebase(cfg::kPollMouseCursor)),
		[](safetyhook::Context&) { Count(C_PollMouseCursor); });
	mhMapper = safetyhook::create_mid(reinterpret_cast<void*>(Rebase(cfg::kInputMapper)),
		[](safetyhook::Context&) { Count(C_InputMapper); });
	mhWndMsg = safetyhook::create_mid(reinterpret_cast<void*>(Rebase(cfg::kWndMsg)),
		[](safetyhook::Context& ctx)
		{
			// на входе: [esp]=ret, [esp+4]=param_1, [esp+8]=hWnd, [esp+0xC]=msg
			uint32_t msg = 0;
			ReadT(static_cast<uintptr_t>(ctx.esp) + 0xC, &msg);
			Count(C_WndMsgAll);
			if (msg == 0x200) Count(C_WndMouseMove); // WM_MOUSEMOVE
		});
	Log("mid-хуки по адресам exe поставлены (успех не проверяется; если счётчики молчат - сверь байты выше)");
}

// ----------------------------------------------------------------------------
// Секундная сводка, хоткеи, главный цикл
// ----------------------------------------------------------------------------
static void PrintSecond()
{
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
	if (!any) return;

	int ax = 0, ay = 0;
	uint8_t cap = 0xFF, rc = 0xFF;
	ReadT(Rebase(cfg::kAccDX), &ax);
	ReadT(Rebase(cfg::kAccDY), &ay);
	ReadT(Rebase(cfg::kFlagCaptured), &cap);
	ReadT(Rebase(cfg::kFlagRecenter), &rc);

	std::string s;
	char b[96];
	for (int i = 0; i < C_COUNT; ++i)
		if (d[i]) { snprintf(b, sizeof(b), "%s=%llu ", kCounterName[i], (unsigned long long)d[i]); s += b; }
	snprintf(b, sizeof(b), "| raw=(%ld,%ld) acc=(%d,%d) cap=%u rc=%u fg=%d", rx, ry, ax, ay, (unsigned)cap, (unsigned)rc, (int)GameFocused());
	s += b;
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

static DWORD WINAPI WorkerThread(LPVOID)
{
	CreateThread(nullptr, 0, RawThread, nullptr, 0, nullptr);
	InstallUser32Hooks();

	const double t0 = NowMs();
	double nextSec = t0 + 1000.0, d3d9Seen = -1.0;
	bool k6 = false, k7 = false, k8 = false;
	int marker = 0;

	for (;;)
	{
		Sleep(10);
		const double now = NowMs();

		// mid-хуки по адресам exe ставим после загрузки d3d9 (к этому моменту код распакован)
		if (!g_exeHooked)
		{
			if (d3d9Seen < 0 && GetModuleHandleW(L"d3d9.dll")) { d3d9Seen = now; Log("d3d9.dll загружен"); }
			if ((d3d9Seen >= 0 && now - d3d9Seen > 1500.0) || now - t0 > cfg::kWaitD3D9MaxMs) InstallExeHooks();
		}

		const bool fg = GameFocused();
		const bool n6 = fg && KeyDown(cfg::kVkMarker), n7 = fg && KeyDown(cfg::kVkStart), n8 = fg && KeyDown(cfg::kVkStop);
		if (n6 && !k6) { Log("=== MARKER %d ===", ++marker); DumpCallers(); }
		if (n7 && !k7) StartCapture();
		if (n8 && !k8) StopCapture();
		k6 = n6; k7 = n7; k8 = n8;

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

		OpenLog();
		Log("DS3Probe attach. pid=%lu", GetCurrentProcessId());

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
		else Log("не удалось загрузить настоящий dinput8.dll!");

		CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
	}
	return TRUE;
}
