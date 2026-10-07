# -*- coding: utf-8 -*-
# DS3 report v2: xrefs + вызывающие + декомпиляция по известным адресам -> один markdown-файл.
#
# Отличия от v1 (аудит 2026-10-07):
#  * адреса выбираются по MD5 открытой сборки (PROFILES): для 1.0.0.1 теперь есть свой набор, отчёт
#    декомпилирует InputMapper_Update, ApplyControlConfiguration, GetPlayerObjectByIndex и др. ИМЕННО в 1.0.0.1;
#  * добавлены цели по ИМЕНИ символа (экспорт ?Init@Mouse@Windows@EARS@@YAXXZ) - работают в любой сборке;
#  * цели декомпилируются первыми, вызывающие - после них (в v1 вызывающие первых целей съедали лимит);
#  * импорты: прямые вызовы (CALL [->USER32...]) отличаются от слотов IAT; в v1 адрес вызова печатался как "слот";
#  * поиск скаляров не только по вызывающим функции, но и по функциям, читающим указатель менеджера устройств;
#  * имя файла отчёта содержит версию и начало MD5.
#
# Запуск: Window -> Script Manager -> положи файл в ~/ghidra_scripts -> Run (на открытой сборке).
# Совместим по синтаксису и с Jython (Python 2.7), и с PyGhidra (Python 3).
# НЕ проверялся автором внутри Ghidra (только py_compile) - если упадёт, пришли текст ошибки из консоли.
#
# @category DS3Probe
from __future__ import print_function

import io
import os
from collections import OrderedDict

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.scalar import Scalar

# ----------------------------- НАСТРОЙКИ -----------------------------------
# MD5 exe -> набор адресов именно этой сборки. (имя, адрес hex, "func" | "data")
PROFILES = OrderedDict()

PROFILES["26c9e56f012c7138ef6a0aebad939595"] = {
    "name": "1.0.0.0",
    "targets": [
        ("PollMouseCursor",            "0040cc20", "func"),
        ("Mouse_GetState",             "0040a620", "func"),
        ("Mouse_WndMsg",               "0040d060", "func"),
        ("InputMapper_Update",         "00ac8210", "func"),
        ("ApplyControlConfiguration",  "00630fb0", "func"),
        ("GetPlayerObjectByIndex",     "00a830a0", "func"),
        ("g_MouseCallback",            "011acdf0", "data"),
        ("g_pfnMouseGetState",         "012863a0", "data"),
        ("g_mouseDX",                  "011acdd0", "data"),
        ("g_mouseDY",                  "011acdd4", "data"),
        ("g_mouseCaptured?",           "011acdce", "data"),
        ("g_cursorRecenterDisabled?",  "011acdee", "data"),
        ("g_inputDeviceMgr?",          "011ac914", "data"),
        ("IAT GetCursorPos",           "00d1735c", "data"),
        ("IAT SetCursorPos",           "00d172cc", "data"),
        ("IAT ClipCursor",             "00d17354", "data"),
    ],
    "scalar_callers": [("GetPlayerObjectByIndex", "00a830a0", [0x17C, 0x18C, 0x540, 0x574, 0x575])],
    "scalar_dataref": [("g_inputDeviceMgr?", "011ac914", [0x4EC, 0x540, 0x544, 0x574, 0x575, 0x578])],
}

PROFILES["1802f17a2cc1c2797323632862c6fb1f"] = {
    "name": "1.0.0.1",
    "targets": [
        # мышь: цепочка в геймплее
        ("Mouse_GetState",             "0040a820", "func"),
        ("Mouse_Recenter?",            "0040a7a0", "func"),
        ("Mouse_WndMsg",               "0040d270", "func"),
        ("PollMouseCursor",            "0040ce30", "func"),
        ("FUN_0040cfe0 (callback+SetCursorPos)", "0040cfe0", "func"),
        ("Mouse_SetCapture",           "0040d0c0", "func"),
        ("message pump (MainLoop?)",   "0040e080", "func"),
        # ввод и настройки (в отчёте v1 для 1.0.0.1 пропущены: проверка смещений +0x17C/+0x18C/+0x4EC/+0x574/+0x575)
        ("InputMapper_Update",         "00acb780", "func"),
        ("ApplyControlConfiguration",  "00632d90", "func"),
        ("GetPlayerObjectByIndex",     "00a868b0", "func"),
        ("LoadControlSettings",        "00645200", "func"),
        ("SaveControlSettings",        "006452e0", "func"),
        ("SetInvertX",                 "004ff2a0", "func"),
        ("SetInvertYAim",              "004ff2d0", "func"),
        ("SetInvertYFlight",           "004ff300", "func"),
        ("GetBackbufferHeight?",       "00b6bfd0", "func"),
        ("GetBackbufferWidth?",        "00b6bfe0", "func"),
        # данные
        ("g_MouseCallback",            "011d1df0", "data"),
        ("g_mouseDX",                  "011d1dd0", "data"),
        ("g_mouseDY",                  "011d1dd4", "data"),
        ("g_mouseCaptured?",           "011d1dce", "data"),
        ("g_cursorRecenterDisabled?",  "011d1dee", "data"),
        ("g_inputDeviceMgr?",          "011d1914", "data"),
        ("g_virtW?",                   "0133b0a8", "data"),
        ("g_virtH?",                   "0133b0ac", "data"),
    ],
    "scalar_callers": [("GetPlayerObjectByIndex", "00a868b0", [0x17C, 0x18C, 0x540, 0x574, 0x575])],
    "scalar_dataref": [("g_inputDeviceMgr?", "011d1914", [0x4EC, 0x540, 0x544, 0x574, 0x575, 0x578])],
}

# Символы по ИМЕНИ (версионно-независимо): экспорт Mouse::Init хранит указатель g_pfnMouseGetState
NAMED_SYMBOLS = ["?Init@Mouse@Windows@EARS@@YAXXZ", "Init"]

# Кто вызывает импортируемую функцию - по имени, без привязки к адресам
IMPORTS = ["GetCursorPos", "SetCursorPos", "ClipCursor", "ScreenToClient", "DirectInput8Create",
           "GetRawInputData", "RegisterRawInputDevices"]

MAX_DECOMPILE = 70          # сколько функций декомпилировать в отчёт (цели - первыми)
CALLER_DEPTH = 1            # 1 = прямые вызывающие
OUT_DIR = os.path.expanduser("~")
# ---------------------------------------------------------------------------

fm = currentProgram.getFunctionManager()          # noqa: F821 (глобалы Ghidra)
rm = currentProgram.getReferenceManager()         # noqa: F821
listing = currentProgram.getListing()             # noqa: F821
af = currentProgram.getAddressFactory()           # noqa: F821

lines = []
decomp_primary = OrderedDict()     # сами цели и функции, где найдены совпадения
decomp_callers = OrderedDict()     # вызывающие (после целей)


def W(s=u""):
    lines.append(u"{}".format(s))


def parse(h):
    return af.getAddress(h)


def fname(f):
    if f is None:
        return u"(вне функции)"
    return u"{}@{}".format(f.getName(), f.getEntryPoint())


def first_bytes(a, n):
    mem = currentProgram.getMemory()              # noqa: F821
    out = []
    for i in range(n):
        try:
            out.append(u"{:02X}".format(mem.getByte(a.add(i)) & 0xFF))
        except Exception:
            out.append(u"??")
    return u" ".join(out)


def instr_text(a):
    ins = listing.getInstructionAt(a)
    return u"{}".format(ins) if ins is not None else u""


def queue(f, primary=True):
    if f is None:
        return
    key = str(f.getEntryPoint())
    if primary:
        decomp_primary[key] = f
    elif key not in decomp_primary:
        decomp_callers[key] = f


def refs_table(a, queue_functions=True):
    refs = list(rm.getReferencesTo(a))
    if not refs:
        W(u"_ссылок нет_")
        return []
    refs.sort(key=lambda r: r.getFromAddress().getOffset())
    W(u"| откуда | тип | функция | инструкция |")
    W(u"|---|---|---|---|")
    for r in refs:
        frm = r.getFromAddress()
        f = fm.getFunctionContaining(frm)
        W(u"| {} | {} | {} | `{}` |".format(frm, r.getReferenceType(), fname(f), instr_text(frm)))
        if queue_functions:
            queue(f, primary=False)
    return refs


def callers_of(f):
    out = OrderedDict()
    for r in rm.getReferencesTo(f.getEntryPoint()):
        if r.getReferenceType().isCall():
            cf = fm.getFunctionContaining(r.getFromAddress())
            if cf is not None:
                out[str(cf.getEntryPoint())] = cf
    return list(out.values())


def walk_callers(f, depth):
    level = [f]
    for d in range(depth):
        nxt = []
        for x in level:
            for c in callers_of(x):
                queue(c, primary=False)
                nxt.append(c)
        level = nxt


def section_target(name, hexaddr, kind):
    W(u"\n## {} `{}`".format(name, hexaddr))
    a = parse(hexaddr)
    if a is None:
        W(u"_адрес не разобран_")
        return
    if kind == "func":
        f = fm.getFunctionAt(a)
        if f is None:
            W(u"_по адресу нет функции (создай её: клавиша F)_")
        else:
            queue(f, primary=True)
            walk_callers(f, CALLER_DEPTH)
    W(u"байты: `{}`".format(first_bytes(a, 24)))
    refs_table(a)


def section_named_symbols():
    W(u"\n# Символы по имени (версионно-независимо)")
    st = currentProgram.getSymbolTable()          # noqa: F821
    seen = set()
    for nm in NAMED_SYMBOLS:
        try:
            it = st.getSymbols(nm)
        except Exception as e:
            W(u"_ошибка поиска {}: {}_".format(nm, e))
            continue
        for sym in it:
            a = sym.getAddress()
            if str(a) in seen:
                continue
            ns = sym.getParentNamespace().getName() if sym.getParentNamespace() is not None else u""
            # короткое имя "Init" берём только если оно из пространства Mouse
            if nm == "Init" and u"Mouse" not in u"{}::{}".format(ns, sym.getName(True)):
                continue
            seen.add(str(a))
            W(u"\n## символ `{}` @{} ({})".format(sym.getName(True), a, sym.getSymbolType()))
            f = fm.getFunctionAt(a)
            if f is not None:
                queue(f, primary=True)
                walk_callers(f, CALLER_DEPTH)
            W(u"байты: `{}`".format(first_bytes(a, 24)))
            refs_table(a)
    if not seen:
        W(u"_символы не найдены_")


def scan_function_scalars(cf, offsets):
    hits = []
    for ins in listing.getInstructions(cf.getBody(), True):
        for op in range(ins.getNumOperands()):
            for o in ins.getOpObjects(op):
                if isinstance(o, Scalar) and o.getValue() in offsets:
                    hits.append(u"{}: `{}`".format(ins.getAddress(), ins))
    return hits


def section_scalar_callers(name, hexaddr, offsets):
    W(u"\n## Обращения к смещениям {} в вызывающих {}".format([hex(o) for o in offsets], name))
    a = parse(hexaddr)
    f = fm.getFunctionAt(a) if a is not None else None
    if f is None:
        W(u"_функция не найдена_")
        return
    any_hit = False
    for cf in sorted(callers_of(f), key=lambda x: x.getEntryPoint().getOffset()):
        hits = scan_function_scalars(cf, offsets)
        if hits:
            any_hit = True
            queue(cf, primary=True)
            W(u"\n**{}**".format(fname(cf)))
            for h in hits:
                W(u"- " + h)
    if not any_hit:
        W(u"_совпадений нет_")


def section_scalar_dataref(name, hexaddr, offsets):
    """Функции, которые читают данные по адресу (указатель менеджера), и обращения к смещениям внутри них."""
    W(u"\n## Обращения к смещениям {} в функциях, читающих {} `{}`".format([hex(o) for o in offsets], name, hexaddr))
    a = parse(hexaddr)
    if a is None:
        W(u"_адрес не разобран_")
        return
    funcs = OrderedDict()
    for r in rm.getReferencesTo(a):
        cf = fm.getFunctionContaining(r.getFromAddress())
        if cf is not None:
            funcs[str(cf.getEntryPoint())] = cf
    any_hit = False
    for cf in sorted(funcs.values(), key=lambda x: x.getEntryPoint().getOffset()):
        hits = scan_function_scalars(cf, offsets)
        if hits:
            any_hit = True
            queue(cf, primary=True)
            W(u"\n**{}**".format(fname(cf)))
            for h in hits[:20]:
                W(u"- " + h)
    W(u"\n_функций, читающих {}: {}_".format(name, len(funcs)))
    if not any_hit:
        W(u"_совпадений нет_")


def section_import(name):
    """Кто вызывает импортируемую функцию (по имени, без привязки к адресам версии)."""
    W(u"\n## import `{}`".format(name))
    found = False
    seen = set()
    try:
        for sym in currentProgram.getSymbolTable().getExternalSymbols():   # noqa: F821
            if sym.getName() != name:
                continue
            found = True
            for r in sym.getReferences():
                frm = r.getFromAddress()
                if str(frm) in seen:
                    continue
                seen.add(str(frm))
                if listing.getInstructionAt(frm) is not None:
                    # прямое использование: CALL [->DLL::Func] - frm это место вызова
                    f = fm.getFunctionContaining(frm)
                    W(u"- вызов `{}`: {} `{}`".format(frm, fname(f), instr_text(frm)))
                    queue(f, primary=False)
                else:
                    # данные: слот IAT / указатель; ссылки НА слот
                    W(u"\n### слот IAT `{}`".format(frm))
                    thunk = fm.getFunctionContaining(frm)
                    if thunk is not None:
                        queue(thunk, primary=False)
                        walk_callers(thunk, CALLER_DEPTH)
                    refs_table(frm)
    except Exception as e:                         # не роняем весь отчёт из-за одной секции
        W(u"_ошибка: {}_".format(e))
    if not found:
        W(u"_внешний символ не найден_")


def section_decompile():
    W(u"\n# Декомпиляция найденных функций (цели и совпадения - первыми, вызывающие - после)")
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)                # noqa: F821
    order = list(decomp_primary.values()) + [f for k, f in decomp_callers.items() if k not in decomp_primary]
    n = 0
    for f in order:
        if n >= MAX_DECOMPILE:
            W(u"\n_лимит MAX_DECOMPILE достигнут, остальные функции пропущены ({} не декомпилировано)_".format(len(order) - n))
            break
        res = ifc.decompileFunction(f, 60, monitor)  # noqa: F821
        W(u"\n### {}".format(fname(f)))
        if res.decompileCompleted():
            W(u"```c")
            W(res.getDecompiledFunction().getC())
            W(u"```")
        else:
            W(u"_декомпиляция не удалась: {}_".format(res.getErrorMessage()))
        n += 1


def main():
    md5 = currentProgram.getExecutableMD5()                      # noqa: F821
    prof = PROFILES.get(md5.lower()) if md5 else None
    tag = prof["name"] if prof else "unknown"
    out_path = os.path.join(OUT_DIR, u"ds3_report_{}_{}.md".format(tag, (md5 or u"nomd5")[:8]))
    W(u"# DS3 report v2")
    W(u"Программа: {}  |  база образа: {}".format(currentProgram.getName(), currentProgram.getImageBase()))  # noqa: F821
    W(u"Executable MD5: `{}`".format(md5))
    W(u"Executable path: `{}`".format(currentProgram.getExecutablePath()))                                   # noqa: F821
    W(u"Профиль адресов: **{}**".format(tag))
    W(u"Функций в базе: {}, инструкций: {}".format(fm.getFunctionCount(), listing.getNumInstructions()))     # быстрая проверка полноты анализа
    if prof:
        for name, hexaddr, kind in prof["targets"]:
            section_target(name, hexaddr, kind)
        for name, hexaddr, offsets in prof["scalar_callers"]:
            section_scalar_callers(name, hexaddr, offsets)
        for name, hexaddr, offsets in prof["scalar_dataref"]:
            section_scalar_dataref(name, hexaddr, offsets)
    else:
        W(u"\n**ВНИМАНИЕ:** MD5 этой сборки нет в PROFILES -> адресные цели ПРОПУЩЕНЫ, чтобы не строить отчёт по чужим адресам.")
        W(u"Ниже только цели по имени символа и по имени импорта. Добавь профиль (адреса из ds3_sigs_found.txt) в PROFILES.")
    section_named_symbols()
    for name in IMPORTS:
        section_import(name)
    section_decompile()
    with io.open(out_path, "w", encoding="utf-8") as fh:
        fh.write(u"\n".join(lines))
    print(u"DS3 report written: {}".format(out_path))


main()
