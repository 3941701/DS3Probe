# -*- coding: utf-8 -*-
# DS3 DiConsumers: кто в exe читает мышь через DirectInput и куда она потом течёт.
#
# Зачем. Пробе v3 показала: курсорный аккумулятор и DirectInput несут один и тот же сигнал, а камера при обнулённом
# аккумуляторе вращается как обычно. Значит, камеру кормит DirectInput (игра читает SysMouse каждый кадр), и потолок
# скорости поворота сидит ПОСЛЕ него. Raw Input и импорты тут не помогают: IDirectInputDevice8 вызывается через
# vtable (CALL dword ptr [reg+0x24]), поэтому xref по имени импорта не находит ничего.
#
# Что делает (версионно-независимо, работает на любой сборке):
#   1. Ищет все косвенные CALL [reg+off] с off из таблицы vtable IDirectInputDevice8
#      (0x18 SetProperty, 0x1C Acquire, 0x20 Unacquire, 0x24 GetDeviceState, 0x28 GetDeviceData,
#       0x2C SetDataFormat, 0x34 SetCooperativeLevel, 0x64 Poll).
#   2. Для GetDeviceState/GetDeviceData смотрит на PUSH-константы перед вызовом: размер буфера 0x14 / 0x10 -> мышь
#      (DIMOUSESTATE2 / DIMOUSESTATE), 0x100 -> клавиатура, 0x110 / 0x44 -> джойстик. Это ДОКАЗАТЕЛЬСТВО, а не догадка:
#      вызовы без такой константы помечены "размер неизвестен".
#   3. По найденным мышиным вызовам: функция, вызывающие (глубина 2), PUSH-адреса глобальных буферов (кандидаты
#      на буфер DIMOUSESTATE) со списком читателей, декомпиляция.
#   4. Если MD5 = 1.0.0.1: цепочка "стик" -> потребители (вызывающие FUN_0040E680 / FUN_0040D820 / FUN_00ABC510).
#
# Пишет ~/ds3_di_consumers_<md5[:8]>.md. Ничего не меняет в базе. Совместим с Jython и PyGhidra.
# НЕ проверялся автором внутри Ghidra (только py_compile и макет API) - если упадёт, пришли текст ошибки из консоли.
#
# @category DS3Probe
from __future__ import print_function

import io
import os
import re
from collections import OrderedDict

from ghidra.app.decompiler import DecompInterface

# ----------------------------- НАСТРОЙКИ -----------------------------------
VTABLE = OrderedDict([(0x18, "SetProperty"), (0x1C, "Acquire"), (0x20, "Unacquire"), (0x24, "GetDeviceState"),
                      (0x28, "GetDeviceData"), (0x2C, "SetDataFormat"), (0x34, "SetCooperativeLevel"), (0x64, "Poll")])
STATE_CALLS = (0x24, 0x28)              # по ним ищем размер буфера
LOOKBACK = 14                           # сколько инструкций назад смотреть PUSH-константы
CB_NAMES = {0x14: "мышь DIMOUSESTATE2 (c_dfDIMouse2, 20 байт)", 0x10: "мышь DIMOUSESTATE (c_dfDIMouse, 16 байт)",
            0x100: "клавиатура (256 байт)", 0x110: "джойстик DIJOYSTATE2", 0x44: "джойстик DIJOYSTATE"}
MOUSE_CB = (0x14, 0x10)
CALLER_DEPTH = 2
MAX_DECOMPILE = 40
MAX_LIST = 60                           # сколько вызовов печатать в сводной таблице на смещение

# Цели 1.0.0.1 (MD5 ниже): по ним строится цепочка "стик -> потребители". В других сборках пропускаются.
ADDRESSES_FOR_MD5 = "1802f17a2cc1c2797323632862c6fb1f"
STICK_TARGETS = [("StickVirt  (мышь как виртуальный стик, круговой клэмп 1.0)", "0040e680"),
                 ("StickSmooth (окно времени + клэмп +-this[3])", "0040d820"),
                 ("AxisPairFetch (читает пару осей для id устройства)", "00abc510"),
                 ("StickSmooth.push (кладёт отсчёт в окно)", "0040a860"),
                 ("StickSmooth.avg (взвешенное среднее окна)", "0040a8f0"),
                 ("IsMapped? (FUN_00a866a0)", "00a866a0")]
OUT_DIR = os.path.expanduser("~")
# ---------------------------------------------------------------------------

fm = currentProgram.getFunctionManager()          # noqa: F821 (глобалы Ghidra)
rm = currentProgram.getReferenceManager()         # noqa: F821
listing = currentProgram.getListing()             # noqa: F821
mem = currentProgram.getMemory()                  # noqa: F821
af = currentProgram.getAddressFactory()           # noqa: F821

lines = []
decomp_queue = OrderedDict()
CALL_RE = re.compile(r"^CALL\s+(?:dword ptr\s*)?\[\s*([A-Za-z]{3})\s*\+\s*(?:0x)?([0-9A-Fa-f]+)\s*\]\s*$")


def W(s=u""):
    lines.append(u"{}".format(s))


def fname(f):
    return u"(вне функции)" if f is None else u"{}@{}".format(f.getName(), f.getEntryPoint())


def queue(f):
    if f is not None:
        decomp_queue[str(f.getEntryPoint())] = f


def safe(fn, label):
    try:
        fn()
    except Exception as e:                         # noqa: BLE001
        W(u"\n_секция {} упала: {}_".format(label, e))


def callers_of(f):
    out = OrderedDict()
    for r in rm.getReferencesTo(f.getEntryPoint()):
        if r.getReferenceType().isCall():
            cf = fm.getFunctionContaining(r.getFromAddress())
            if cf is not None:
                out[str(cf.getEntryPoint())] = cf
    return list(out.values())


def callers_levels(f, depth):
    """[[(функция, чей вызывающий)] на каждом уровне]"""
    levels = []
    cur = [f]
    seen = set([str(f.getEntryPoint())])
    for _ in range(depth):
        nxt = []
        for x in cur:
            for c in callers_of(x):
                k = str(c.getEntryPoint())
                if k in seen:
                    continue
                seen.add(k)
                nxt.append(c)
        levels.append(nxt)
        cur = nxt
    return levels


def scalar_of(ins, i=0):
    try:
        s = ins.getScalar(i)
        return None if s is None else int(s.getUnsignedValue())
    except Exception:                              # noqa: BLE001
        return None


def lookback(ins):
    """PUSH-константы перед вызовом (ближайшие первыми) + признак LEA/другой PUSH. Останавливаемся на RET и на пределе."""
    pushes = []
    k = 0
    p = ins.getPrevious()
    fn0 = fm.getFunctionContaining(ins.getAddress())
    while p is not None and k < LOOKBACK:
        if fm.getFunctionContaining(p.getAddress()) != fn0:
            break
        mn = p.getMnemonicString()
        if mn in ("RET", "RETN"):
            break
        if mn == "PUSH":
            v = scalar_of(p, 0)
            pushes.append((p.getAddress(), v, str(p)))
        p = p.getPrevious()
        k += 1
    return pushes


def is_data_addr(v):
    if v is None or v < 0x400000:
        return False
    try:
        a = af.getAddress("%08x" % v)
        blk = mem.getBlock(a)
        return blk is not None and not blk.isExecute()
    except Exception:                              # noqa: BLE001
        return False


# ------------------------------------------------------------------ 1-2. вызовы vtable
def collect_calls():
    hits = OrderedDict((off, []) for off in VTABLE)
    n_all = 0
    for ins in listing.getInstructions(True):
        if ins.getMnemonicString() != "CALL":
            continue
        n_all += 1
        m = CALL_RE.match(str(ins))
        if not m:
            continue
        off = int(m.group(2), 16)
        if off not in hits:
            continue
        pushes = lookback(ins) if off in STATE_CALLS else []
        hits[off].append({"addr": ins.getAddress(), "reg": m.group(1).upper(), "ins": str(ins),
                          "func": fm.getFunctionContaining(ins.getAddress()), "pushes": pushes})
    return hits, n_all


def classify(call):
    """Ближайшая подходящая константа-размер из CB_NAMES. Возвращает (cb | None, текст)."""
    for (a, v, t) in call["pushes"]:
        if v in CB_NAMES:
            return v, CB_NAMES[v]
    return None, "размер неизвестен"


def section_calls(hits, n_all):
    W(u"# 1. Косвенные вызовы методов IDirectInputDevice8 (по vtable)")
    W(u"Всего CALL в программе: {}. Совпадение по смещению vtable ещё НЕ доказывает DirectInput: те же смещения есть у любых COM/C++-объектов. "
      u"Доказательство - константа размера буфера перед вызовом (колонка evidence).".format(n_all))
    mouse = []
    for off, name in VTABLE.items():
        lst = hits[off]
        W(u"\n## [reg+0x{:X}] {} - {} вызовов".format(off, name, len(lst)))
        if not lst:
            continue
        W(u"| адрес | функция | инструкция | evidence | PUSH-константы перед вызовом (ближайшие первыми) |")
        W(u"|---|---|---|---|---|")
        for c in lst[:MAX_LIST]:
            cb, text = (classify(c) if off in STATE_CALLS else (None, u"-"))
            pu = u", ".join(u"{}".format(("0x%X" % v) if v is not None else "?") for (_, v, _) in c["pushes"][:8])
            W(u"| {} | {} | `{}` | {} | {} |".format(c["addr"], fname(c["func"]), c["ins"], text, pu))
            if off in STATE_CALLS and cb in MOUSE_CB:
                mouse.append((off, c))
                queue(c["func"])
        if len(lst) > MAX_LIST:
            W(u"_... ещё {} вызовов не показаны_".format(len(lst) - MAX_LIST))
    return mouse


# ------------------------------------------------------------------ 3. мышиные вызовы: вызывающие, буферы
def section_mouse(mouse):
    W(u"\n# 2. Мышиные чтения DirectInput (evidence: размер 0x14 / 0x10)")
    if not mouse:
        W(u"_ни одного вызова GetDeviceState/GetDeviceData с константой 0x14/0x10 перед вызовом._ "
          u"Возможные причины: размер передаётся через регистр/переменную (смотри таблицу выше: 'размер неизвестен'), "
          u"или вызов идёт через обёртку. Тогда см. стек вызывающих из DS3Probe (F6, таблица callers DI_mouse_State).")
        return
    seen = set()
    for off, c in mouse:
        f = c["func"]
        if f is None:
            W(u"\n**{} {}**: вызов вне функции (создай функцию: клавиша F)".format(VTABLE[off], c["addr"]))
            continue
        key = str(f.getEntryPoint())
        W(u"\n## {} в {} (вызов {})".format(VTABLE[off], fname(f), c["addr"]))
        W(u"PUSH-константы: " + u", ".join(("0x%X" % v) if v is not None else "?" for (_, v, _) in c["pushes"][:8]))
        bufs = [v for (_, v, _) in c["pushes"] if v not in CB_NAMES and is_data_addr(v)]
        if bufs:
            W(u"\nPUSH-адреса данных рядом (кандидаты на глобальный буфер DIMOUSESTATE):")
            for v in bufs[:4]:
                W(u"- `{:08x}`".format(v))
                for dv in (0, 4, 8):
                    a = af.getAddress("%08x" % (v + dv))
                    refs = [r for r in rm.getReferencesTo(a)]
                    for r in refs[:10]:
                        rf = fm.getFunctionContaining(r.getFromAddress())
                        W(u"  - +{} {} {} {}".format(dv, r.getReferenceType(), r.getFromAddress(), fname(rf)))
                        queue(rf)
        else:
            W(u"_PUSH-адресов глобальных данных нет: буфер, вероятно, локальный или поле объекта (смотри декомпиляцию)._")
        if key in seen:
            continue
        seen.add(key)
        levels = callers_levels(f, CALLER_DEPTH)
        for i, lv in enumerate(levels, 1):
            W(u"\nВызывающие, уровень {}: ".format(i) + (u", ".join(fname(x) for x in lv[:20]) if lv else u"-"))
            for x in lv[:20]:
                queue(x)


# ------------------------------------------------------------------ 4. цепочка "стик" (1.0.0.1)
def section_sticks():
    W(u"\n# 3. Цепочка 'стик' (1.0.0.1): кто потребляет выход FUN_0040E680 / FUN_0040D820")
    md5 = currentProgram.getExecutableMD5()        # noqa: F821
    if md5 is None or md5.lower() != ADDRESSES_FOR_MD5:
        W(u"_MD5 {} не равен {}: адреса 1.0.0.1 пропущены._".format(md5, ADDRESSES_FOR_MD5))
        return
    for title, ha in STICK_TARGETS:
        a = af.getAddress(ha)
        f = fm.getFunctionAt(a)
        W(u"\n## {} `{}`".format(title, ha))
        if f is None:
            W(u"_по адресу нет функции_")
            continue
        queue(f)
        levels = callers_levels(f, CALLER_DEPTH)
        for i, lv in enumerate(levels, 1):
            W(u"- уровень {}: ".format(i) + (u", ".join(fname(x) for x in lv[:25]) if lv else u"-"))
            for x in lv[:25]:
                queue(x)


def section_decompile():
    W(u"\n# 4. Декомпиляция")
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)                # noqa: F821
    n = 0
    for key, f in decomp_queue.items():
        if n >= MAX_DECOMPILE:
            W(u"\n_лимит MAX_DECOMPILE достигнут, остальные функции пропущены: {}_".format(len(decomp_queue) - n))
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
    W(u"# DS3 DiConsumers")
    W(u"Программа: {} | база образа: {} | MD5: `{}`".format(currentProgram.getName(), currentProgram.getImageBase(),   # noqa: F821
                                                            currentProgram.getExecutableMD5()))                       # noqa: F821
    state = {}

    def s1():
        hits, n_all = collect_calls()
        state["mouse"] = section_calls(hits, n_all)
    safe(s1, "calls")
    safe(lambda: section_mouse(state.get("mouse", [])), "mouse")
    safe(section_sticks, "sticks")
    safe(section_decompile, "decompile")
    md5 = currentProgram.getExecutableMD5() or "unknown"       # noqa: F821
    path = os.path.join(OUT_DIR, "ds3_di_consumers_{}.md".format(md5[:8]))
    with io.open(path, "w", encoding="utf-8") as fh:
        fh.write(u"\n".join(lines))
    print(u"DS3 DiConsumers written: {}".format(path))


main()
