# -*- coding: utf-8 -*-
# DS3 hunt: три быстрых проверки на рабочем ПК, ответы на вопросы аудита 2026-10-07 (разделы 2.7, 3, 7).
#
#  1. HEALTH   - полнота анализа текущей базы: блоки памяти, число функций/инструкций, включённые анализаторы.
#                (В базе 1.0.0.1 на 10.5% меньше инструкций и на 6.8% меньше функций, чем в 1.0.0.0 - либо анализ не
#                 закончился, либо опции разные. Запусти на ОБЕИХ сборках и сравни два файла.)
#  2. STRINGS  - строки по шаблонам (smooth, mouse, sensitiv, control. ...) со ссылками и функциями.
#                Главное: есть ли в 1.0.0.1 строка MouseSmoothing - ссылка на неё ведёт к коду сглаживания.
#  3. RTTI     - таблицы виртуальных методов классов по шаблонам (Camera, Aim, Mouse, Input, Player*SM ...)
#                с первыми виртуальными методами: зацепки для второй половины цепочки (MouseState -> камера).
#
# Пишет ~/ds3_hunt_<версия>_<md5[:8]>.md. Ничего не меняет в базе. Совместим с Jython и PyGhidra.
# НЕ проверялся автором внутри Ghidra (только py_compile) - если упадёт, пришли текст ошибки из консоли.
#
# @category DS3Probe
from __future__ import print_function

import io
import os
import re
from collections import OrderedDict

from ghidra.app.decompiler import DecompInterface

# ----------------------------- НАСТРОЙКИ -----------------------------------
STRING_PATTERNS = ["smooth", "mousesmooth", "mouse", "sensitiv", "control.", "invert", "lookspeed",
                   "turnspeed", "cameraspeed", "framerate", "frametime", "vsync", "fps"]
STRING_MAX_HITS = 120           # сколько строк печатать
STRING_MAX_REFS = 6             # ссылок на строку
RTTI_CLASS_REGEX = r"(?i)camera|aim|mouse|input|player.*sm|orbit|look|turn|control|fps|cursor|device"
RTTI_MAX_CLASSES = 80
RTTI_VMETHODS = 10              # сколько виртуальных методов печатать на класс
DECOMPILE_STRING_FUNCS = 12     # сколько функций со ссылками на подходящие строки декомпилировать
DEEP_COVERAGE = False           # True: посчитать долю исполняемых блоков, покрытую инструкциями (минуты на большом exe)
OUT_DIR = os.path.expanduser("~")
# ---------------------------------------------------------------------------

fm = currentProgram.getFunctionManager()          # noqa: F821
rm = currentProgram.getReferenceManager()         # noqa: F821
listing = currentProgram.getListing()             # noqa: F821
mem = currentProgram.getMemory()                  # noqa: F821
af = currentProgram.getAddressFactory()           # noqa: F821
lines = []
decomp_queue = OrderedDict()


def W(s=u""):
    lines.append(u"{}".format(s))


def fname(f):
    return u"(вне функции)" if f is None else u"{}@{}".format(f.getName(), f.getEntryPoint())


def safe(fn, label):
    """Секция не должна ронять весь отчёт."""
    try:
        fn()
    except Exception as e:                        # noqa: BLE001
        W(u"\n_секция {} упала: {}_".format(label, e))


# --------------------------------------------------------------------- HEALTH
def section_health():
    W(u"\n# 1. HEALTH: полнота анализа")
    W(u"Функций: **{}**, инструкций: **{}**, определённых данных: **{}**".format(
        fm.getFunctionCount(), listing.getNumInstructions(), listing.getNumDefinedData()))
    W(u"\n| блок | начало | конец | размер | RWX | init | overlay |")
    W(u"|---|---|---|---|---|---|---|")
    exec_total = 0
    for b in mem.getBlocks():
        perms = (u"R" if b.isRead() else u"-") + (u"W" if b.isWrite() else u"-") + (u"X" if b.isExecute() else u"-")
        if b.isExecute():
            exec_total += b.getSize()
        W(u"| {} | {} | {} | 0x{:X} | {} | {} | {} |".format(b.getName(), b.getStart(), b.getEnd(), b.getSize(), perms, b.isInitialized(), b.isOverlay()))
    W(u"\nИсполняемых байт: 0x{:X}".format(exec_total))
    try:
        W(u"Точки входа: " + u", ".join(u"{}".format(a) for a in currentProgram.getSymbolTable().getExternalEntryPointIterator()))  # noqa: F821
    except Exception as e:                        # noqa: BLE001
        W(u"_точки входа: {}_".format(e))
    if DEEP_COVERAGE:
        covered = 0
        for b in mem.getBlocks():
            if not b.isExecute():
                continue
            monitor.checkCancelled()              # noqa: F821
            for ins in listing.getInstructions(b.getStart(), True):
                if ins.getAddress().compareTo(b.getEnd()) > 0:
                    break
                covered += ins.getLength()
        W(u"Покрыто инструкциями: 0x{:X} из 0x{:X} ({:.1f}%)".format(covered, exec_total, 100.0 * covered / exec_total if exec_total else 0))
    try:
        opts = currentProgram.getOptions("Analyzers")   # noqa: F821
        names = sorted(opts.getOptionNames())
        W(u"\n## Анализаторы (сравни с другой сборкой: отличия = разные опции анализа)")
        for n in names:
            W(u"- {} = {}".format(n, opts.getValueAsString(n)))
    except Exception as e:                        # noqa: BLE001
        W(u"_опции анализаторов недоступны: {}_".format(e))


# --------------------------------------------------------------------- STRINGS
def iter_strings():
    try:
        from ghidra.program.util import DefinedDataIterator
        for d in DefinedDataIterator.definedStrings(currentProgram):   # noqa: F821
            yield d
        return
    except Exception:                             # noqa: BLE001
        pass
    for d in listing.getDefinedData(True):
        t = d.getDataType().getName().lower()
        if "string" in t or "unicode" in t:
            yield d


def section_strings():
    W(u"\n# 2. STRINGS")
    pats = [p.lower() for p in STRING_PATTERNS]
    hits = []
    total = 0
    for d in iter_strings():
        total += 1
        v = d.getValue()
        if v is None:
            continue
        s = u"{}".format(v)
        low = s.lower()
        matched = [p for p in pats if p in low]
        if matched:
            hits.append((d, s, matched))
    W(u"Всего строк: {}, подошло по шаблонам: {}".format(total, len(hits)))
    # сначала более специфичные совпадения (smooth), потом остальные
    hits.sort(key=lambda h: (0 if any(m.startswith("smooth") or m.startswith("mousesmooth") for m in h[2]) else 1, str(h[0].getAddress())))
    for d, s, matched in hits[:STRING_MAX_HITS]:
        a = d.getAddress()
        W(u"\n**{}** `{}` {}".format(a, s[:110].replace(u"`", u"'"), matched))
        refs = list(rm.getReferencesTo(a))
        if not refs:
            W(u"  ссылок нет (строка может адресоваться через таблицу/хеш)")
        for r in refs[:STRING_MAX_REFS]:
            f = fm.getFunctionContaining(r.getFromAddress())
            W(u"  - {} в {}".format(r.getFromAddress(), fname(f)))
            if f is not None and any(m.startswith("smooth") or m.startswith("mousesmooth") or m == "control." for m in matched):
                decomp_queue[str(f.getEntryPoint())] = f
    if len(hits) > STRING_MAX_HITS:
        W(u"\n_показано {} из {}; сузь STRING_PATTERNS_".format(STRING_MAX_HITS, len(hits)))
    if not any("smooth" in h[1].lower() for h in hits):
        W(u"\n**Строки со 'smooth' в этой сборке НЕТ.** Совет PCGamingWiki про control.MouseSmoothing может не относиться к этому exe "
          u"(или ключ собирается из частей / лежит в данных игры).")


# --------------------------------------------------------------------- RTTI
def read_ptr(a):
    try:
        return mem.getInt(a) & 0xFFFFFFFF
    except Exception:                             # noqa: BLE001
        return None


def section_rtti():
    W(u"\n# 3. RTTI: виртуальные таблицы классов по шаблону /{}/".format(RTTI_CLASS_REGEX))
    st = currentProgram.getSymbolTable()          # noqa: F821
    rx = re.compile(RTTI_CLASS_REGEX)
    classes = OrderedDict()
    n_all = 0
    for sym in st.getSymbols("vftable"):
        n_all += 1
        ns = sym.getParentNamespace()
        cname = ns.getName(True) if ns is not None else u"?"
        if rx.search(cname):
            classes.setdefault(cname, []).append(sym.getAddress())
    W(u"Всего vftable-символов: {}, подошло по шаблону классов: {}".format(n_all, len(classes)))
    if n_all == 0:
        W(u"_vftable-символов нет: RTTI-анализатор не запускался или имена другие (ищи через Symbol Tree -> Classes)_")
        return
    for cname in sorted(classes.keys())[:RTTI_MAX_CLASSES]:
        for va in classes[cname]:
            W(u"\n**{}** vftable @{}".format(cname, va))
            for i in range(RTTI_VMETHODS):
                p = read_ptr(va.add(4 * i))
                if p is None or p < 0x400000 or p > 0x1000000:
                    break
                fa = af.getAddress(u"{:08x}".format(p))
                f = fm.getFunctionAt(fa) if fa is not None else None
                if f is None:
                    break
                W(u"  - [{}] {}".format(i, fname(f)))


def section_decompile():
    if not decomp_queue:
        return
    W(u"\n# Декомпиляция функций со ссылками на 'smooth'/'control.'")
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)                # noqa: F821
    for n, f in enumerate(decomp_queue.values()):
        if n >= DECOMPILE_STRING_FUNCS:
            W(u"\n_лимит DECOMPILE_STRING_FUNCS_")
            break
        res = ifc.decompileFunction(f, 60, monitor)  # noqa: F821
        W(u"\n### {}".format(fname(f)))
        if res.decompileCompleted():
            W(u"```c")
            W(res.getDecompiledFunction().getC())
            W(u"```")
        else:
            W(u"_декомпиляция не удалась: {}_".format(res.getErrorMessage()))


def main():
    md5 = currentProgram.getExecutableMD5() or u"nomd5"   # noqa: F821
    out_path = os.path.join(OUT_DIR, u"ds3_hunt_{}_{}.md".format(currentProgram.getName().replace(u" ", u"_"), md5[:8]))  # noqa: F821
    W(u"# DS3 hunt")
    W(u"Программа: {} | MD5 `{}` | база образа {}".format(currentProgram.getName(), md5, currentProgram.getImageBase()))   # noqa: F821
    safe(section_health, "HEALTH")
    safe(section_strings, "STRINGS")
    safe(section_rtti, "RTTI")
    safe(section_decompile, "DECOMPILE")
    with io.open(out_path, "w", encoding="utf-8") as fh:
        fh.write(u"\n".join(lines))
    print(u"DS3 hunt written: {}".format(out_path))


main()
