# -*- coding: utf-8 -*-
# DS3 CamChain: что происходит с выходом стика ПОСЛЕ FUN_0040D820 (второй ограничитель поворота камеры).
#
# Зачем. Данные 20261008_082440 показали: первый потолок - клэмп +-this[3] (=2.0) в FUN_0040D820 (формула окна подобрана с
# ошибкой <1e-5, потолок ~2300 отсчётов/с, он съедает 56-69% горизонтального поворота). Но с открытым клэмпом (F11) резкий
# рывок "подклинивает, упирается в невидимое и отскакивает в то же место". В декомпиляции FUN_0073f310 (основной look-апдейт)
# после поворота FUN_00721bd0(...) идёт вызов FUN_004fdf60, а потом, если он вернул true и local_40 == this, состояние камеры
# (40 dword) ВОЗВРАЩАЕТСЯ из копии, снятой в начале функции: поворот откатывается. Скрипт собирает всё, чтобы это проверить.
#
# Что делает (адреса 1.0.0.1; на другой сборке MD5 не совпадёт - секции с адресами пропускаются):
#   0. Готовые строки для ds3probe.cfg (Trace1..Trace8): байты начала функций + хук после CALL FUN_004fdf60 (читает eax) и
#      на входе в блок отката. Скопируй блок целиком в ds3probe.cfg рядом с deadspace3.exe.
#   1. Значения констант-флоатов, которые встречаются в формулах (_DAT_00d22bb0 и др.).
#   2. Поиск конструктора сглаживателя стика: функции, где есть константа 0x3D088889 (1/30) - кандидаты на запись win/clamp.
#   3. FUN_0073f310: дизассемблер вокруг вызовов FUN_004fdf60 и блок отката (чтобы увидеть условие точно, без декомпилятора).
#   4. Вызывающие FUN_00721bd0 / FUN_004fdf60 (глубина 2).
#   5. Декомпиляция целевых функций и вызывающих FUN_004fdf60 (1-й уровень).
#
# Пишет ~/ds3_camchain_<md5[:8]>.md. Ничего не меняет в базе. Совместим с Jython и PyGhidra.
# НЕ проверялся автором внутри Ghidra (только py_compile и макет API) - если упадёт, пришли текст ошибки из консоли.
#
# @category DS3Probe
from __future__ import print_function

import io
import os
import re
import struct
from collections import OrderedDict

from ghidra.app.decompiler import DecompInterface

# ----------------------------- НАСТРОЙКИ -----------------------------------
ADDRESSES_FOR_MD5 = "1802f17a2cc1c2797323632862c6fb1f"
OUT_DIR = os.path.expanduser("~")
MAX_DECOMPILE = 60
CALLER_DEPTH = 2
MAX_LIST = 40
CTX_BEFORE = 14                  # инструкций до интересующей точки в дизассемблере
CTX_AFTER = 40                   # и после
HOOK_BYTES_MIN = 10              # сколько байт начала брать для .bytes (целыми инструкциями)

# Функции для полной декомпиляции: (адрес, зачем)
DECOMP_TARGETS = [
    ("004fdf60", "проверка после поворота в FUN_0073f310: true => откат состояния камеры?"),
    ("00721bd0", "применить дельту (pitch, yaw, roll, 0) к камере"),
    ("00721d20", "геттер (pitch или yaw?) - вызывается в FUN_005906a0 / FUN_00552030"),
    ("00721d30", "сеттер/сброс"),
    ("00b32040", "геттер второго угла"),
    ("0073ceb0", "вызывается после поворота в FUN_005906a0 (фиксация/применение?)"),
    ("0073d840", "трассировка/доля пути в FUN_0074baa0 (коллизия камеры?)"),
    ("0040a860", "StickSmooth.push"),
    ("0040a8f0", "StickSmooth.avg"),
    ("0042ed00", "чувствительность yaw (обычный режим)"),
    ("0042ed80", "чувствительность yaw (режим 1)"),
    ("0042ee00", "чувствительность yaw (режим 2)"),
    ("0042ee80", "чувствительность pitch"),
    ("0043af60", "множитель после FUN_005438a0 (X)"),
    ("0043af20", "множитель после FUN_005438a0 (Y)"),
    ("005438a0", "кривая отклика стика (FUN_00549ea0)"),
    ("00ab8f60", "клэмп пары на единичный круг (флаг 1 в FUN_00abc510)"),
    ("00ab9830", "мёртвая зона / кривая (флаг 7 в FUN_00abc510)"),
    ("00aa22d0", "поиск объекта по id (камера / игрок)"),
    ("00721300", "в FUN_0073f310 влияет на множитель local_28 (оружие?)"),
    ("0056d150", "в FUN_0073f310 влияет на множитель local_28"),
    ("00443e60", "индекс игрока для битовых масок инверсии осей"),
    ("0074baa0", "следование камеры (сглаживание позиции + трассировка)"),
]

# Константы: (адрес, зачем). Печатаются как float и как hex dword.
CONSTANTS = [
    ("00d22bb0", "C в FUN_0040D820 (делитель выхода: out = clamp(Xb)/(Tb*C)); по данным = 30.0"),
    ("00d1ff7c", "порог/мёртвая зона по умолчанию (параметры FUN_00abc510)"),
    ("00d53810", "порог активности в FUN_0040D820"),
    ("00d2047c", "порог 'есть ввод' в FUN_0073f310"),
    ("00d4c2a8", "нижняя граница обёртки yaw (-pi?)"),
    ("00d27bc0", "верхняя граница обёртки yaw (pi?)"),
    ("00ed2e98", "2*pi?"),
    ("012a9aa8", "глобальный dt кадра"),
    ("012a9b08", "глобальная константа времени (используется как допуск)"),
    ("00d28718", "множитель инверсии оси (-1?)"),
    ("00d26dd8", "градусы->радианы? (множитель в 00647820 / 00552030)"),
    ("00d4c1c8", "порог/мёртвая зона (FUN_00549ea0)"),
    ("00d20590", "0.5?"),
    ("00d7ca08", "знаменатель в FUN_0067a420"),
    ("00d34bc0", "порог в FUN_0067a420"),
    ("00d320f8", "множитель в FUN_0074baa0"),
    ("00d27e68", "множитель в FUN_0043b770 / 0074baa0"),
    ("01227db8", "битовая маска инверсии X по игрокам"),
    ("01227dbc", "битовая маска инверсии Y по игрокам"),
]

# Трассировщики для cfg: (адрес, имя, args, this_dwords, fields)
TRACE_FUNCS = [
    ("00721bd0", "ApplyRotDelta", 6, 0, []),
    ("0073f310", "LookUpdate", 2, 0, [0x70, 0x150, 0x158, 0xC8, 0xCC, 0xD0, 0xD4, 0xD8, 0x74, 0x7C, 0x90, 0x134, 0x138, 0x164, 0x1D0, 0x618]),
    ("004fdf60", "CamCheck", 6, 6, []),
    ("0073ceb0", "CamCommit", 4, 4, []),
    ("0074baa0", "CamFollow", 4, 0, [0x70, 0x170, 0x174, 0x178, 0x1A0, 0x1A4, 0x1A8, 0x1B4, 0x1B8, 0x1BC]),
    ("005906a0", "LookB", 2, 0, [0x70, 0xA8, 0xAC, 0x90, 0x14]),
]
# ---------------------------------------------------------------------------

fm = currentProgram.getFunctionManager()          # noqa: F821 (глобалы Ghidra)
rm = currentProgram.getReferenceManager()         # noqa: F821
listing = currentProgram.getListing()             # noqa: F821
mem = currentProgram.getMemory()                  # noqa: F821
af = currentProgram.getAddressFactory()           # noqa: F821

lines = []
decomp_queue = OrderedDict()


def W(s=u""):
    lines.append(u"{}".format(s))


def A(h):
    return af.getAddress(h if isinstance(h, str) else "%08x" % h)


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


def ins_bytes(ins):
    try:
        return [int(b) & 0xFF for b in ins.getBytes()]
    except Exception:                              # noqa: BLE001
        return []


def hexbytes(bs):
    return u" ".join(u"%02X" % b for b in bs)


def bytes_from(addr, minimum=HOOK_BYTES_MIN):
    """байты целыми инструкциями от addr, пока не наберётся minimum; (список байт, число инструкций)"""
    out = []
    n = 0
    ins = listing.getInstructionAt(addr)
    while ins is not None and len(out) < minimum and n < 6:
        out += ins_bytes(ins)
        n += 1
        ins = ins.getNext()
    return out, n


def disasm(start, before, after, mark=None):
    """строки дизассемблера: [before инструкций до start] + [after после]"""
    ins = listing.getInstructionAt(start)
    if ins is None:
        return [u"_нет инструкции по адресу {}_".format(start)]
    cur = ins
    for _ in range(before):
        p = cur.getPrevious()
        if p is None:
            break
        cur = p
    res = []
    k = 0
    total = before + after + 1
    while cur is not None and k < total:
        flag = u"=>" if (mark is not None and str(cur.getAddress()) in mark) else u"  "
        res.append(u"{} {}  {:<24} {}".format(flag, cur.getAddress(), hexbytes(ins_bytes(cur)), cur))
        cur = cur.getNext()
        k += 1
    return res


def read_dword(addr):
    try:
        return int(mem.getInt(addr)) & 0xFFFFFFFF
    except Exception:                              # noqa: BLE001
        return None


def as_float(u):
    return struct.unpack("<f", struct.pack("<I", u & 0xFFFFFFFF))[0]


# ------------------------------------------------------------------ 3. FUN_0073f310: откат
def find_look_func():
    return fm.getFunctionAt(A("0073f310"))


def call_sites(func, target_entry):
    """CALL-инструкции внутри func на target_entry"""
    res = []
    if func is None:
        return res
    body = func.getBody()
    it = listing.getInstructions(body, True)
    for ins in it:
        if ins.getMnemonicString() != "CALL":
            continue
        try:
            for r in ins.getReferencesFrom():
                if r.getReferenceType().isCall() and str(r.getToAddress()) == str(target_entry):
                    res.append(ins)
        except Exception:                          # noqa: BLE001
            pass
    return res


def find_revert_block(func, after_addr):
    """первая инструкция вида MOV ECX,0x28 строго после after_addr внутри func: начало цикла копирования 160 байт (откат)"""
    body = func.getBody()
    for ins in listing.getInstructions(body, True):
        if ins.getAddress().compareTo(after_addr) <= 0:
            continue
        if ins.getMnemonicString() == "MOV" and scalar_of(ins, 1) == 0x28 and str(ins).upper().find("ECX") >= 0:
            return ins
    return None


def section_revert(state):
    W(u"\n# 3. FUN_0073f310: вызовы FUN_004fdf60 и блок отката")
    look = find_look_func()
    chk = fm.getFunctionAt(A("004fdf60"))
    if look is None or chk is None:
        W(u"_нет функции FUN_0073f310 или FUN_004fdf60 по этим адресам_")
        return
    sites = call_sites(look, chk.getEntryPoint())
    W(u"Вызовов FUN_004fdf60 внутри FUN_0073f310: {}".format(len(sites)))
    for ins in sites:
        W(u"\n## CALL по {}".format(ins.getAddress()))
        W(u"```")
        marks = set([str(ins.getAddress())])
        rev = find_revert_block(look, ins.getAddress())
        if rev is not None:
            marks.add(str(rev.getAddress()))
        for l in disasm(ins.getAddress(), CTX_BEFORE, CTX_AFTER, marks):
            W(l)
        W(u"```")
        nxt = ins.getNext()
        if nxt is not None:
            state["post_call"] = nxt.getAddress()
        if rev is not None:
            state["revert"] = rev.getAddress()
            W(u"Кандидат на начало блока отката (MOV ECX,0x28 после вызова): {}".format(rev.getAddress()))
        else:
            W(u"_MOV ECX,0x28 после вызова не найден: блок отката ищи глазами в дизассемблере выше_")


# ------------------------------------------------------------------ 0. cfg
def section_cfg(state):
    W(u"\n# 0. Готовый блок для ds3probe.cfg (v4.1)")
    W(u"Положи рядом с `deadspace3.exe` как `ds3probe.cfg` (или добавь к существующему). Хуки ставятся ТОЛЬКО если байты совпали "
      u"с памятью игры; в логе будут строки `TraceN ... hook: ok`. Максимум 8 трассировщиков.")
    W(u"```")
    W(u"# --- вставлено DS3_CamChain.py ---")
    idx = 0
    for h, name, args, thisd, fields in TRACE_FUNCS:
        idx += 1
        f = fm.getFunctionAt(A(h))
        if f is None:
            W(u"# Trace{}: по {} нет функции - пропущено".format(idx, h))
            continue
        bs, n = bytes_from(f.getEntryPoint())
        W(u"Trace{} = {}".format(idx, h.upper()))
        W(u"Trace{}.bytes = {}".format(idx, hexbytes(bs)))
        W(u"Trace{}.name = {}".format(idx, name))
        W(u"Trace{}.args = {}".format(idx, args))
        W(u"Trace{}.this = {}".format(idx, thisd))
        if fields:
            W(u"Trace{}.fields = {}".format(idx, u" ".join(u"%X" % x for x in fields)))
    pc = state.get("post_call")
    if pc is not None and idx < 8:
        idx += 1
        bs, n = bytes_from(pc)
        W(u"# хук сразу после CALL FUN_004fdf60 (в колонке eax будет его возвращаемое значение)")
        W(u"Trace{} = {}".format(idx, str(pc).upper()))
        W(u"Trace{}.bytes = {}".format(idx, hexbytes(bs)))
        W(u"Trace{}.name = CamCheckRet".format(idx))
        W(u"Trace{}.args = 4".format(idx))
        W(u"Trace{}.this = 0".format(idx))
    rv = state.get("revert")
    if rv is not None and idx < 8:
        idx += 1
        bs, n = bytes_from(rv)
        W(u"# хук на начало блока отката: вызов = состояние камеры возвращено из копии")
        W(u"Trace{} = {}".format(idx, str(rv).upper()))
        W(u"Trace{}.bytes = {}".format(idx, hexbytes(bs)))
        W(u"Trace{}.name = RevertExec".format(idx))
        W(u"Trace{}.args = 2".format(idx))
        W(u"Trace{}.this = 0".format(idx))
    W(u"```")
    W(u"Замечания: для функций, где соглашение вызова неизвестно, `args` снимает dword со стека (a0 - первый аргумент после адреса возврата); "
      u"`this`/`fields` читаются по ecx. Для хуков посреди функции (CamCheckRet, RevertExec) ecx может не быть this - "
      u"смотри eax и стек. В `FUN_0073f310` `this` = ecx (thiscall), dt = a0.")


# ------------------------------------------------------------------ 1. константы
def section_constants():
    W(u"\n# 1. Константы")
    W(u"| адрес | float | hex | что это |")
    W(u"|---|---|---|---|")
    for h, why in CONSTANTS:
        v = read_dword(A(h))
        if v is None:
            W(u"| {} | ? | ? | {} |".format(h, why))
        else:
            W(u"| {} | {:.8g} | {:08X} | {} |".format(h, as_float(v), v, why))


# ------------------------------------------------------------------ 2. конструктор сглаживателя
def section_init():
    W(u"\n# 2. Кандидаты на конструктор сглаживателя стика (константа 0x3D088889 = 1/30 = win)")
    hits = []
    for ins in listing.getInstructions(True):
        for i in range(2):
            if scalar_of(ins, i) == 0x3D088889:
                hits.append(ins)
                break
    W(u"Инструкций с операндом 0x3D088889: {}".format(len(hits)))
    seen = set()
    for ins in hits[:MAX_LIST]:
        f = fm.getFunctionContaining(ins.getAddress())
        W(u"\n## {} в {}".format(ins.getAddress(), fname(f)))
        W(u"```")
        for l in disasm(ins.getAddress(), 6, 10, set([str(ins.getAddress())])):
            W(l)
        W(u"```")
        if f is not None and str(f.getEntryPoint()) not in seen:
            seen.add(str(f.getEntryPoint()))
            queue(f)
            lv = callers_levels(f, 1)
            W(u"Вызывающие: " + (u", ".join(fname(x) for x in lv[0][:15]) if lv and lv[0] else u"-"))


# ------------------------------------------------------------------ 4. вызывающие
def section_callers():
    W(u"\n# 4. Вызывающие")
    for h, why in (("00721bd0", "применить дельту"), ("004fdf60", "проверка/откат")):
        f = fm.getFunctionAt(A(h))
        W(u"\n## {} `{}` ({})".format(fname(f), h, why))
        if f is None:
            continue
        levels = callers_levels(f, CALLER_DEPTH)
        for i, lv in enumerate(levels, 1):
            W(u"- уровень {}: ".format(i) + (u", ".join(fname(x) for x in lv[:30]) if lv else u"-"))
            if h == "004fdf60" and i == 1:
                for x in lv[:12]:
                    queue(x)


# ------------------------------------------------------------------ 5. декомпиляция
def section_decompile():
    W(u"\n# 5. Декомпиляция")
    ordered = OrderedDict()
    for h, why in DECOMP_TARGETS:
        f = fm.getFunctionAt(A(h))
        if f is None:
            W(u"\n_{}: функции нет_".format(h))
            continue
        ordered[str(f.getEntryPoint())] = (f, why)
    for k, f in decomp_queue.items():
        if k not in ordered:
            ordered[k] = (f, u"(вызывающий / кандидат)")
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)                # noqa: F821
    n = 0
    for k, (f, why) in ordered.items():
        if n >= MAX_DECOMPILE:
            W(u"\n_лимит MAX_DECOMPILE достигнут, пропущено: {}_".format(len(ordered) - n))
            break
        res = ifc.decompileFunction(f, 60, monitor)  # noqa: F821
        W(u"\n### {}  - {}".format(fname(f), why))
        if res.decompileCompleted():
            W(u"```c")
            W(res.getDecompiledFunction().getC())
            W(u"```")
        else:
            W(u"_декомпиляция не удалась: {}_".format(res.getErrorMessage()))
        n += 1


def section_text(fn, label):
    """выполняет секцию и возвращает её строки отдельным списком (порядок вывода не равен порядку вычисления)"""
    saved = list(lines)
    del lines[:]
    safe(fn, label)
    res = list(lines)
    del lines[:]
    lines.extend(saved)
    return res


def main():
    W(u"# DS3 CamChain")
    md5 = currentProgram.getExecutableMD5()        # noqa: F821
    W(u"Программа: {} | база образа: {} | MD5: `{}`".format(currentProgram.getName(), currentProgram.getImageBase(), md5))   # noqa: F821
    if md5 is None or md5.lower() != ADDRESSES_FOR_MD5:
        W(u"\n_MD5 не равен {}: адреса 1.0.0.1 не применимы, отчёт пуст._".format(ADDRESSES_FOR_MD5))
    else:
        state = {}
        s3 = section_text(lambda: section_revert(state), "revert")      # заполняет state для cfg
        s0 = section_text(lambda: section_cfg(state), "cfg")
        s1 = section_text(section_constants, "constants")
        s2 = section_text(section_init, "init")
        s4 = section_text(section_callers, "callers")
        s5 = section_text(section_decompile, "decompile")
        for part in (s0, s1, s2, s3, s4, s5):
            lines.extend(part)
    path = os.path.join(OUT_DIR, "ds3_camchain_{}.md".format((md5 or "unknown")[:8]))
    with io.open(path, "w", encoding="utf-8") as fh:
        fh.write(u"\n".join(lines))
    print(u"DS3 CamChain written: {}".format(path))


main()
