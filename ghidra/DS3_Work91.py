# -*- coding: utf-8 -*-
# DS3 Work91: раздел 9.1 архитектурного среза 2026-10-08 (задачи W1-W7) одним прогоном, без ручных шагов.
#
# Что делает (адреса 1.0.0.1; на другой сборке MD5 не совпадёт - отчёт пуст):
#   W1  чувствительность камеры (Q2): ECX у вызовов FUN_0042ED00/ED80/EE00/EE80 в FUN_0073F310 (цепочка определений назад по
#       листингу), глобальный указатель и его писатели, тела FUN_0042EC90 и FUN_004F9BC0, писатели полей +0x10..+0x90
#       (в FUN_004F9BC0 и её вызываемых, и по всей программе), готовые строки cfg с 12+ байтами начала функций.
#   W2  поле +0x70 и масштабы (Q1): виртуальная таблица класса FUN_0073F310, конструктор (MOV [reg],vftable) и значения полей
#       +0x70/+0x150/+0x158/+0xC8/+0xCC/+0xD0/+0xD4, ранжирование писателей по всей программе, связь +0x70 с dt (012A9AA8).
#   W3  скорость разворота (H4): строки "*TurnSpeed*", их обработчики, какие поля/глобалы они пишут и читает ли это камера
#       (достижимость из FUN_0073F310 за 2 вызова).
#   W4  константы: чтение по 8 байт (float и double), тип по инструкциям-читателям, совпадение с известными числами (пи и др.),
#       плюс все константы из .rdata, которые читает цепочка камеры (автоматически). Закрывает ограничение T1.
#   W5  источник win/blend/clamp (Q3): поиск байтов 89 88 08 3D (1/30) и тройки {1/30, 1.0, 2.0}, xref на найденное,
#       читатели 00D22BB0, вызывающие FUN_0040D820 (откуда ECX), кандидаты на конструктор по записям [reg+4/+8/+0xC].
#       Закрывает ограничение T3.
#   W6  вызывающие (глубина 2) FUN_0073F310, FUN_005906A0, FUN_00549EA0, FUN_00647820, FUN_0067A420, FUN_0040D820 (H6).
#   W7  FUN_00AA25F0, FUN_00AA9200, FUN_0050C960 (смысл проверки владельца камеры).
#
# Чего скрипт сделать не может (и честно пишет об этом в отчёте): значения полей в рантайме, калибровку 360 градусов, выбор между
# гипотезами H1/H3/H4/H6. Он собирает факты и оставляет их на разбор.
#
# Пишет ~/ds3_work91_<md5[:8]>.md. Ничего не меняет в базе. Совместим с Jython и PyGhidra. Полный проход по инструкциям
# занимает от десятков секунд до нескольких минут.
# Прогнан в настоящей Ghidra на 1.0.0.1 (отчёт ds3_work91_1802f17a.md в файлах проекта); логика проверяется макетом
# tests/mock_ghidra_work91.py.
#
# @category DS3Probe
from __future__ import print_function

import io
import math
import os
import re
import struct
import time
import traceback
from collections import OrderedDict

from ghidra.app.decompiler import DecompInterface
from java.lang import Byte
from java.lang.reflect import Array

# ----------------------------- НАСТРОЙКИ -----------------------------------
ADDRESSES_FOR_MD5 = "1802f17a2cc1c2797323632862c6fb1f"
OUT_DIR = os.path.expanduser("~")
MAX_DECOMPILE = 90               # всего декомпиляций за прогон
DECOMP_TIMEOUT = 90              # секунд на функцию
MAX_ROWS = 40                    # строк в списках
CTX_BEFORE = 30                  # инструкций до CALL (W1)
CTX_AFTER = 4
BACK_DEFS = 400                  # насколько назад искать определение регистра (инструкций)
CALLER_DEPTH = 2

A_LOOK = "0073f310"              # LookUpdate (рыскание/тангаж)
A_APPLY = "00721bd0"             # ApplyRotDelta
A_SMOOTH = "0040d820"            # StickSmooth
A_OWNER = "004fdf60"             # OwnerCheck
A_FOLLOW = "0074baa0"            # CamFollow
A_LOOKB = "005906a0"
A_CURVE = "00549ea0"
A_SENS_CURVE = "0042ec90"
A_SENS_CFG = "004f9bc0"
DT_GLOBALS = ["012a9aa8", "012a9b08"]
CONST_SMOOTH_C = "00d22bb0"

SENS_FUNCS = [("0042ed00", u"SensYaw (обычный режим)"), ("0042ed80", u"SensYaw1 (режим 1, по декомпиляции недостижим)"),
              ("0042ee00", u"SensYawAim (прицел)"), ("0042ee80", "SensPitch")]
SENS_DISPS = [0x10, 0x14, 0x18, 0x1C, 0x60, 0x64, 0x68, 0x6C, 0x84, 0x88, 0x8C, 0x90]
SCALE_DISPS = [0x60, 0x64, 0x68, 0x6C, 0x84, 0x88, 0x8C, 0x90]
LOOK_DISPS = [0x70, 0x150, 0x158, 0xC8, 0xCC, 0xD0, 0xD4]
LOOK_CORE = [0x150, 0x158, 0xC8, 0xCC, 0xD0, 0xD4]
LOOK_NAMES = {0x70: u"+0x70 (общий множитель)", 0x150: u"+0x150 (масштаб рыскания)", 0x158: u"+0x158 (масштаб тангажа)",
              0xC8: u"+0xC8 (предел рыскания +)", 0xCC: u"+0xCC (предел рыскания -)", 0xD0: u"+0xD0 (предел тангажа +)",
              0xD4: u"+0xD4 (предел тангажа -)"}
TRACK_DISPS = set(LOOK_DISPS + [0xD8, 0x1D0, 0x1D4])

# W3: известные обработчики из среза (проверяются, даже если строки не нашлись)
TURN_HANDLERS = [("00559810", "CMD_SetDSGroundAimTurnSpeed"), ("006c6700", "CMD_SetActionTurnSpeed"),
                 ("007d0670", "CMD_SetWalkTurnSpeed (1)"), ("007d0bf0", "CMD_SetWalkTurnSpeed (2)")]
STRING_PATTERNS = ["TurnSpeed", "LookSens", "MouseSens", "CameraSens", "YawLimit", "PitchLimit", "AimSpeed", "LookSpeed"]

# W4: константы, перечисленные в разделе 4.10 среза: (адрес, зачем)
CONSTANTS = [
    ("00d22bb0", u"C в FUN_0040D820 (делитель выхода)"),
    ("00d4c2a8", u"нижняя граница нормировки рыскания"),
    ("00d27bc0", u"верхняя граница нормировки / делитель local_28"),
    ("00ed2e98", u"шаг нормировки рыскания"),
    ("00d53810", u"порог активности в FUN_0040D820"),
    ("00d2047c", u"порог 'есть ввод'"),
    ("00d1ff7c", u"маркер 'по умолчанию' в FUN_00ABC510"),
    ("00d28718", u"множитель инверсии"),
    ("00d26dd8", u"множитель в FUN_00647820 / FUN_00552030"),
    ("00d20590", u"в цепочке камеры (не прочитана)"),
    ("00d320f8", u"множитель в FUN_0074BAA0"),
    ("00d27e68", u"множитель в FUN_0043B770 / FUN_0074BAA0"),
    ("00d1fed0", u"прибавка к local_28 / FUN_0074BAA0"),
    ("011d1f1c", u"множитель в local_28 (float)"),
    ("00d7ad58", u"множитель ползунка мыши (1.8 по 1.0.0.0)"),
    ("00d229a8", u"смещение ползунка мыши (0.1 по 1.0.0.0)"),
    ("00d7ca08", u"знаменатель в FUN_0067A420"),
    ("00d34bc0", u"порог в FUN_0067A420"),
    ("00d4c1c8", u"порог в FUN_00549EA0"),
    ("00d206f8", u"поправка беззнакового в FUN_0040A8F0"),
]
AUTO_CONST_FUNCS = [A_LOOK, A_SMOOTH, A_FOLLOW, A_LOOKB, A_CURVE, "00647820", "0067a420", "00552030", A_SENS_CURVE, "0042ed00",
                    "0042ee80", A_SENS_CFG, A_APPLY, "005438a0"]

# W6: (адрес, что это)
CALLER_TARGETS = [(A_LOOK, u"LookUpdate (основной взгляд)"), (A_LOOKB, u"LookB (потребитель стика с dt)"),
                  (A_CURVE, u"потребитель стика с кривой отклика"), ("00647820", u"накопление углов"),
                  ("0067a420", u"KBM-ветка через окно / следящий ввод"), (A_SMOOTH, u"StickSmooth (все вызывающие)")]
# W7
OWNER_TARGETS = [("00aa25f0", u"состояние контроллера (==4: пропуск)"), ("00aa9200", u"курсор владельца / перечисление"),
                 ("0050c960", u"второй вызывающий OwnerCheck")]
# ---------------------------------------------------------------------------

fm = currentProgram.getFunctionManager()          # noqa: F821 (глобалы Ghidra)
rm = currentProgram.getReferenceManager()         # noqa: F821
listing = currentProgram.getListing()             # noqa: F821
mem = currentProgram.getMemory()                  # noqa: F821
af = currentProgram.getAddressFactory()           # noqa: F821

try:
    _STR = basestring                             # noqa: F821 (Jython / Py2)
except NameError:
    _STR = str

lines = []
FINDINGS = OrderedDict()
STATUS = OrderedDict()
T0 = time.time()

REGS32 = set(["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"])
STORE_MN = set(["MOV", "MOVSS", "MOVSD", "MOVAPS", "MOVUPS", "MOVQ", "MOVD", "MOVDQA", "MOVDQU", "FST", "FSTP", "FIST", "FISTP",
                "FISTTP"])
NOWRITE_OP0 = set(["CMP", "TEST", "PUSH", "CALL", "JMP", "BT", "FLD", "FCOM", "FCOMP", "FUCOM", "FUCOMP", "FICOM", "FICOMP"])
MEM_RE = re.compile(r"\[([^\]]*)\]")
SIZE_RE = re.compile(r"\b(byte|word|dword|qword|float|double|tbyte|xmmword|ymmword|fword)\s+ptr\b", re.I)
SS_MN = set(["MOVSS", "ADDSS", "SUBSS", "MULSS", "DIVSS", "COMISS", "UCOMISS", "CVTSS2SD", "SQRTSS", "MAXSS", "MINSS"])
SD_MN = set(["ADDSD", "SUBSD", "MULSD", "DIVSD", "COMISD", "UCOMISD", "CVTSD2SS", "SQRTSD", "MAXSD", "MINSD"])


def W(s=u""):
    lines.append(u"{}".format(s))


def F(sec, text):
    FINDINGS.setdefault(sec, []).append(u"{}".format(text))


def log(s):
    print(s)                                        # только ASCII: консоль Jython может не принять юникод


def A(h):
    return af.getAddress(h if isinstance(h, _STR) else "%08x" % h)


def aoff(a):
    return int(a.getOffset()) & 0xFFFFFFFF


def hx(v):
    return u"%08x" % (v & 0xFFFFFFFF)


def fname(f):
    return u"(вне функции)" if f is None else u"{}@{}".format(f.getName(), f.getEntryPoint())


def fshort(f):
    return u"(вне функции)" if f is None else u"{}".format(f.getName())


def itext(ins):
    try:
        return u"{}".format(str(ins))
    except Exception:                              # noqa: BLE001
        return u"?"


def safe(fn, label):
    try:
        fn()
    except Exception as e:                         # noqa: BLE001
        if e.__class__.__name__ == "CancelledException":
            raise
        W(u"\n_секция {} упала: {}_".format(label, e))
        W(u"```")
        W(traceback.format_exc())
        W(u"```")
        STATUS[label] = u"ОШИБКА"
        log("section %s failed: %s" % (label, e))


# --------------------------------------------------------------- разбор операндов
def split_commas(s):
    out = []
    depth = 0
    cur = []
    for ch in s:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(u"".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append(u"".join(cur).strip())
    return out


def split_ops(text):
    parts = text.split(None, 1)
    if len(parts) < 2:
        return []
    return split_commas(parts[1])


def parse_int(t):
    t = t.strip()
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        if t.lower().startswith("-0x"):
            return -int(t[1:], 16)
        if re.match(r"^-?\d+$", t):
            return int(t)
    except ValueError:
        pass
    return None


def parse_mem(op):
    u"""разбор операнда памяти: dict(base, index, disp, sym, size) или None"""
    m = MEM_RE.search(op)
    if not m:
        return None
    base = None
    index = None
    disp = 0
    sym = None
    for t in m.group(1).split("+"):
        t = t.strip()
        if not t:
            continue
        if "*" in t:
            index = t
            continue
        if t.upper() in REGS32:
            if base is None:
                base = t.upper()
            else:
                index = t
            continue
        v = parse_int(t)
        if v is not None:
            disp += v
        else:
            sym = t
    disp &= 0xFFFFFFFF
    if disp >= 0x80000000:
        disp -= 0x100000000
    symaddr = None
    if sym is not None:
        m2 = re.search(r"_([0-9a-fA-F]{8})$", sym)
        if m2:
            symaddr = int(m2.group(1), 16)
    sz = SIZE_RE.search(op)
    return {"base": base, "index": index, "disp": disp, "sym": sym, "symaddr": symaddr,
            "size": sz.group(1).lower() if sz else None}


def mem_target(ins, mm):
    u"""адрес глобала в операнде памяти без регистров: по ссылке Ghidra, затем по имени DAT_xxxxxxxx, затем по смещению"""
    t = data_target(ins)
    if t is not None:
        return t
    if mm.get("symaddr") is not None:
        return mm["symaddr"]
    return mm["disp"] & 0xFFFFFFFF


def scalar_of(ins, i=0):
    try:
        s = ins.getScalar(i)
        return None if s is None else int(s.getUnsignedValue())
    except Exception:                              # noqa: BLE001
        return None


def ref_types(ins):
    u"""data-ссылки инструкции: список (toAddress_int, isRead, isWrite)"""
    out = []
    try:
        for r in ins.getReferencesFrom():
            rt = r.getReferenceType()
            if rt.isCall() or rt.isFlow():
                continue
            to = r.getToAddress()
            try:
                if not mem.contains(to):
                    continue
            except Exception:                      # noqa: BLE001
                pass
            out.append((aoff(to), bool(rt.isRead()), bool(rt.isWrite())))
    except Exception:                              # noqa: BLE001
        pass
    return out


def data_target(ins):
    r = ref_types(ins)
    return r[0][0] if r else None


def imm_values(ins):
    u"""все целые, встречающиеся в инструкции как непосредственные операнды или цели ссылок"""
    vals = set()
    for t in split_ops(itext(ins)):
        v = parse_int(t)
        if v is not None:
            vals.add(v & 0xFFFFFFFF)
    for i in range(2):
        v = scalar_of(ins, i)
        if v is not None:
            vals.add(v & 0xFFFFFFFF)
    for to, rd, wr in ref_types(ins):
        vals.add(to)
    return vals


def cand_values(ins):
    u"""значения, которые инструкция 'передаёт' (PUSH/MOV imm, адреса данных), без целей CALL/JMP/Jcc"""
    mn = ins.getMnemonicString()
    if mn == "CALL" or mn.startswith("J"):
        return set()
    return imm_values(ins)


def ins_bytes(ins):
    try:
        return [int(b) & 0xFF for b in ins.getBytes()]
    except Exception:                              # noqa: BLE001
        return []


def hexbytes(bs):
    return u" ".join(u"%02X" % b for b in bs)


def bytes_from(addr, minimum=12):
    out = []
    n = 0
    ins = listing.getInstructionAt(addr)
    while ins is not None and len(out) < minimum and n < 8:
        out += ins_bytes(ins)
        n += 1
        ins = ins.getNext()
    return out, n


def disasm(start, before, after, mark=None, note=None, lo=None):
    u"""lo - смещение входа функции: назад дальше входа не идём"""
    ins = listing.getInstructionAt(start)
    if ins is None:
        return [u"_нет инструкции по адресу {}_".format(start)]
    cur = ins
    for _ in range(before):
        p = cur.getPrevious()
        if p is None or (lo is not None and aoff(p.getAddress()) < lo):
            break
        cur = p
    res = []
    k = 0
    total = before + after + 1
    while cur is not None and k < total:
        key = str(cur.getAddress())
        flag = u"=>" if (mark is not None and key in mark) else u"  "
        tail = u""
        if note is not None and key in note:
            tail = u"   ; " + note[key]
        res.append(u"{} {}  {:<24} {}{}".format(flag, cur.getAddress(), hexbytes(ins_bytes(cur)), itext(cur), tail))
        cur = cur.getNext()
        k += 1
    return res


# --------------------------------------------------------------- память и числа
def rd8(a):
    try:
        return int(mem.getByte(a)) & 0xFF
    except Exception:                              # noqa: BLE001
        return None


def rd32(a):
    try:
        return int(mem.getInt(a)) & 0xFFFFFFFF
    except Exception:                              # noqa: BLE001
        return None


def rd64(a):
    try:
        return int(mem.getLong(a)) & 0xFFFFFFFFFFFFFFFF
    except Exception:                              # noqa: BLE001
        return None


def f32(u):
    return struct.unpack("<f", struct.pack("<I", u & 0xFFFFFFFF))[0]


def f64(q):
    return struct.unpack("<d", struct.pack("<Q", q & 0xFFFFFFFFFFFFFFFF))[0]


def fnum(x):
    if x != x:
        return u"nan"
    if x in (float("inf"), float("-inf")):
        return u"inf" if x > 0 else u"-inf"
    return u"%.9g" % x


KNOWN = [("pi", math.pi), ("-pi", -math.pi), ("2*pi", 2 * math.pi), ("pi/2", math.pi / 2), ("pi/180", math.pi / 180.0),
         ("180/pi", 180.0 / math.pi), ("0.5", 0.5), ("1", 1.0), ("-1", -1.0), ("2", 2.0), ("3", 3.0), ("4", 4.0), ("10", 10.0),
         ("30", 30.0), ("60", 60.0), ("100", 100.0), ("360", 360.0), ("1000", 1000.0), ("1/30", 1.0 / 30), ("1/60", 1.0 / 60),
         ("0.1", 0.1), ("0.01", 0.01), ("0.001", 0.001), ("0.032", 0.032), ("0.05", 0.05), ("0.2", 0.2), ("0.25", 0.25),
         ("1.8", 1.8), ("0.0174533", math.pi / 180.0)]


def match_known(x):
    if x != x:
        return None
    if x == 0.0:
        return u"0"
    for name, v in KNOWN:
        if abs(x - v) <= 1e-6 * abs(v):
            return name
    return None


def dword_text(v):
    u"""0xXXXXXXXX (int N / float X) - оба толкования, если float 'нормальный'"""
    if v is None:
        return u"?"
    s = u"0x%08x" % v
    signed = v - 0x100000000 if v >= 0x80000000 else v
    s += u" (int %d" % signed
    x = f32(v)
    if x == x and (1e-6 <= abs(x) <= 1e9):
        s += u" / float %s" % fnum(x)
        k = match_known(x)
        if k:
            s += u" = %s" % k
    elif v == 0:
        s += u" / float 0"
    s += u")"
    return s


def read_cstring(a, maxlen=110):
    out = []
    for i in range(maxlen):
        b = rd8(a.add(i))
        if b is None:
            return None
        if b == 0:
            break
        if b < 0x20 or b > 0x7E:
            return None
        out.append(chr(b))
    s = u"".join(out)
    return s if len(s) >= 3 else None


# --------------------------------------------------------------- поиск байтов
def jbytes(lst):
    arr = Array.newInstance(Byte.TYPE, len(lst))
    for i, b in enumerate(lst):
        arr[i] = b - 256 if b > 127 else b
    return arr


def find_all_bytes(pattern, limit=100):
    u"""все вхождения последовательности байт (список int) в инициализированной памяти"""
    res = []
    try:
        pat = jbytes(pattern)
        cur = mem.getMinAddress()
        while cur is not None and len(res) < limit:
            monitor.checkCanceled()                 # noqa: F821
            hit = mem.findBytes(cur, pat, None, True, monitor)   # noqa: F821
            if hit is None:
                break
            res.append(hit)
            try:
                cur = hit.add(1)
            except Exception:                       # noqa: BLE001
                break
        return res
    except Exception as e:                         # noqa: BLE001
        if e.__class__.__name__ == "CancelledException":
            raise
        if not _FB["warned"]:
            _FB["warned"] = True
            log("findBytes failed, using memory image fallback: %s" % e)
    res = []
    want = bytearray(pattern)
    for start, data in image_blocks():
        i = data.find(want)
        while i >= 0 and len(res) < limit:
            res.append(start.add(i))
            i = data.find(want, i + 1)
    return res


_IMG_BLOCKS = []
_FB = {"warned": False}


def image_blocks():
    u"""образ памяти одним куском на блок (кэш для запасного поиска байтов, когда findBytes недоступен)"""
    if _IMG_BLOCKS:
        return _IMG_BLOCKS
    for blk in mem.getBlocks():
        if not blk.isInitialized():
            continue
        start = blk.getStart()
        size = int(blk.getSize())
        data = bytearray()
        pos = 0
        while pos < size:
            n = min(1 << 20, size - pos)
            buf = Array.newInstance(Byte.TYPE, n)
            try:
                blk.getBytes(start.add(pos), buf)
                data.extend([(x & 0xFF) for x in buf])
            except Exception:                      # noqa: BLE001
                data.extend(bytearray(n))
            pos += n
        _IMG_BLOCKS.append((start, data))
    return _IMG_BLOCKS


def le32(v):
    return [v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF]


# --------------------------------------------------------------- граф вызовов
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


def call_instrs_to(f):
    u"""CALL-инструкции на f: список (ins, функция-вызывающий)"""
    out = []
    for r in rm.getReferencesTo(f.getEntryPoint()):
        if r.getReferenceType().isCall():
            ins = listing.getInstructionAt(r.getFromAddress())
            if ins is not None:
                out.append((ins, fm.getFunctionContaining(r.getFromAddress())))
    return out


def call_sites(func, target_entry):
    res = []
    if func is None:
        return res
    for ins in listing.getInstructions(func.getBody(), True):
        if ins.getMnemonicString() != "CALL":
            continue
        try:
            for r in ins.getReferencesFrom():
                if r.getReferenceType().isCall() and str(r.getToAddress()) == str(target_entry):
                    res.append(ins)
        except Exception:                          # noqa: BLE001
            pass
    return res


def callees_of(func):
    out = OrderedDict()
    if func is None:
        return out
    for ins in listing.getInstructions(func.getBody(), True):
        if ins.getMnemonicString() != "CALL":
            continue
        try:
            for r in ins.getReferencesFrom():
                if r.getReferenceType().isCall():
                    cf = fm.getFunctionAt(r.getToAddress())
                    if cf is not None:
                        try:
                            if cf.isThunk():
                                tf = cf.getThunkedFunction(True)
                                if tf is not None:
                                    cf = tf
                        except Exception:          # noqa: BLE001
                            pass
                        out[aoff(cf.getEntryPoint())] = cf
        except Exception:                          # noqa: BLE001
            pass
    return out


REACH_CACHE = {}


def reach_set(root, depth):
    key = (aoff(root.getEntryPoint()), depth)
    if key in REACH_CACHE:
        return REACH_CACHE[key]
    seen = set([aoff(root.getEntryPoint())])
    cur = [root]
    for _ in range(depth):
        nxt = []
        for x in cur:
            for e, cf in callees_of(x).items():
                if e not in seen and len(seen) < 600:
                    seen.add(e)
                    nxt.append(cf)
        cur = nxt
    REACH_CACHE[key] = seen
    return seen


def func_strings(f, limit=4, scan=4000):
    out = []
    if f is None:
        return out
    n = 0
    for ins in listing.getInstructions(f.getBody(), True):
        n += 1
        if n > scan or len(out) >= limit:
            break
        for to, rd, wr in ref_types(ins):
            a = A(to)
            blk = mem.getBlock(a)
            if blk is None or blk.isExecute():
                continue
            s = read_cstring(a, 70)
            if s and len(s) >= 5 and s not in out:
                out.append(s)
    return out


# --------------------------------------------------------------- декомпиляция
_DEC = {}
_IFC = [None]
_DEC_N = [0]


def decompile_text(f):
    key = aoff(f.getEntryPoint())
    if key in _DEC:
        return _DEC[key], True
    if _DEC_N[0] >= MAX_DECOMPILE:
        return None, False
    if _IFC[0] is None:
        ifc = DecompInterface()
        ifc.openProgram(currentProgram)             # noqa: F821
        _IFC[0] = ifc
    _DEC_N[0] += 1
    try:
        res = _IFC[0].decompileFunction(f, DECOMP_TIMEOUT, monitor)    # noqa: F821
        if res.decompileCompleted():
            txt = res.getDecompiledFunction().getC()
            _DEC[key] = (True, txt)
        else:
            _DEC[key] = (False, u"{}".format(res.getErrorMessage()))
    except Exception as e:                         # noqa: BLE001
        if e.__class__.__name__ == "CancelledException":
            raise
        _DEC[key] = (False, u"исключение: {}".format(e))
    return _DEC[key], False


def emit_decompile(f, why):
    if f is None:
        return
    W(u"\n### {}  - {}".format(fname(f), why))
    res, again = decompile_text(f)
    if res is None:
        W(u"_лимит MAX_DECOMPILE ({}) достигнут_".format(MAX_DECOMPILE))
        return
    if again:
        W(u"_уже декомпилирована выше_")
        return
    ok, txt = res
    if ok:
        W(u"```c")
        W(txt)
        W(u"```")
    else:
        W(u"_декомпиляция не удалась: {}_".format(txt))


def func_at(h):
    return fm.getFunctionAt(A(h))


# --------------------------------------------------------------- глобальный проход
FN_STORES = {}       # entry -> {reg: {disp: addr}}   записи [reg+disp], disp 0..0xFFF (без EBP/ESP)
VT_STORES = {}       # imm -> [(addr, entry)]          MOV dword ptr [reg], imm  (кандидаты записи vftable)
SCAN = {"done": False, "functions": 0, "instructions": 0}
IMG = {"lo": 0x400000, "hi": 0x7FFFFFFF}


def scan_program():
    if SCAN["done"]:
        return
    SCAN["done"] = True
    try:
        IMG["hi"] = aoff(mem.getMaxAddress())
    except Exception:                              # noqa: BLE001
        pass
    nf = 0
    ni = 0
    for f in fm.getFunctions(True):
        nf += 1
        if (nf & 0x3FF) == 0:
            monitor.checkCanceled()                 # noqa: F821
            log("scan: %d functions, %d instructions, %.0f s" % (nf, ni, time.time() - T0))
        entry = aoff(f.getEntryPoint())
        regs = None
        for ins in listing.getInstructions(f.getBody(), True):
            ni += 1
            mn = ins.getMnemonicString()
            if mn not in STORE_MN:
                continue
            ops = split_ops(itext(ins))
            if not ops:
                continue
            mm = parse_mem(ops[0])
            if mm is None or mm["base"] is None or mm["index"] is not None or mm["base"] in ("ESP", "EBP"):
                continue
            d = mm["disp"]
            if d < 0 or d >= 0x1000:
                continue
            addr = aoff(ins.getAddress())
            if regs is None:
                regs = FN_STORES.setdefault(entry, {})
            regs.setdefault(mm["base"], {}).setdefault(d, addr)
            if mn == "MOV" and d == 0 and len(ops) == 2 and mm["size"] in (None, "dword") and ops[1].upper() not in REGS32:
                for v in imm_values(ins):
                    if IMG["lo"] <= v <= IMG["hi"]:
                        VT_STORES.setdefault(v, []).append((addr, entry))
    SCAN["functions"] = nf
    SCAN["instructions"] = ni
    log("scan done: %d functions, %d instructions, %.0f s" % (nf, ni, time.time() - T0))


# --------------------------------------------------------------- значения записей и определения регистров
def func_lo(ins):
    f = fm.getFunctionContaining(ins.getAddress())
    return aoff(f.getEntryPoint()) if f is not None else 0


def back_instrs(ins, n, lo=None):
    u"""до n инструкций назад, не выходя за вход функции (lo; по умолчанию - функция самой ins)"""
    if lo is None:
        lo = func_lo(ins)
    out = []
    cur = ins.getPrevious()
    while cur is not None and len(out) < n and aoff(cur.getAddress()) >= lo:
        out.append(cur)
        cur = cur.getPrevious()
    return out


def fpu_source(ins):
    u"""что лежало в ST0 перед FST/FSTP: (float|None, описание)"""
    for p in back_instrs(ins, 8):
        mn = p.getMnemonicString()
        if mn == "CALL":
            return None, u"после CALL"
        if mn == "FLDZ":
            return 0.0, u"FLDZ"
        if mn == "FLD1":
            return 1.0, u"FLD1"
        if mn == "FLD":
            ops = split_ops(itext(p))
            mm = parse_mem(ops[0]) if ops else None
            if mm is None:
                continue                            # FLD ST(i)
            tgt = mem_target(p, mm) if (mm["base"] is None and mm["index"] is None) else None
            if tgt is None:
                return None, u"FLD [память] @%s" % p.getAddress()
            if mm["size"] in ("double", "qword"):
                q = rd64(A(tgt))
                return (None if q is None else f64(q)), u"DAT_%s (double)" % hx(tgt)
            u = rd32(A(tgt))
            return (None if u is None else f32(u)), u"DAT_%s (float)" % hx(tgt)
        if mn.startswith("F") and mn not in ("FXCH", "FWAIT", "FNSTSW", "FNSTCW", "FLDCW", "FST", "FSTP"):
            return None, u"вычисление (%s @%s)" % (mn, p.getAddress())
    return None, u"не найдено"


def store_value(ins):
    u"""значение, которое пишет инструкция-запись: (текст, u32|None, float|None)"""
    try:
        mn = ins.getMnemonicString()
        ops = split_ops(itext(ins))
        if not ops:
            return u"?", None, None
        mm = parse_mem(ops[0])
        size = mm["size"] if mm else None
        if mn in ("FST", "FSTP"):
            x, why = fpu_source(ins)
            if x is None:
                return u"? (%s)" % why, None, None
            k = match_known(x)
            u = None
            try:
                u = struct.unpack("<I", struct.pack("<f", x))[0]
            except Exception:                      # noqa: BLE001
                pass
            return u"%s (%s)%s" % (fnum(x), why, u" = %s" % k if k else u""), u, x
        if mn in ("FIST", "FISTP", "FISTTP"):
            return u"? (целое из FPU)", None, None
        if len(ops) < 2:
            return u"?", None, None
        src = ops[1].strip()
        v = parse_int(src)
        if v is not None:
            u = v & 0xFFFFFFFF
            txt = dword_text(u) if size in (None, "dword", "float") else u"0x%x" % (v & 0xFFFFFFFFFFFFFFFF)
            return txt, u, f32(u)
        if src.upper() in REGS32:
            reg = src.upper()
            for p in back_instrs(ins, 8):
                pm = p.getMnemonicString()
                if pm == "CALL":
                    return u"? (после CALL)", None, None
                pops = split_ops(itext(p))
                if pops and pops[0].upper() == reg and pm not in NOWRITE_OP0:
                    if pm == "XOR" and len(pops) == 2 and pops[1].upper() == reg:
                        return dword_text(0), 0, 0.0
                    if pm == "MOV" and len(pops) == 2:
                        pv = parse_int(pops[1])
                        if pv is not None:
                            u = pv & 0xFFFFFFFF
                            return dword_text(u), u, f32(u)
                        pmm = parse_mem(pops[1])
                        if pmm is not None:
                            if pmm["base"] is None and pmm["index"] is None:
                                tgt = mem_target(p, pmm)
                                u = rd32(A(tgt))
                                return u"DAT_%s -> %s" % (hx(tgt), dword_text(u)), u, (None if u is None else f32(u))
                            return u"? (из памяти @%s: %s)" % (p.getAddress(), itext(p)), None, None
                    return u"? (%s @%s)" % (itext(p), p.getAddress()), None, None
            return u"? (регистр %s)" % reg, None, None
        if parse_mem(src) is not None:
            return u"? (память)", None, None
        return u"?", None, None
    except Exception as e:                         # noqa: BLE001
        if e.__class__.__name__ == "CancelledException":
            raise
        return u"? (ошибка: %s)" % e, None, None


def resolve_store(ins):
    return store_value(ins)[0]


def find_def(ins, reg, lo):
    u"""ближайшая назад инструкция, пишущая reg: (ins, число CALL между) или None; lo - смещение входа функции"""
    ncalls = 0
    cur = ins.getPrevious()
    n = 0
    while cur is not None and n < BACK_DEFS and aoff(cur.getAddress()) >= lo:
        mn = cur.getMnemonicString()
        if mn == "CALL":
            ncalls += 1
        elif mn not in NOWRITE_OP0:
            ops = split_ops(itext(cur))
            if ops and ops[0].upper() == reg:
                return cur, ncalls, n + 1
        cur = cur.getPrevious()
        n += 1
    return (None, "entry" if (cur is None or aoff(cur.getAddress()) < lo) else "window", n)


def chase_reg(ins, reg):
    u"""цепочка 'откуда значение reg перед ins': (строки, факты). Идёт линейно назад по листингу, ветвления не учитывает"""
    facts = []
    out = []
    f = fm.getFunctionContaining(ins.getAddress())
    lo = aoff(f.getEntryPoint()) if f is not None else 0
    cur_ins, cur_reg = ins, reg
    for hop in range(5):
        d = find_def(cur_ins, cur_reg, lo)
        if d[0] is None:
            if d[1] == "entry":
                out.append(u"%s: до входа в функцию не менялся (значение пришло от вызывающего; для ECX в thiscall это this)" % cur_reg)
                facts.append(("entry_reg", cur_reg))
            else:
                out.append(u"%s: определение не найдено в окне %d инструкций: смотри дизассемблер" % (cur_reg, BACK_DEFS))
                facts.append(("extern", cur_reg))
            break
        dins, ncalls, nback = d
        txt = itext(dins)
        note = u"  [назад %d инстр.]" % nback
        if ncalls:
            note += u"  [между определением и использованием CALL: %d, регистр мог измениться]" % ncalls
        out.append(u"%s <- %s   @%s%s" % (cur_reg, txt, dins.getAddress(), note))
        mn = dins.getMnemonicString()
        ops = split_ops(txt)
        if len(ops) < 2:
            if mn == "POP":
                facts.append(("pop",))
            break
        src = ops[1]
        if mn == "XOR" and ops[0].upper() == src.upper():
            facts.append(("zero",))
            break
        mm = parse_mem(src)
        if mm is not None:
            tgt = mem_target(dins, mm)
            if mn == "LEA" and mm["base"] is None and mm["index"] is None:
                facts.append(("global_obj", tgt))
                break
            if mn == "LEA":
                facts.append(("embedded", mm["base"], mm["disp"]))
                if mm["base"] in REGS32 and mm["base"] not in ("ESP", "EBP"):
                    cur_ins, cur_reg = dins, mm["base"]
                    continue
                break
            if mm["base"] is None and mm["index"] is None:
                facts.append(("global", tgt))
                break
            if mm["base"] in ("ESP", "EBP"):
                facts.append(("local", mm["base"], mm["disp"]))
                break
            facts.append(("field", mm["base"], mm["disp"]))
            if mm["base"]:
                cur_ins, cur_reg = dins, mm["base"]
                continue
            break
        if src.upper() in REGS32:
            cur_ins, cur_reg = dins, src.upper()
            continue
        v = parse_int(src)
        if v is None:
            vs = imm_values(dins)
            v = sorted(vs)[0] if vs else None
        if v is not None:
            v &= 0xFFFFFFFF
            facts.append(("global_obj", v) if IMG["lo"] <= v <= IMG["hi"] else ("imm", v))
        break
    return out, facts


def facts_expr(facts):
    u"""факты цепочки -> выражение для значения исходного регистра: (текст, тип). Тип: global|global_obj|this|expr|extern|zero|imm|local"""
    base = None
    kind = "expr"
    steps = []
    for fc in facts:
        if fc[0] == "global":
            return u"*(DAT_%s)" % hx(fc[1]), "global"
        if fc[0] == "global_obj":
            return u"&DAT_%s" % hx(fc[1]), "global_obj"
        if fc[0] == "zero":
            return u"0", "zero"
        if fc[0] == "imm":
            return u"0x%x" % fc[1], "imm"
        if fc[0] == "field":
            steps.append(("f", fc[1], fc[2]))
        elif fc[0] == "embedded":
            steps.append(("e", fc[1], fc[2]))
        elif fc[0] == "local":
            return u"локальная переменная [%s%+d]" % (fc[1], fc[2]), "local"
        elif fc[0] == "entry_reg":
            base = u"this" if fc[1] == "ECX" else u"вход:%s" % fc[1]
        elif fc[0] == "extern":
            base = u"?%s" % fc[1]
    if base is None:
        if not steps:
            return u"?", "extern"
        base = u"?%s" % steps[-1][1]
    expr = base
    for t, reg, d in reversed(steps):
        expr = u"*(%s+0x%x)" % (expr, d) if t == "f" else u"(%s+0x%x)" % (expr, d)
    if base == u"this":
        kind = "this"
    elif base.startswith(u"?"):
        kind = "extern"
    return expr, kind


def refs_to_addr(a, limit=60):
    u"""ссылки на адрес данных: список (from_int, func, тип, текст инструкции)"""
    res = []
    try:
        refs = rm.getReferencesTo(a)
    except Exception:                              # noqa: BLE001
        return res
    for r in refs:
        if len(res) >= limit:
            break
        rt = r.getReferenceType()
        fa = r.getFromAddress()
        ins = listing.getInstructionAt(fa)
        kind = u"WRITE" if rt.isWrite() else (u"READ" if rt.isRead() else (u"CALL" if rt.isCall() else u"DATA"))
        res.append((aoff(fa), fm.getFunctionContaining(fa), kind, itext(ins) if ins is not None else u"(данные)"))
    return res


def show_global(g, why, queue_writers=True, max_dec=4):
    u"""всё про глобальный адрес: ссылки, писатели (с декомпиляцией)"""
    a = A(g)
    W(u"\n#### Глобал `%s` (%s)" % (hx(g), why))
    cur = rd32(a)
    W(u"Значение в образе: %s" % dword_text(cur))
    rs = refs_to_addr(a)
    W(u"Ссылок: %d" % len(rs))
    wr = [x for x in rs if x[2] == u"WRITE"]
    for fr, fn, kind, txt in rs[:MAX_ROWS]:
        W(u"- %s `%s` в %s: `%s`" % (kind, hx(fr), fname(fn), txt))
    if queue_writers:
        done = 0
        seen = set()
        for fr, fn, kind, txt in wr:
            if fn is None or aoff(fn.getEntryPoint()) in seen:
                continue
            seen.add(aoff(fn.getEntryPoint()))
            if done >= max_dec:
                break
            emit_decompile(fn, u"пишет глобал %s" % hx(g))
            done += 1
    return rs


# =========================================================================== W1
def section_w1():
    W(u"\n# W1. Чувствительность камеры (вопрос Q2)")
    look = func_at(A_LOOK)
    if look is None:
        W(u"_нет FUN_0073F310_")
        STATUS["W1"] = u"ПУСТО"
        return
    globals_found = []
    for h, label in SENS_FUNCS:
        f = func_at(h)
        W(u"\n## {} `{}`".format(label, h))
        if f is None:
            W(u"_функции нет_")
            continue
        sites = call_sites(look, f.getEntryPoint())
        W(u"Вызовов в FUN_0073F310: {}".format(len(sites)))
        for ins in sites:
            chain, facts = chase_reg(ins, "ECX")
            note = {}
            W(u"\n### CALL по {}".format(ins.getAddress()))
            W(u"Источник ECX (линейный поиск назад, ветвления не учитываются):")
            for c in chain:
                W(u"- " + c)
                m = re.search(r"@([0-9a-f]{8})", c)
                if m:
                    note[m.group(1)] = u"определение регистра"
            marks = set([str(ins.getAddress())] + list(note.keys()))
            W(u"```")
            for l in disasm(ins.getAddress(), CTX_BEFORE, CTX_AFTER, marks, note, aoff(look.getEntryPoint())):
                W(l)
            W(u"```")
            expr, kind = facts_expr(facts)
            F("W1", u"ECX у вызова `%s` (@%s) = %s" % (h, ins.getAddress(), expr))
            for fc in facts:
                if fc[0] == "global":
                    globals_found.append((fc[1], u"указатель на объект чувствительности (ECX = значение глобала)"))
                elif fc[0] == "global_obj":
                    globals_found.append((fc[1], u"статический объект чувствительности (ECX = этот адрес)"))
    seen_g = set()
    for g, why_g in globals_found:
        if g in seen_g:
            continue
        seen_g.add(g)
        show_global(g, why_g)
    # тела
    for h, why in [(A_SENS_CURVE, u"кривая чувствительности: (a, b, c) -> множитель"), (A_SENS_CFG, u"ControllerSensitivity -> объект?")] + \
            [(x[0], x[1]) for x in SENS_FUNCS]:
        emit_decompile(func_at(h), why)
    cfgf = func_at(A_SENS_CFG)
    if cfgf is not None:
        W(u"\n## Вызываемые из FUN_004F9BC0 (глубина 1)")
        cl = callees_of(cfgf)
        for e, cf in list(cl.items())[:MAX_ROWS]:
            W(u"- %s, размер %s адресов" % (fname(cf), cf.getBody().getNumAddresses()))
        for e, cf in list(cl.items())[:6]:
            emit_decompile(cf, u"вызывается из FUN_004F9BC0")
        W(u"\n## Вызывающие FUN_004F9BC0")
        for ins, cf in call_instrs_to(cfgf)[:MAX_ROWS]:
            W(u"- %s в %s: `%s`" % (ins.getAddress(), fname(cf), itext(ins)))
        # записи полей чувствительности в FUN_004F9BC0 и её вызываемых
        W(u"\n## Записи полей чувствительности (смещения %s) в FUN_004F9BC0 и её вызываемых" % u" ".join(u"+0x%x" % d for d in SENS_DISPS))
        scan_program()
        group = [cfgf] + list(cl.values())
        rows = 0
        for gf in group:
            ge = aoff(gf.getEntryPoint())
            for reg, dmap in sorted(FN_STORES.get(ge, {}).items()):
                for d in sorted(dmap):
                    if d in SENS_DISPS:
                        ins = listing.getInstructionAt(A(dmap[d]))
                        W(u"- %s [%s+0x%x] @%s: `%s` -> %s" % (fshort(gf), reg, d, hx(dmap[d]), itext(ins) if ins else u"?",
                                                               resolve_store(ins) if ins else u"?"))
                        rows += 1
        if rows == 0:
            W(u"_записей не найдено: поля пишутся не в FUN_004F9BC0 и не в её прямых вызываемых_")
        F("W1", u"записей полей чувствительности в FUN_004F9BC0 и её вызываемых: %d" % rows)
    # ранжирование по программе
    scan_program()
    W(u"\n## Функции, которые пишут восемь полей масштаба (%s) через один регистр: кандидаты на инициализацию объекта" %
      u" ".join(u"+0x%x" % d for d in SCALE_DISPS))
    ranked = []
    for entry, regs in FN_STORES.items():
        for reg, dmap in regs.items():
            n = len(set(dmap) & set(SCALE_DISPS))
            m = len(set(dmap) & set([0x10, 0x14, 0x18, 0x1C]))
            if n >= 3:
                ranked.append((n * 2 + m, n, m, entry, reg))
    ranked.sort(reverse=True)
    if not ranked:
        W(u"_ни одна функция не пишет 3 и более полей масштаба через один регистр_")
    for score, n, m, entry, reg in ranked[:12]:
        fx = fm.getFunctionAt(A(entry))
        W(u"\n### %s через %s: полей масштаба %d из 8, полей +0x10..+0x1C %d из 4" % (fname(fx), reg, n, m))
        dmap = FN_STORES[entry][reg]
        for d in sorted(dmap):
            if d in SCALE_DISPS or d in (0x10, 0x14, 0x18, 0x1C):
                ins = listing.getInstructionAt(A(dmap[d]))
                W(u"- [%s+0x%x] @%s: %s" % (reg, d, hx(dmap[d]), resolve_store(ins) if ins else u"?"))
    for score, n, m, entry, reg in ranked[:3]:
        emit_decompile(fm.getFunctionAt(A(entry)), u"кандидат на инициализацию объекта чувствительности")
    if ranked:
        F("W1", u"кандидатов на инициализацию объекта (3+ поля масштаба): %d, лучший %s" % (
            len(ranked), fshort(fm.getFunctionAt(A(ranked[0][3])))))
    # cfg
    W(u"\n## Готовые строки для ds3probe.cfg (необязательно; все 8 слотов вечернего cfg заняты)")
    W(u"Вечерний блок (приложение A среза) занимает Trace1..Trace8. Чтобы снять фактические множители в игре, замени слоты 3 и 4 "
      u"(`OwnerCheck`, `SetTransform`: на пути рывка не нужны, T5) строками `Trace3`/`Trace4` ниже. `Trace5`/`Trace6` занимают места "
      u"`CamFollow`/`LookB` - используй их, только если готов пожертвовать H3/H6. Для thiscall `ecx` = this, `a0` = параметр `char`.")
    W(u"```")
    items = [(3, "0042ed00", "SensYaw", 2, 0, True), (4, "0042ee80", "SensPitch", 2, 0, True),
             (5, "0042ee00", "SensYawAim", 2, 0, True), (6, A_SENS_CURVE, "SensCurve", 3, 0, False)]
    for idx, h, name, nargs, thisd, withf in items:
        f = func_at(h)
        if f is None:
            continue
        bs, n = bytes_from(f.getEntryPoint(), 12)
        if idx == 5:
            W(u"# --- необязательно: вместо CamFollow ---")
        if idx == 6:
            W(u"# --- необязательно: вместо LookB. a0..a2 = три float (параметры кривой), результат в ST0 ---")
        W(u"Trace%d = %s" % (idx, h.upper()))
        W(u"Trace%d.bytes = %s" % (idx, hexbytes(bs)))
        W(u"Trace%d.name = %s" % (idx, name))
        W(u"Trace%d.args = %d" % (idx, nargs))
        W(u"Trace%d.this = %d" % (idx, thisd))
        if withf:
            W(u"Trace%d.fields = %s" % (idx, u" ".join(u"%X" % d for d in SENS_DISPS)))
    W(u"```")
    STATUS.setdefault("W1", u"ГОТОВО")


# =========================================================================== W2
def dump_group(entry, reg, hi_disps, limit=140):
    dmap = FN_STORES.get(entry, {}).get(reg, {})
    n = 0
    for d in sorted(dmap):
        ins = listing.getInstructionAt(A(dmap[d]))
        mark = u" <==" if d in hi_disps else u""
        W(u"- [%s+0x%x] @%s: %s%s" % (reg, d, hx(dmap[d]), resolve_store(ins) if ins else u"?", mark))
        n += 1
        if n >= limit:
            W(u"- ... (обрезано)")
            break


def dt_near(ins):
    u"""есть ли рядом (8 инструкций назад) ссылка на глобальный dt"""
    dts = [int(x, 16) for x in DT_GLOBALS]
    for p in back_instrs(ins, 10):
        for to, rd, wr in ref_types(p):
            if to in dts:
                return True
    return False


def section_w2():
    W(u"\n# W2. Поле +0x70 и масштабы LookUpdate (вопрос Q1)")
    look = func_at(A_LOOK)
    if look is None:
        W(u"_нет FUN_0073F310_")
        STATUS["W2"] = u"ПУСТО"
        return
    scan_program()
    W(u"Проход по программе: %d функций, %d инструкций; записей `[reg+disp]` в индексе: %d функций" % (
        SCAN["functions"], SCAN["instructions"], len(FN_STORES)))
    # --- что видит сам LookUpdate
    W(u"\n## Обращения LookUpdate к +0x70 и к глобальному dt")
    dts = [int(x, 16) for x in DT_GLOBALS]
    rows = 0
    for ins in listing.getInstructions(look.getBody(), True):
        txt = itext(ins)
        mm = None
        for op in split_ops(txt):
            m = parse_mem(op)
            if m is not None and m["disp"] == 0x70 and m["base"] is not None:
                mm = m
        refs_dt = [to for to, rd, wr in ref_types(ins) if to in dts]
        if mm is not None or refs_dt:
            W(u"- %s `%s`%s" % (ins.getAddress(), txt, u"   <== глобальный dt" if refs_dt else u""))
            rows += 1
            if rows >= 60:
                W(u"- ...")
                break
    W(u"_Если dt глобальный (012A9AA8) и `[this+0x70]` встречаются в одном выражении (платформа: `ω·dt·[+0x70]`), то `+0x70` - безразмерный "
      u"множитель, а не dt: иначе получилось бы dt в квадрате. Это довод, не доказательство._")
    # --- виртуальная таблица
    W(u"\n## Виртуальная таблица класса FUN_0073F310 и конструктор")
    vts = vtable_info(look)
    ctor_funcs = []
    if not vts:
        W(u"_адрес FUN_0073F310 не найден ни в одной таблице указателей (вызывается напрямую или не виртуальная)_")
    for v in vts:
        W(u"- слот `%s` (индекс %d, смещение +0x%x), таблица начинается в `%s`, длина %d слотов, символ: %s" % (
            hx(v["slot"]), v["index"], v["index"] * 4, hx(v["start"]), v["length"], v["sym"] or u"(нет)"))
        if not v["ctors"]:
            W(u"  - записей `MOV [reg], %s` не найдено" % hx(v["start"]))
        for addr, entry in v["ctors"][:6]:
            cf = fm.getFunctionAt(A(entry)) or fm.getFunctionContaining(A(addr))
            W(u"  - конструктор/деструктор: %s, запись vftable @%s" % (fname(cf), hx(addr)))
            ctor_funcs.append((cf, addr, entry))
    if vts:
        F("W2", u"таблицы с FUN_0073F310: %d; конструкторов-кандидатов: %d" % (len(vts), len(ctor_funcs)))
    for cf, addr, entry in ctor_funcs[:4]:
        ins = listing.getInstructionAt(A(addr))
        reg = "ESI"
        if ins is not None:
            ops = split_ops(itext(ins))
            mm = parse_mem(ops[0]) if ops else None
            if mm and mm["base"]:
                reg = mm["base"]
        W(u"\n### Поля, записанные в %s через %s" % (fname(cf), reg))
        dump_group(entry, reg, set(LOOK_DISPS + [0xD8]))
        W(u"\nКонструкторы-предки (вызываемые), которые пишут нужные смещения:")
        found_callee = False
        for e, cc in callees_of(cf).items():
            for creg, dmap in FN_STORES.get(e, {}).items():
                hits = sorted(d for d in dmap if d in TRACK_DISPS)
                if hits:
                    found_callee = True
                    W(u"- %s через %s: %s" % (fname(cc), creg, u", ".join(u"+0x%x" % d for d in hits)))
                    for d in hits:
                        ins2 = listing.getInstructionAt(A(dmap[d]))
                        W(u"    +0x%x @%s: %s" % (d, hx(dmap[d]), resolve_store(ins2) if ins2 else u"?"))
        if not found_callee:
            W(u"_нет_")
        emit_decompile(cf, u"конструктор класса LookUpdate")
        # значения ключевых полей в сводку
        dmap = FN_STORES.get(entry, {}).get(reg, {})
        for d in LOOK_DISPS:
            if d in dmap:
                ins3 = listing.getInstructionAt(A(dmap[d]))
                F("W2", u"%s = %s (конструктор %s)" % (LOOK_NAMES[d], resolve_store(ins3) if ins3 else u"?", fshort(cf)))
    # --- писатели по программе
    W(u"\n## Писатели полей по всей программе (ранжирование по числу совпавших смещений в одном регистре)")
    ranked = []
    for entry, regs in FN_STORES.items():
        for reg, dmap in regs.items():
            core = len(set(dmap) & set(LOOK_CORE))
            if core >= 2:
                bonus = len(set(dmap) & set([0x70, 0xD8, 0x1D0, 0x1D4]))
                ranked.append((core * 3 + bonus, core, entry, reg))
    ranked.sort(reverse=True)
    if not ranked:
        W(u"_ни одна функция не пишет 2 и более из +0x150/+0x158/+0xC8/+0xCC/+0xD0/+0xD4 через один регистр_")
    for score, core, entry, reg in ranked[:10]:
        fx = fm.getFunctionAt(A(entry))
        W(u"\n### %s через %s: совпало %d из 6 смещений масштаба/пределов" % (fname(fx), reg, core))
        dmap = FN_STORES[entry][reg]
        for d in sorted(dmap):
            if d in TRACK_DISPS:
                ins = listing.getInstructionAt(A(dmap[d]))
                near = u""
                if d == 0x70 and ins is not None:
                    near = u"   [dt рядом: %s]" % (u"ДА" if dt_near(ins) else u"нет")
                W(u"- [%s+0x%x] @%s: %s%s" % (reg, d, hx(dmap[d]), resolve_store(ins) if ins else u"?", near))
    for score, core, entry, reg in ranked[:2]:
        if not any(entry == c[2] for c in ctor_funcs):
            emit_decompile(fm.getFunctionAt(A(entry)), u"кандидат: пишет масштаб/пределы камеры")
    if ranked:
        F("W2", u"писателей по программе (2+ поля масштаба/пределов): %d, лучший %s" % (
            len(ranked), fshort(fm.getFunctionAt(A(ranked[0][2])))))
    # --- все записи +0x70 рядом с dt
    W(u"\n## Записи [reg+0x70] в функциях, которые ссылаются на глобальный dt (012A9AA8)")
    dt_funcs = set()
    for g in DT_GLOBALS[:1]:
        for r in rm.getReferencesTo(A(g)):
            cf = fm.getFunctionContaining(r.getFromAddress())
            if cf is not None:
                dt_funcs.add(aoff(cf.getEntryPoint()))
    both = []
    for entry in dt_funcs:
        for reg, dmap in FN_STORES.get(entry, {}).items():
            if 0x70 in dmap:
                both.append((entry, reg, dmap[0x70]))
    W(u"Функций, читающих dt: %d; из них пишут [reg+0x70]: %d" % (len(dt_funcs), len(both)))
    for entry, reg, addr in both[:MAX_ROWS]:
        ins = listing.getInstructionAt(A(addr))
        W(u"- %s [%s+0x70] @%s: %s   [dt рядом: %s]" % (fname(fm.getFunctionAt(A(entry))), reg, hx(addr),
                                                        resolve_store(ins) if ins else u"?",
                                                        u"ДА" if (ins is not None and dt_near(ins)) else u"нет"))
    F("W2", u"функций, пишущих [reg+0x70] и читающих dt: %d" % len(both))
    STATUS.setdefault("W2", u"ГОТОВО")


# --------------------------------------------------------------- таблицы виртуальных функций
VT_CACHE = {}


def code_ptr(v):
    if v is None or v < IMG["lo"] or v > IMG["hi"]:
        return False
    a = A(v)
    blk = mem.getBlock(a)
    if blk is None or not blk.isExecute():
        return False
    return listing.getInstructionAt(a) is not None


def sym_name(a):
    try:
        s = currentProgram.getSymbolTable().getPrimarySymbol(a)   # noqa: F821
        if s is None:
            return None
        return u"{}".format(s.getName(True))
    except Exception:                              # noqa: BLE001
        return None


def vtable_info(func):
    key = aoff(func.getEntryPoint())
    if key in VT_CACHE:
        return VT_CACHE[key]
    scan_program()
    slots = OrderedDict()
    for r in rm.getReferencesTo(func.getEntryPoint()):
        if r.getReferenceType().isCall():
            continue
        fa = r.getFromAddress()
        if listing.getInstructionAt(fa) is None:
            slots[aoff(fa)] = "ref"
    for hit in find_all_bytes(le32(key), 40):
        blk = mem.getBlock(hit)
        if blk is not None and not blk.isExecute():
            slots.setdefault(aoff(hit), "bytes")
    res = []
    seen_start = set()
    for s in slots:
        start = s
        n = 0
        while n < 256 and code_ptr(rd32(A(start - 4))):
            start -= 4
            n += 1
        if start in seen_start:
            continue
        seen_start.add(start)
        k = 0
        while k < 512 and code_ptr(rd32(A(start + 4 * k))):
            k += 1
        res.append({"slot": s, "start": start, "index": (s - start) // 4, "length": k, "sym": sym_name(A(start)),
                    "ctors": VT_STORES.get(start, [])})
    VT_CACHE[key] = res
    return res


# =========================================================================== W3
def section_w3():
    W(u"\n# W3. Скорость разворота (гипотеза H4)")
    scan_program()
    look = func_at(A_LOOK)
    reach = reach_set(look, 2) if look is not None else set()
    W(u"Достижимо из FUN_0073F310 за <= 2 вызова: %d функций (для проверки 'читает ли это рыскание камеры')" % len(reach))
    # --- строки
    strings = OrderedDict()
    for pat in STRING_PATTERNS:
        for hit in find_all_bytes([ord(c) for c in pat], 60):
            start = hit
            for _ in range(90):
                try:
                    b = rd8(start.add(-1))
                except Exception:                  # noqa: BLE001
                    break
                if b is None or b < 0x20 or b > 0x7E:
                    break
                start = start.add(-1)
            s = read_cstring(start, 120)
            if s and aoff(start) not in strings:
                strings[aoff(start)] = s
    W(u"\n## Найденные строки (%s)" % u", ".join(STRING_PATTERNS))
    if not strings:
        W(u"_строк нет_")
    handlers = OrderedDict()                       # entry -> [(строка, источник)]
    for h, name in TURN_HANDLERS:
        f = func_at(h)
        if f is not None:
            handlers.setdefault(aoff(f.getEntryPoint()), []).append((name, u"известен из среза"))
    for sa, s in list(strings.items())[:80]:
        rs = refs_to_addr(A(sa), 12)
        W(u"- `%s` \"%s\": ссылок %d" % (hx(sa), s, len(rs)))
        for fr, fn, kind, txt in rs[:6]:
            W(u"    - %s `%s` в %s: `%s`" % (kind, hx(fr), fshort(fn), txt))
            ins = listing.getInstructionAt(A(fr))
            fn_entry = aoff(fn.getEntryPoint()) if fn is not None else None
            best = []
            if ins is not None:
                def funcs_in(ci, acc):
                    if ci is None:
                        return
                    for v in sorted(cand_values(ci)):
                        if IMG["lo"] <= v <= IMG["hi"]:
                            tf = fm.getFunctionAt(A(v))
                            if tf is not None and aoff(tf.getEntryPoint()) != fn_entry and tf not in acc:
                                acc.append(tf)
                funcs_in(ins, best)
                pi = ni = ins
                dist = 0
                while not best and dist < 8:
                    dist += 1
                    pi = pi.getPrevious() if pi is not None else None
                    ni = ni.getNext() if ni is not None else None
                    funcs_in(pi, best)            # 'PUSH handler / PUSH string': предыдущая ближе всего
                    funcs_in(ni, best)
            else:
                for off in (-4, 4, -8, 8, -12, 12, -16, 16):
                    v = rd32(A(fr).add(off))
                    if v is not None and IMG["lo"] <= v <= IMG["hi"]:
                        tf = fm.getFunctionAt(A(v))
                        if tf is not None and tf not in best:
                            best.append(tf)
                        if best:
                            break
            if "TurnSpeed" in s or "Sens" in s or "Limit" in s or "Speed" in s:
                for tf in best:
                    handlers.setdefault(aoff(tf.getEntryPoint()), []).append((s, u"ближайший адрес функции к ссылке @%s" % hx(fr)))
    # --- обработчики
    W(u"\n## Обработчики-кандидаты и что они пишут")
    cam_access = {}
    for h in [A_LOOK, A_APPLY, A_FOLLOW, A_LOOKB, A_CURVE, "00647820", "0067a420", "00552030"]:
        cf = func_at(h)
        if cf is None:
            continue
        for ins in listing.getInstructions(cf.getBody(), True):
            for op in split_ops(itext(ins)):
                m = parse_mem(op)
                if m is not None and m["base"] is not None and m["disp"] >= 0:
                    cam_access.setdefault(m["disp"], set()).add(cf.getName())
    shown = 0
    verdict_rows = []
    for e, srcs in handlers.items():
        hf = fm.getFunctionAt(A(e))
        if hf is None:
            continue
        shown += 1
        if shown > 12:
            break
        names = u"; ".join(sorted(set(s[0] for s in srcs)))
        W(u"\n### %s  (%s)" % (fname(hf), names))
        for s, how in srcs[:4]:
            W(u"- строка %s: %s" % (s, how))
        W(u"Размер: %s адресов; вызываемых: %d" % (hf.getBody().getNumAddresses(), len(callees_of(hf))))
        # записи в поля
        written = []
        for reg, dmap in sorted(FN_STORES.get(e, {}).items()):
            for d in sorted(dmap):
                written.append((reg, d))
                ins = listing.getInstructionAt(A(dmap[d]))
                W(u"- запись [%s+0x%x] @%s: %s" % (reg, d, hx(dmap[d]), resolve_store(ins) if ins else u"?"))
        # записи в глобалы
        gl = []
        for ins in listing.getInstructions(hf.getBody(), True):
            for to, rd, wr in ref_types(ins):
                if wr:
                    gl.append((to, ins))
        for to, ins in gl[:10]:
            W(u"- запись в глобал `%s` @%s: `%s`" % (hx(to), ins.getAddress(), itext(ins)))
        # читатели глобалов в камере
        reader_hits = []
        for to, ins in gl[:10]:
            for r in rm.getReferencesTo(A(to)):
                rt = r.getReferenceType()
                if rt.isWrite() or rt.isCall():
                    continue
                rf = fm.getFunctionContaining(r.getFromAddress())
                if rf is not None and aoff(rf.getEntryPoint()) in reach:
                    reader_hits.append((to, rf))
        if reader_hits:
            for to, rf in reader_hits[:8]:
                W(u"- ЧИТАЕТСЯ достижимой из LookUpdate функцией: глобал `%s` читает %s" % (hx(to), fname(rf)))
        coll = []
        for reg, d in written:
            if look is not None and d in cam_access and look.getName() in cam_access[d]:
                coll.append(d)
        if coll:
            W(u"- совпадения смещений с обращениями LookUpdate: %s (возможна случайность: смещения повторяются в разных классах)" %
              u", ".join(u"+0x%x" % d for d in coll))
        verdict_rows.append((fshort(hf), names, len(written), len(gl), len(reader_hits), len(coll)))
        emit_decompile(hf, u"обработчик команды разворота")
    W(u"\n## Итоговая таблица W3")
    W(u"| обработчик | строка | записей в поля | записей в глобалы | читателей глобала в зоне LookUpdate | совпадений смещений с LookUpdate |")
    W(u"|---|---|---|---|---|---|")
    for r in verdict_rows:
        W(u"| %s | %s | %d | %d | %d | %d |" % r)
        F("W3", u"%s (%s): глобалов записано %d, читателей в зоне LookUpdate %d, совпадений смещений %d" % (r[0], r[1], r[3], r[4], r[5]))
    if not verdict_rows:
        F("W3", u"обработчики не найдены")
    W(u"\nИнтерпретация: 'читателей в зоне LookUpdate > 0' говорит, что значение достижимо из кода взгляда; 'совпадений смещений' - слабый признак. "
      u"Окончательный ответ по H4 даст декомпиляция обработчика и рантайм-проверка (`ApplyRotDelta a1` против `out`).")
    STATUS.setdefault("W3", u"ГОТОВО")


# =========================================================================== W4
def usage_kind(ins):
    mn = ins.getMnemonicString().upper()
    text = itext(ins)
    m = SIZE_RE.search(text)
    sz = m.group(1).lower() if m else None
    if mn in SS_MN:
        return "f32"
    if mn in SD_MN or (mn == "MOVSD" and sz == "qword"):
        return "f64"
    if sz == "float":
        return "f32"
    if sz == "double":
        return "f64"
    if mn.startswith("FI"):
        return "int"
    if mn.startswith("F") and sz == "dword":
        return "f32"
    if mn.startswith("F") and sz == "qword":
        return "f64"
    if sz:
        return "i" + sz
    return "?"


def const_uses(a, limit=200):
    uses = []
    for r in rm.getReferencesTo(a):
        rt = r.getReferenceType()
        if rt.isCall() or rt.isWrite():
            continue
        ins = listing.getInstructionAt(r.getFromAddress())
        if ins is None:
            continue
        uses.append((ins, fm.getFunctionContaining(r.getFromAddress()), usage_kind(ins)))
        if len(uses) >= limit:
            break
    return uses


def const_row(h, why):
    a = A(h)
    lo = rd32(a)
    hi = rd32(a.add(4))
    if lo is None:
        return u"| %s | ? | ? | ? | ? | %s | |" % (h if isinstance(h, _STR) else hx(h), why), None
    q = (hi << 32) | lo if hi is not None else lo
    uses = const_uses(a)
    cnt = {}
    for ins, fn, k in uses:
        cnt[k] = cnt.get(k, 0) + 1
    n32 = cnt.get("f32", 0)
    n64 = cnt.get("f64", 0)
    x32 = f32(lo)
    x64 = f64(q) if hi is not None else None
    m32 = match_known(x32)
    m64 = match_known(x64) if x64 is not None else None
    if n64 > 0 and n32 == 0:
        typ, val = u"double", x64
        guess = m64
    elif n32 > 0 and n64 == 0:
        typ, val = u"float", x32
        guess = m32
    elif n32 > 0 and n64 > 0:
        typ, val, guess = u"смешанно (f32 %d / f64 %d)" % (n32, n64), None, (u"f32=%s f64=%s" % (m32, m64))
    else:
        if m64 is not None and m32 is None:
            typ, val, guess = u"double (по значению)", x64, m64
        elif m32 is not None and m64 is None:
            typ, val, guess = u"float (по значению)", x32, m32
        else:
            typ, val, guess = u"неясно (читателей нет или не FPU)", None, (m64 or m32)
    hexs = u"%08X_%08X" % (hi if hi is not None else 0, lo)
    users = u", ".join(sorted(set(fshort(fn) for ins, fn, k in uses if fn is not None))[:4])
    cnts = u", ".join(u"%s:%d" % (k, v) for k, v in sorted(cnt.items()))
    row = u"| %s | %s | %s | %s | %s | %s | %s | %s |" % (
        h if isinstance(h, _STR) else hx(h), typ, fnum(val) if val is not None else u"-",
        u"f32 %s / f64 %s" % (fnum(x32), fnum(x64) if x64 is not None else u"?"), hexs, guess or u"-", cnts or u"-", users or why)
    return row, (typ, val, guess)


def section_w4():
    W(u"\n# W4. Константы (читаются по 8 байт; тип определяется по инструкциям-читателям)")
    W(u"Колонки: адрес | тип | значение | оба толкования | hex (старший_младший dword) | совпадение с известным числом | "
      u"читатели по виду (f32/f64/целое) | кто читает или назначение")
    W(u"")
    W(u"| адрес | тип | значение | оба толкования | hex | совпадение | читатели | кто / зачем |")
    W(u"|---|---|---|---|---|---|---|---|")
    summary = []
    for h, why in CONSTANTS:
        row, info = const_row(h, why)
        W(row)
        if info and info[1] is not None:
            summary.append(u"%s = %s (%s)%s" % (h, fnum(info[1]), info[0], u" = " + info[2] if info[2] else u""))
        elif info:
            summary.append(u"%s: %s" % (h, info[0]))
    for s in summary:
        F("W4", s)
    W(u"\n## Все константы, читаемые цепочкой камеры (автоматически, из .rdata; без перечисленных выше)")
    known = set(int(h, 16) for h, w in CONSTANTS)
    found = OrderedDict()
    for h in AUTO_CONST_FUNCS:
        cf = func_at(h)
        if cf is None:
            continue
        for ins in listing.getInstructions(cf.getBody(), True):
            if ins.getMnemonicString() in ("LEA", "PUSH", "CALL", "JMP") or not any(
                    parse_mem(op) is not None for op in split_ops(itext(ins))):
                continue
            for to, rd, wr in ref_types(ins):
                if wr or to in known:
                    continue
                blk = mem.getBlock(A(to))
                if blk is None or blk.isExecute() or blk.isWrite():
                    continue
                found.setdefault(to, set()).add(cf.getName())
    W(u"Найдено уникальных адресов: %d" % len(found))
    W(u"")
    W(u"| адрес | тип | значение | оба толкования | hex | совпадение | читатели | кто / зачем |")
    W(u"|---|---|---|---|---|---|---|---|")
    for to in sorted(found)[:150]:
        row, info = const_row(hx(to), u", ".join(sorted(found[to])[:3]))
        W(row)
    if len(found) > 150:
        W(u"_показаны первые 150 из %d_" % len(found))
    F("W4", u"автоматически найдено констант в .rdata, читаемых цепочкой камеры: %d" % len(found))
    STATUS.setdefault("W4", u"ГОТОВО")


# =========================================================================== W5
def section_w5():
    W(u"\n# W5. Источник win/blend/clamp сглаживателя (вопрос Q3)")
    scan_program()
    pat1 = [0x89, 0x88, 0x08, 0x3D]
    pat3 = pat1 + [0x00, 0x00, 0x80, 0x3F, 0x00, 0x00, 0x00, 0x40]
    hits = find_all_bytes(pat1, 60)
    trip = set(aoff(h) for h in find_all_bytes(pat3, 60))
    W(u"Байты `89 88 08 3D` (float 1/30): вхождений %d; из них с продолжением `00 00 80 3F 00 00 00 40` (win=1/30, blend=1.0, clamp=2.0): %d" % (
        len(hits), len(trip)))
    F("W5", u"вхождений 1/30 (float) в памяти: %d; тройка {1/30, 1.0, 2.0} подряд: %d" % (len(hits), len(trip)))
    readers_total = 0
    for h in hits[:20]:
        o = aoff(h)
        blk = mem.getBlock(h)
        W(u"\n## Вхождение `%s` (блок %s%s)%s" % (hx(o), blk.getName() if blk else u"?", u", исполняемый" if (blk and blk.isExecute()) else u"",
                                               u"  <== ТРОЙКА 1/30, 1.0, 2.0" if o in trip else u""))
        ins = listing.getInstructionContaining(h)
        if ins is not None:
            W(u"Внутри инструкции `%s` @%s" % (itext(ins), ins.getAddress()))
        dat = None
        try:
            dat = listing.getDataContaining(h)
        except Exception:                          # noqa: BLE001
            pass
        if dat is not None:
            try:
                W(u"Данные: тип %s, начало %s, длина %s" % (dat.getDataType().getName(), dat.getMinAddress(), dat.getLength()))
            except Exception:                      # noqa: BLE001
                pass
        W(u"Дамп dword (-16..+32), floatами:")
        W(u"```")
        for off in range(-16, 36, 4):
            v = rd32(h.add(off))
            W(u"%s %+3d: %s" % (hx(o + off), off, dword_text(v)))
        W(u"```")
        base_cands = [o, o - 4, o - 8, o - 12]
        shown = set()
        for b in base_cands:
            for fr, fn, kind, txt in refs_to_addr(A(b), 30):
                if (fr, b) in shown:
                    continue
                shown.add((fr, b))
                W(u"- ссылка на `%s` (%s): %s `%s` в %s: `%s`" % (hx(b), u"точно на 1/30" if b == o else u"на начало структуры -%d" % (o - b),
                                                                  kind, hx(fr), fname(fn), txt))
                readers_total += 1
                if fn is not None:
                    pass
        # дизассемблер вокруг читателей
        done = set()
        for b in base_cands:
            for fr, fn, kind, txt in refs_to_addr(A(b), 6):
                if fn is None or aoff(fn.getEntryPoint()) in done:
                    continue
                done.add(aoff(fn.getEntryPoint()))
                W(u"\nКонтекст @%s:" % hx(fr))
                W(u"```")
                for l in disasm(A(fr), 10, 12, set([str(A(fr))])):
                    W(l)
                W(u"```")
                if len(done) <= 3:
                    emit_decompile(fn, u"читает структуру/значение 1/30")
    F("W5", u"ссылок на найденные адреса: %d" % readers_total)
    # --- читатели 00D22BB0
    W(u"\n## Читатели константы 30.0 (`%s`): возможно, win вычисляется как 1/30 на лету" % CONST_SMOOTH_C)
    rs = refs_to_addr(A(CONST_SMOOTH_C), 40)
    for fr, fn, kind, txt in rs:
        W(u"- %s `%s` в %s: `%s`" % (kind, hx(fr), fname(fn), txt))
    F("W5", u"читателей 30.0 (`00D22BB0`): %d, функции: %s" % (
        len(rs), u", ".join(sorted(set(fshort(x[1]) for x in rs if x[1] is not None))[:6])))
    # --- вызывающие StickSmooth
    sm = func_at(A_SMOOTH)
    if sm is not None:
        W(u"\n## Вызывающие FUN_0040D820: откуда ECX (this сглаживателя)")
        for ins, cf in call_instrs_to(sm)[:16]:
            chain, facts = chase_reg(ins, "ECX")
            W(u"\n### CALL @%s в %s" % (ins.getAddress(), fname(cf)))
            for c in chain:
                W(u"- " + c)
            expr, kind = facts_expr(facts)
            F("W5", u"вызов FUN_0040D820 @%s: this = %s" % (ins.getAddress(), expr))
    # --- кандидаты по записям [reg+4/+8/+0xC]
    W(u"\n## Функции, пишущие [reg+4], [reg+8], [reg+0xC] и ещё что-то из +0x10..+0x30 одним регистром (кандидаты на конструктор объекта сглаживателя)")
    W(u"Фильтр по значениям: [reg+8] = 1.0 и [reg+0xC] = 2.0 (точное совпадение с параметрами сглаживателя).")
    exact = []
    partial = []
    total = 0
    for entry, regs in FN_STORES.items():
        for reg, dmap in regs.items():
            if 4 in dmap and 8 in dmap and 0xC in dmap and any(0x10 <= d <= 0x30 for d in dmap):
                total += 1
                i8 = listing.getInstructionAt(A(dmap[8]))
                ic = listing.getInstructionAt(A(dmap[0xC]))
                v8, u8, x8 = store_value(i8) if i8 else (u"?", None, None)
                vc, uc, xc = store_value(ic) if ic else (u"?", None, None)
                is8 = (u8 == 0x3F800000) or (x8 == 1.0)
                isc = (uc == 0x40000000) or (xc == 2.0)
                if is8 and isc:
                    exact.append((entry, reg, v8, vc))
                elif isc or is8:
                    partial.append((entry, reg, v8, vc))
    W(u"Групп с набором {+4,+8,+0xC,+0x10..+0x30}: %d; точных совпадений: %d; частичных (одно из двух): %d" % (total, len(exact), len(partial)))
    F("W5", u"кандидатов-конструкторов с [reg+8]=1.0 и [reg+0xC]=2.0: %d (частичных %d)" % (len(exact), len(partial)))
    for entry, reg, v8, vc in exact[:12]:
        fx = fm.getFunctionAt(A(entry))
        W(u"\n### ТОЧНО: %s через %s" % (fname(fx), reg))
        dump_group(entry, reg, set([4, 8, 0xC, 0x30]), 60)
        F("W5", u"конструктор-кандидат: %s через %s ([+8]=%s, [+0xC]=%s)" % (fshort(fx), reg, v8, vc))
    for entry, reg, v8, vc in exact[:3]:
        emit_decompile(fm.getFunctionAt(A(entry)), u"точный кандидат на конструктор сглаживателя")
    for entry, reg, v8, vc in partial[:10]:
        fx = fm.getFunctionAt(A(entry))
        W(u"- частично: %s через %s: [+8]=%s, [+0xC]=%s" % (fname(fx), reg, v8, vc))
    STATUS.setdefault("W5", u"ГОТОВО")


# =========================================================================== W6
def section_w6():
    W(u"\n# W6. Вызывающие потребителей стика (гипотеза H6), глубина %d" % CALLER_DEPTH)
    for h, why in CALLER_TARGETS:
        f = func_at(h)
        W(u"\n## %s `%s` (%s)" % (fname(f), h, why))
        if f is None:
            W(u"_функции нет_")
            continue
        levels = callers_levels(f, CALLER_DEPTH)
        total = 0
        for i, lv in enumerate(levels, 1):
            total += len(lv)
            W(u"- уровень %d (%d): %s" % (i, len(lv), u", ".join(fname(x) for x in lv[:30]) if lv else u"-"))
        vts = vtable_info(f)
        for v in vts:
            W(u"- адрес функции лежит в таблице `%s` (слот %d, индекс %d, символ %s); записей vftable в конструкторах: %d" % (
                hx(v["start"]), v["index"] * 4, v["index"], v["sym"] or u"-", len(v["ctors"])))
            for addr, entry in v["ctors"][:4]:
                cf = fm.getFunctionAt(A(entry)) or fm.getFunctionContaining(A(addr))
                W(u"    - конструктор: %s" % fname(cf))
        if levels and levels[0]:
            W(u"\nСтроки в вызывающих 1-го уровня (подсказка о режиме игры):")
            for cf in levels[0][:12]:
                ss = func_strings(cf)
                W(u"- %s: %s" % (fshort(cf), u"; ".join(u"\"%s\"" % s for s in ss) if ss else u"(строк нет)"))
        F("W6", u"%s: вызывающих L1+L2 = %d, таблиц %d" % (fshort(f), total, len(vts)))
        # прямые ссылки (не вызовы), например указатели в таблицах
        nonc = [x for x in refs_to_addr(f.getEntryPoint(), 40) if x[2] != u"CALL"]
        if nonc:
            W(u"Ссылки на функцию, не вызовы:")
            for fr, fn, kind, txt in nonc[:10]:
                W(u"- %s `%s` в %s: `%s`" % (kind, hx(fr), fshort(fn), txt))
    STATUS.setdefault("W6", u"ГОТОВО")


# =========================================================================== W7
def section_w7():
    W(u"\n# W7. Проверка владельца камеры: FUN_00AA25F0, FUN_00AA9200, FUN_0050C960")
    for h, why in OWNER_TARGETS:
        f = func_at(h)
        if f is None:
            W(u"\n_%s: функции нет_" % h)
            continue
        emit_decompile(f, why)
        lv = callers_levels(f, 1)
        W(u"Вызывающие: " + (u", ".join(fname(x) for x in lv[0][:20]) if lv and lv[0] else u"-"))
        ss = func_strings(f)
        if ss:
            W(u"Строки внутри: " + u"; ".join(u"\"%s\"" % s for s in ss))
        F("W7", u"%s декомпилирована; вызывающих %d" % (fshort(f), len(lv[0]) if lv else 0))
    STATUS.setdefault("W7", u"ГОТОВО")


# =========================================================================== сводка
QUESTIONS = OrderedDict([
    ("W1", u"Чем масштабируется камера (Q2): ECX у вызовов чувствительности, объект, писатели полей"),
    ("W2", u"Кто пишет +0x70/+0x150/+0x158/+0xC8..+0xD4 и есть ли в них dt (Q1)"),
    ("W3", u"Влияет ли скорость разворота на рыскание камеры (H4)"),
    ("W4", u"Константы: тип и значение (закрывает T1)"),
    ("W5", u"Откуда win/blend/clamp (Q3, закрывает T3)"),
    ("W6", u"Кто вызывает потребителей стика (H6)"),
    ("W7", u"Смысл проверки владельца камеры (Q4)"),
])

NOT_AUTOMATABLE = [
    u"Калибровка 360 градусов (N360) и коэффициент k: нужна игра (протокол E2).",
    u"Значения полей `this` в рантайме (+0x70, +0xC8.. и т.д.): конструктор даёт только начальные значения, дальше их могут менять другие функции; "
    u"подтверждение даёт `Trace2.fields` на вечернем запуске.",
    u"Выбор между H1/H3/H4/H6: скрипт приносит факты (достижимость, писатели, значения), решение остаётся за разбором вместе с данными вечера.",
    u"Линейный поиск назад по листингу не знает ветвлений: источник ECX/регистров, найденный скриптом, нужно сверять по приведённому дизассемблеру.",
    u"Если класс не виртуальный или Ghidra не создала таблицу, конструктор не находится по vftable; тогда остаются ранжирование писателей и вызывающие.",
]


def build_summary():
    out = []
    out.append(u"## Сводка (собрана автоматически)")
    out.append(u"")
    out.append(u"| № | вопрос | статус | ключевые находки |")
    out.append(u"|---|---|---|---|")
    for k, q in QUESTIONS.items():
        fs = FINDINGS.get(k, [])
        st = STATUS.get(k, u"ПУСТО" if not fs else u"ГОТОВО")
        txt = u"<br>".join(fs[:8]) if fs else u"-"
        if len(fs) > 8:
            txt += u"<br>... (+%d)" % (len(fs) - 8)
        out.append(u"| %s | %s | %s | %s |" % (k, q, st, txt))
    out.append(u"")
    if u"scan" in STATUS:
        out.append(u"**Внимание: глобальный проход по инструкциям упал, индексы неполные (W2, W5 и часть W1/W3 могут быть пустыми).**")
        out.append(u"")
    out.append(u"**Чего скрипт не может и что остаётся:**")
    for s in NOT_AUTOMATABLE:
        out.append(u"- " + s)
    out.append(u"")
    out.append(u"Время прогона: %.0f с; декомпиляций: %d; функций в индексе: %d; инструкций просмотрено: %d" % (
        time.time() - T0, _DEC_N[0], SCAN["functions"], SCAN["instructions"]))
    out.append(u"")
    return out


def main():
    md5 = currentProgram.getExecutableMD5()        # noqa: F821
    head = [u"# DS3 Work91 (раздел 9.1: W1-W7)",
            u"Программа: {} | база образа: {} | MD5: `{}`".format(currentProgram.getName(), currentProgram.getImageBase(), md5), u""]   # noqa: F821
    if md5 is None or md5.lower() != ADDRESSES_FOR_MD5:
        lines.extend(head)
        lines.append(u"_MD5 не равен {}: адреса 1.0.0.1 не применимы, отчёт пуст._".format(ADDRESSES_FOR_MD5))
    else:
        log("DS3 Work91 start")
        safe(scan_program, "scan")
        log("scan finished %.0f s" % (time.time() - T0))
        safe(section_w1, "W1")
        log("W1 done %.0f s" % (time.time() - T0))
        safe(section_w2, "W2")
        log("W2 done %.0f s" % (time.time() - T0))
        safe(section_w3, "W3")
        log("W3 done %.0f s" % (time.time() - T0))
        safe(section_w4, "W4")
        log("W4 done %.0f s" % (time.time() - T0))
        safe(section_w5, "W5")
        log("W5 done %.0f s" % (time.time() - T0))
        safe(section_w6, "W6")
        log("W6 done %.0f s" % (time.time() - T0))
        safe(section_w7, "W7")
        log("W7 done %.0f s" % (time.time() - T0))
        body = list(lines)
        del lines[:]
        lines.extend(head)
        lines.extend(build_summary())
        lines.extend(body)
    path = os.path.join(OUT_DIR, "ds3_work91_{}.md".format((md5 or "unknown")[:8]))
    with io.open(path, "w", encoding="utf-8") as fh:
        fh.write(u"\n".join(lines))
    log("DS3 Work91 written: %r" % (path,))


main()
