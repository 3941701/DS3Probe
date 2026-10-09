# -*- coding: utf-8 -*-
# DS3 range: дизассемблирование диапазона адресов с пояснениями (вызовы - с именами функций, обращения к данным по
# абсолютному адресу - со значением как float/int). Нужен там, где Ghidra не выделила функцию ("вне функции"),
# например внешняя функция камеры вокруг 0074D6C0..0074E200 (оттуда вызываются LookUpdate 0074D7D4, SetTransform
# 0074DC7A и FUN_0074CF50 в 0074DF1D). Дополнительно печатает все места, где встречается константа 7.5 (0x40F00000)
# и умножение на [reg+0x120]/[reg+0x70]. Пишет ~/ds3_range_<START>_<md5[:8]>.md. Ничего не меняет в базе.
# НЕ проверялся автором внутри Ghidra (только py_compile). Если упадёт - пришли текст ошибки.
#
# @category DS3Probe
from __future__ import print_function

import io
import os
import struct

# ----------------------------- НАСТРОЙКИ -----------------------------------
START = "0074D6C0"
END = "0074E200"
OUT_DIR = os.path.expanduser("~")
# ---------------------------------------------------------------------------

fm = currentProgram.getFunctionManager()          # noqa: F821
listing = currentProgram.getListing()             # noqa: F821
mem = currentProgram.getMemory()                  # noqa: F821
af = currentProgram.getAddressFactory()           # noqa: F821
lines = []


def W(s=u""):
    lines.append(u"{}".format(s))


def read_dword(addr):
    try:
        bs = bytearray(4)
        mem.getBytes(addr, bs)
        return struct.unpack("<I", bytes(bs))[0]
    except Exception:                             # noqa: BLE001
        return None


def note_for(ins):
    notes = []
    if ins.getFlowType().isCall():
        for r in ins.getReferencesFrom():
            if r.getReferenceType().isCall():
                tf = fm.getFunctionContaining(r.getToAddress())
                notes.append(u"-> {}".format(u"{}@{}".format(tf.getName(), tf.getEntryPoint()) if tf else r.getToAddress()))
    else:
        for r in ins.getReferencesFrom():
            if r.getReferenceType().isData() or r.getReferenceType().isRead():
                ta = r.getToAddress()
                if ta is not None and ta.isMemoryAddress():
                    d = read_dword(ta)
                    if d is not None:
                        notes.append(u"[{}] = 0x{:08X} / float {:.6g}".format(ta, d, struct.unpack("<f", struct.pack("<I", d))[0]))
    for k in range(ins.getNumOperands()):
        for o in ins.getOpObjects(k):
            try:
                v = o.getUnsignedValue()
            except Exception:                     # noqa: BLE001
                continue
            if v == 0x40F00000:
                notes.append(u"*** константа 7.5f")
    return u"; " + u"; ".join(notes) if notes else u""


def main():
    start = af.getAddress(START)
    end = af.getAddress(END)
    W(u"# DS3: дизассемблирование {}..{}\n".format(START, END))
    W(u"Функции, чьи тела пересекают диапазон: " + u", ".join(
        u"{}@{}..{}".format(f.getName(), f.getEntryPoint(), f.getBody().getMaxAddress()) for f in fm.getFunctions(True)
        if f.getBody().contains(start) or (f.getEntryPoint().compareTo(start) >= 0 and f.getEntryPoint().compareTo(end) <= 0)))
    W(u"")
    W(u"```")
    ins = listing.getInstructionAt(start) or listing.getInstructionAfter(start)
    n = 0
    while ins is not None and ins.getAddress().compareTo(end) <= 0:
        bs = u" ".join(u"%02X" % (b & 0xFF) for b in ins.getBytes())
        W(u"{}  {:<24} {:<40} {}".format(ins.getAddress(), bs, ins.toString(), note_for(ins)))
        ins = ins.getNext()
        n += 1
    W(u"```")
    W(u"\nИнструкций: {}".format(n))
    path = os.path.join(OUT_DIR, "ds3_range_%s_%s.md" % (START, currentProgram.getExecutableMD5()[:8]))   # noqa: F821
    with io.open(path, "w", encoding="utf-8") as fh:
        fh.write(u"\n".join(lines))
    print("written: " + path)


main()
