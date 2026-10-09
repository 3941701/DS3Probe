# -*- coding: utf-8 -*-
# DS3 writers: разбор адресов, найденных "ловцом писателей" v4.4 (F3). Для каждого адреса инструкции:
#   - функция, в которую он попадает, её вызывающие;
#   - дизассемблирование вокруг адреса (±WINDOW инструкций), с пометкой самой инструкции;
#   - декомпиляция функции;
# и отдельно для "объемлющей" функции камеры (по адресу возврата из стека) - список ВСЕХ вызовов по порядку
# (адрес вызова, вызываемая функция) и все float-константы (в том числе 7.5 = 0x40F00000), чтобы увидеть порядок
# внутри кадра: обновление следящих углов -> положение камеры -> LookUpdate -> чтение матрицы -> SetTransform.
#
# Адреса - адреса Ghidra (в логе в скобках "ghidra XXXXXXXX"). Пишет ~/ds3_writers_<md5[:8]>.md. Ничего не меняет в базе.
# НЕ проверялся автором внутри Ghidra (только py_compile). Если упадёт - пришли текст ошибки из консоли.
#
# @category DS3Probe
from __future__ import print_function

import io
import os

from ghidra.app.decompiler import DecompInterface

# ----------------------------- НАСТРОЙКИ -----------------------------------
# (имя, адрес инструкции из watch-строки лога v4.4)
HITS = [
    ("W1 write ctrl+0x44 (yaw слоя)",       "00A60520"),
    ("W3 write ctrl+0x40 (pitch слоя)",     "00A60538"),
    ("W2 write ctrl+0x20 (положение)",      "0074D620"),
    ("W4 read cam+0x30 (после LookUpdate)", "0074D7ED"),
    ("W4 read cam+0x30 (копия в LookUpdate)", "0073F36D"),
    ("W4 read cam+0x30 (внешний читатель)", "006CA383"),
]
# адреса возврата (первый адрес exe из стека) - вызывающая функция камеры; по ним строится таблица вызовов
CALLER_ADDRS = ["0074D089", "0074D7D9", "0074DC7A", "0072B222"]
WINDOW = 14
DECOMP_TIMEOUT = 60
OUT_DIR = os.path.expanduser("~")
# ---------------------------------------------------------------------------

fm = currentProgram.getFunctionManager()          # noqa: F821
listing = currentProgram.getListing()             # noqa: F821
af = currentProgram.getAddressFactory()           # noqa: F821
rm = currentProgram.getReferenceManager()         # noqa: F821
lines = []
decomp_done = set()


def W(s=u""):
    lines.append(u"{}".format(s))


def A(h):
    return af.getAddress(h)


def fname(f):
    return u"(вне функции)" if f is None else u"{}@{}".format(f.getName(), f.getEntryPoint())


def safe(fn, label):
    try:
        fn()
    except Exception as e:                        # noqa: BLE001
        W(u"\n_секция {} упала: {}_".format(label, e))


def func_at(addr):
    f = fm.getFunctionContaining(addr)
    return f


def callers(f):
    res = []
    if f is None:
        return res
    for r in rm.getReferencesTo(f.getEntryPoint()):
        if r.getReferenceType().isCall():
            cf = fm.getFunctionContaining(r.getFromAddress())
            res.append((r.getFromAddress(), cf))
    return res


def disasm(center, window):
    ins = listing.getInstructionContaining(center)
    if ins is None:
        W(u"_по адресу нет инструкции (не дизассемблировано?)_")
        return
    before = []
    cur = ins
    for _ in range(window):
        cur = cur.getPrevious()
        if cur is None:
            break
        before.append(cur)
    before.reverse()
    seq = before + [ins]
    cur = ins
    for _ in range(window):
        cur = cur.getNext()
        if cur is None:
            break
        seq.append(cur)
    W(u"```")
    for i in seq:
        mark = u"  <== ловушка сработала ПОСЛЕ этой/предыдущей инструкции" if i.getAddress() == ins.getAddress() else u""
        W(u"{}  {}{}".format(i.getAddress(), i.toString(), mark))
    W(u"```")


def code_bytes(addr, n=16):
    """Байты по адресу в формате ключа cfg TraceN.bytes (для mid-хука на этом адресе)."""
    try:
        bs = bytearray(n)
        currentProgram.getMemory().getBytes(addr, bs)                 # noqa: F821
        return u" ".join(u"%02X" % b for b in bs)
    except Exception as e:                        # noqa: BLE001
        return u"(не прочитано: {})".format(e)


def decompile(f, di):
    if f is None or f.getEntryPoint() in decomp_done:
        return
    decomp_done.add(f.getEntryPoint())
    W(u"\n#### Декомпиляция {}\n```c".format(fname(f)))
    try:
        res = di.decompileFunction(f, DECOMP_TIMEOUT, monitor)          # noqa: F821
        if res and res.decompileCompleted():
            W(res.getDecompiledFunction().getC())
        else:
            W(u"/* не декомпилировано: {} */".format(res.getErrorMessage() if res else "?"))
    except Exception as e:                        # noqa: BLE001
        W(u"/* ошибка декомпиляции: {} */".format(e))
    W(u"```")


def call_table(f):
    """Все вызовы функции по порядку адресов + float-константы."""
    W(u"\n#### Вызовы внутри {} (по порядку адресов)".format(fname(f)))
    W(u"| адрес вызова | вызываемая функция |")
    W(u"|---|---|")
    it = listing.getInstructions(f.getBody(), True)
    consts = []
    for ins in it:
        if ins.getFlowType().isCall():
            tgt = u"?"
            for r in ins.getReferencesFrom():
                if r.getReferenceType().isCall():
                    tf = fm.getFunctionContaining(r.getToAddress())
                    tgt = fname(tf) if tf else u"{}".format(r.getToAddress())
            W(u"| {} | {} |".format(ins.getAddress(), tgt))
        else:
            for k in range(ins.getNumOperands()):
                for o in ins.getOpObjects(k):
                    try:
                        v = o.getUnsignedValue()
                    except Exception:             # noqa: BLE001
                        continue
                    if v == 0x40F00000:
                        consts.append((ins.getAddress(), u"7.5f (0x40F00000)", ins.toString()))
    for a, d, s in consts:
        W(u"\n- float 7.5 как непосредственная константа: {}  `{}`".format(a, s))


def main():
    di = DecompInterface()
    di.openProgram(currentProgram)                # noqa: F821
    W(u"# DS3: функции, найденные ловцом писателей v4.4\n")
    W(u"Версия базы: {}\n".format(currentProgram.getName()))   # noqa: F821
    for name, h in HITS:
        def one(name=name, h=h):
            a = A(h)
            f = func_at(a)
            W(u"\n## {} — {}  ({})".format(name, h, fname(f)))
            if f is not None:
                W(u"Вызывающие: " + u", ".join(u"{} (из {})".format(fa, fname(cf)) for fa, cf in callers(f)[:12]))
            W(u"Байты по адресу (для TraceN.bytes): `{}`".format(code_bytes(a)))
            disasm(a, WINDOW)
            decompile(f, di)
        safe(one, name)
    W(u"\n# Функции камеры по адресам возврата")
    for h in CALLER_ADDRS:
        def one2(h=h):
            a = A(h)
            f = func_at(a)
            W(u"\n## адрес {} — {}".format(h, fname(f)))
            if f is not None:
                call_table(f)
                disasm(a, 6)
                decompile(f, di)
        safe(one2, "caller " + h)
    path = os.path.join(OUT_DIR, "ds3_writers_%s.md" % currentProgram.getExecutableMD5()[:8])   # noqa: F821
    with io.open(path, "w", encoding="utf-8") as fh:
        fh.write(u"\n".join(lines))
    print("written: " + path)


main()
