#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Макет API Ghidra для DS3_DiConsumers.py: проверяет ЛОГИКУ скрипта (разбор CALL [reg+off], PUSH-константы, классификация,
буферы, вызывающие, файл отчёта). Настоящую Ghidra не заменяет: формат строк инструкций в макете - мои допущения.
Запуск:  python tests/mock_ghidra_di.py     (код возврата 0 = всё сошлось)
"""
import os
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "ghidra", "DS3_DiConsumers.py")


class Addr(object):
    def __init__(self, v): self.v = v
    def __str__(self): return "%08x" % self.v
    __repr__ = __str__
    def __hash__(self): return hash(self.v)
    def __eq__(self, o): return isinstance(o, Addr) and o.v == self.v
    def __ne__(self, o): return not self.__eq__(o)
    def getOffset(self): return self.v


class Scalar(object):
    def __init__(self, v): self.v = v
    def getUnsignedValue(self): return self.v


class Ins(object):
    def __init__(self, a, mn, text, scalar=None):
        self.a, self.mn, self.text, self.sc, self.prev = Addr(a), mn, text, scalar, None
    def getMnemonicString(self): return self.mn
    def getAddress(self): return self.a
    def getPrevious(self): return self.prev
    def getScalar(self, i): return Scalar(self.sc) if self.sc is not None else None
    def __str__(self): return self.text


class RT(object):
    def __init__(self, call): self.call = call
    def isCall(self): return self.call
    def __str__(self): return "CALL" if self.call else "READ"


class Ref(object):
    def __init__(self, frm, call): self.frm, self.call = Addr(frm), call
    def getFromAddress(self): return self.frm
    def getReferenceType(self): return RT(self.call)


class Func(object):
    def __init__(self, name, lo, hi): self.name, self.lo, self.hi = name, lo, hi
    def getName(self): return self.name
    def getEntryPoint(self): return Addr(self.lo)
    def __str__(self): return self.name


class FM(object):
    def __init__(self, funcs): self.funcs = funcs
    def getFunctionContaining(self, a):
        for f in self.funcs:
            if f.lo <= a.v < f.hi: return f
        return None
    def getFunctionAt(self, a):
        for f in self.funcs:
            if f.lo == a.v: return f
        return None


class RM(object):
    def __init__(self, refs): self.refs = refs
    def getReferencesTo(self, a): return list(self.refs.get(a.v, []))


class Block(object):
    def __init__(self, ex): self.ex = ex
    def isExecute(self): return self.ex


class Mem(object):
    def getBlock(self, a): return Block(0x400000 <= a.v < 0x900000)


class AF(object):
    def getAddress(self, s): return Addr(int(s, 16))


class Listing(object):
    def __init__(self, ins): self.ins = ins
    def getInstructions(self, fwd): return iter(self.ins)


class Prog(object):
    def __init__(self, ins, funcs, refs, md5):
        self.l, self.f, self.r, self.md5 = Listing(ins), FM(funcs), RM(refs), md5
    def getFunctionManager(self): return self.f
    def getReferenceManager(self): return self.r
    def getListing(self): return self.l
    def getMemory(self): return Mem()
    def getAddressFactory(self): return AF()
    def getName(self): return "mock.exe"
    def getImageBase(self): return Addr(0x400000)
    def getExecutableMD5(self): return self.md5


class DecRes(object):
    def decompileCompleted(self): return True
    def getDecompiledFunction(self): return self
    def getC(self): return "/* mock decompile */"


class DecompInterface(object):
    def openProgram(self, p): pass
    def decompileFunction(self, f, t, m): return DecRes()


def build():
    seq = [
        # F1 @00500000: GetDeviceState(this, 0x14, buf=0x011d2000) + запись из буфера
        (0x500000, "PUSH", "PUSH 0x11d2000", 0x11d2000),
        (0x500005, "PUSH", "PUSH 0x14", 0x14),
        (0x500007, "PUSH", "PUSH EAX", None),
        (0x500008, "MOV", "MOV EAX,dword ptr [ESI + 0x10]", None),
        (0x50000b, "CALL", "CALL dword ptr [EDX + 0x24]", None),
        (0x50000e, "RET", "RET", None),
        # F2 @00501000: клавиатура
        (0x501000, "PUSH", "PUSH 0x11d3000", 0x11d3000),
        (0x501005, "PUSH", "PUSH 0x100", 0x100),
        (0x501007, "CALL", "CALL dword ptr [EAX + 0x24]", None),
        (0x50100a, "RET", "RET", None),
        # F3 @00502000: размер неизвестен + Acquire
        (0x502000, "PUSH", "PUSH ECX", None),
        (0x502001, "CALL", "CALL dword ptr [ESI + 0x24]", None),
        (0x502004, "CALL", "CALL dword ptr [EAX + 0x1c]", None),
        (0x502007, "CALL", "CALL 0x00500000", None),
        (0x50200c, "RET", "RET", None),
        # F4 @00503000: вызывает F1 (вызывающий)
        (0x503000, "CALL", "CALL 0x00500000", None),
        (0x503005, "RET", "RET", None),
    ]
    ins = []
    for a, mn, t, sc in seq:
        i = Ins(a, mn, t, sc)
        if ins and ins[-1].a.v // 0x1000 == a // 0x1000:
            i.prev = ins[-1]
        ins.append(i)
    funcs = [Func("FUN_00500000", 0x500000, 0x500100), Func("FUN_00501000", 0x501000, 0x501100),
             Func("FUN_00502000", 0x502000, 0x502100), Func("FUN_00503000", 0x503000, 0x503100)]
    refs = {0x500000: [Ref(0x503000, True), Ref(0x50200c - 5 + 0, True)],
            0x11d2000: [Ref(0x503000, False)], 0x11d2004: [Ref(0x502000, False)]}
    return Prog(ins, funcs, refs, "1802f17a2cc1c2797323632862c6fb1f")


def main():
    tmp = tempfile.mkdtemp(prefix="mockhome_")
    os.environ["HOME"] = tmp
    os.environ["USERPROFILE"] = tmp
    for name in ("ghidra", "ghidra.app", "ghidra.app.decompiler"):
        sys.modules[name] = types.ModuleType(name)
    sys.modules["ghidra.app.decompiler"].DecompInterface = DecompInterface
    g = {"currentProgram": build(), "monitor": None, "__name__": "__main__"}
    with open(SCRIPT, encoding="utf-8") as f:
        exec(compile(f.read(), SCRIPT, "exec"), g)
    rep = [f for f in os.listdir(tmp) if f.startswith("ds3_di_consumers_")]
    ok = True

    def chk(name, cond):
        nonlocal ok
        print("%-44s %s" % (name.encode("ascii", "replace").decode("ascii"), "OK" if cond else "FAIL"))
        ok &= bool(cond)

    chk("файл отчёта создан", len(rep) == 1)
    txt = open(os.path.join(tmp, rep[0]), encoding="utf-8").read() if rep else ""
    chk("GetDeviceState: 3 вызова", "GetDeviceState - 3 вызовов" in txt)
    chk("Acquire: 1 вызов", "Acquire - 1 вызовов" in txt)
    chk("мышь 0x14 распознана", "DIMOUSESTATE2" in txt)
    chk("клавиатура 0x100 распознана", "клавиатура (256 байт)" in txt)
    chk("размер неизвестен помечен", "размер неизвестен" in txt)
    chk("кандидат-буфер 011d2000 и читатель", "`011d2000`" in txt and "FUN_00503000" in txt)
    chk("буфер клавиатуры не в секции мыши", "`011d3000`" not in txt)
    chk("вызывающие уровня 1 у F1", "Вызывающие, уровень 1" in txt and "FUN_00503000@00503000" in txt)
    chk("декомпиляция есть", "mock decompile" in txt)
    chk("секция стика пропущена без функции", "по адресу нет функции" in txt)
    print("TOTAL: %s" % ("ALL OK" if ok else "MISMATCH"))
    if not ok:
        print(txt[:3000].encode("ascii", "replace").decode("ascii"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
