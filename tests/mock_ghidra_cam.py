#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Макет API Ghidra для DS3_CamChain.py: проверяет ЛОГИКУ скрипта (поиск CALL FUN_004fdf60 внутри FUN_0073f310, блок отката
MOV ECX,0x28, строки cfg с байтами, константы, поиск 0x3D088889, декомпиляция, файл отчёта). Настоящую Ghidra не заменяет:
формат строк инструкций и API-вызовы в макете - мои допущения.
Запуск:  python tests/mock_ghidra_cam.py     (код возврата 0 = всё сошлось)
"""
import os
import struct
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "ghidra", "DS3_CamChain.py")


class Addr(object):
    def __init__(self, v): self.v = v
    def __str__(self): return "%08x" % self.v
    __repr__ = __str__
    def __hash__(self): return hash(self.v)
    def __eq__(self, o): return isinstance(o, Addr) and o.v == self.v
    def __ne__(self, o): return not self.__eq__(o)
    def compareTo(self, o): return (self.v > o.v) - (self.v < o.v)
    def getOffset(self): return self.v


class Scalar(object):
    def __init__(self, v): self.v = v
    def getUnsignedValue(self): return self.v


class RT(object):
    def __init__(self, call): self.call = call
    def isCall(self): return self.call


class RefFrom(object):
    def __init__(self, to, call): self.to, self.call = Addr(to), call
    def getToAddress(self): return self.to
    def getReferenceType(self): return RT(self.call)


class Ins(object):
    def __init__(self, a, mn, text, raw, sc=None, call_to=None):
        self.a, self.mn, self.text, self.raw, self.sc, self.call_to = Addr(a), mn, text, raw, sc, call_to
        self.prev = self.next = None
    def getMnemonicString(self): return self.mn
    def getAddress(self): return self.a
    def getPrevious(self): return self.prev
    def getNext(self): return self.next
    def getBytes(self): return [(b - 256 if b > 127 else b) for b in self.raw]   # как Java byte[] (знаковые)
    def getScalar(self, i):
        # второй операнд (индекс 1) - константа для MOV reg,imm; первый для PUSH imm
        if self.sc is None: return None
        if self.mn == "MOV" and i != 1: return None
        if self.mn == "PUSH" and i != 0: return None
        return Scalar(self.sc)
    def getReferencesFrom(self):
        return [RefFrom(self.call_to, True)] if self.call_to is not None else []
    def __str__(self): return self.text


class Ref(object):
    def __init__(self, frm, call): self.frm, self.call = Addr(frm), call
    def getFromAddress(self): return self.frm
    def getReferenceType(self): return RT(self.call)


class Body(object):
    def __init__(self, lo, hi): self.lo, self.hi = lo, hi


class Func(object):
    def __init__(self, name, lo, hi): self.name, self.lo, self.hi = name, lo, hi
    def getName(self): return self.name
    def getEntryPoint(self): return Addr(self.lo)
    def getBody(self): return Body(self.lo, self.hi)
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


class Mem(object):
    def __init__(self, data): self.data = data
    def getInt(self, a):
        if a.v not in self.data: raise Exception("no memory")
        v = self.data[a.v]
        return v - (1 << 32) if v >= (1 << 31) else v


class AF(object):
    def getAddress(self, s): return Addr(int(s, 16))


class Listing(object):
    def __init__(self, ins): self.ins = ins; self.by = dict((i.a.v, i) for i in ins)
    def getInstructionAt(self, a): return self.by.get(a.v)
    def getInstructions(self, x, fwd=True):
        if isinstance(x, Body):
            return iter([i for i in self.ins if x.lo <= i.a.v < x.hi])
        return iter(self.ins)


class Prog(object):
    def __init__(self, ins, funcs, refs, mem, md5):
        self.l, self.f, self.r, self.m, self.md5 = Listing(ins), FM(funcs), RM(refs), Mem(mem), md5
    def getFunctionManager(self): return self.f
    def getReferenceManager(self): return self.r
    def getListing(self): return self.l
    def getMemory(self): return self.m
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
    # FUN_0073f310 @0073f310 ... CALL 004fdf60 @0073f9f9 ... revert: MOV ECX,0x28 @0073fa10
    seq = [
        (0x73f310, "PUSH", "PUSH EBP", [0x55], None, None),
        (0x73f311, "MOV", "MOV EBP,ESP", [0x8B, 0xEC], None, None),
        (0x73f313, "SUB", "SUB ESP,0x140", [0x81, 0xEC, 0x40, 0x01, 0x00, 0x00], None, None),
        (0x73f319, "MOV", "MOV ECX,0x28", [0xB9, 0x28, 0x00, 0x00, 0x00], 0x28, None),      # первый цикл копирования (в начале) - НЕ откат
        (0x73f31e, "NOP", "NOP", [0x90], None, None),
        (0x73f9ee, "CALL", "CALL 0x00721bd0", [0xE8, 0x00, 0x00, 0x00, 0x00], None, 0x721bd0),
        (0x73f9f9, "CALL", "CALL 0x004fdf60", [0xE8, 0x62, 0x05, 0xDC, 0xFF], None, 0x4fdf60),
        (0x73f9fe, "TEST", "TEST AL,AL", [0x84, 0xC0], None, None),
        (0x73fa00, "JZ", "JZ 0x0073fa30", [0x74, 0x2E], None, None),
        (0x73fa02, "CMP", "CMP dword ptr [EBP + -0x3c],ESI", [0x39, 0x75, 0xC4], None, None),
        (0x73fa05, "JNZ", "JNZ 0x0073fa30", [0x75, 0x29], None, None),
        (0x73fa10, "MOV", "MOV ECX,0x28", [0xB9, 0x28, 0x00, 0x00, 0x00], 0x28, None),      # блок отката
        (0x73fa15, "REP", "REP MOVSD", [0xF3, 0xA5], None, None),
        (0x73fa30, "RET", "RET 0x4", [0xC2, 0x04, 0x00], None, None),
        # FUN_00721bd0
        (0x721bd0, "PUSH", "PUSH EBP", [0x55], None, None),
        (0x721bd1, "MOV", "MOV EBP,ESP", [0x8B, 0xEC], None, None),
        (0x721bd3, "SUB", "SUB ESP,0x20", [0x83, 0xEC, 0x20], None, None),
        (0x721bd6, "PUSH", "PUSH ESI", [0x56], None, None),
        (0x721bd7, "MOV", "MOV ESI,ECX", [0x8B, 0xF1], None, None),
        (0x721bd9, "RET", "RET 0x10", [0xC2, 0x10, 0x00], None, None),
        # FUN_004fdf60
        (0x4fdf60, "PUSH", "PUSH EBP", [0x55], None, None),
        (0x4fdf61, "MOV", "MOV EBP,ESP", [0x8B, 0xEC], None, None),
        (0x4fdf63, "SUB", "SUB ESP,0x40", [0x83, 0xEC, 0x40], None, None),
        (0x4fdf66, "PUSH", "PUSH ESI", [0x56], None, None),
        (0x4fdf67, "PUSH", "PUSH EDI", [0x57], None, None),
        (0x4fdf68, "RET", "RET", [0xC3], None, None),
        # конструктор сглаживателя: MOV dword ptr [ESI+4], 0x3D088889
        (0x40a000, "MOV", "MOV dword ptr [ESI + 0x4],0x3d088889", [0xC7, 0x46, 0x04, 0x89, 0x88, 0x08, 0x3D], 0x3D088889, None),
        (0x40a007, "RET", "RET", [0xC3], None, None),
    ]
    ins = []
    for a, mn, t, raw, sc, ct in seq:
        i = Ins(a, mn, t, raw, sc, ct)
        if ins and ins[-1].a.v >= a - 0x10 and ins[-1].a.v < a:   # соседние инструкции цепляем в список
            ins[-1].next = i
            i.prev = ins[-1]
        ins.append(i)
    funcs = [Func("FUN_0073f310", 0x73f310, 0x740000), Func("FUN_00721bd0", 0x721bd0, 0x721c00),
             Func("FUN_004fdf60", 0x4fdf60, 0x4fe000), Func("FUN_0040a000", 0x40a000, 0x40a010)]
    refs = {0x721bd0: [Ref(0x73f9ee, True)], 0x4fdf60: [Ref(0x73f9f9, True)], 0x73f310: [Ref(0x500000, True)]}
    mem = {0xd22bb0: struct.unpack("<I", struct.pack("<f", 30.0))[0], 0xd1ff7c: struct.unpack("<I", struct.pack("<f", 0.05))[0]}
    return Prog(ins, funcs, refs, mem, "1802f17a2cc1c2797323632862c6fb1f")


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
    rep = [f for f in os.listdir(tmp) if f.startswith("ds3_camchain_")]
    ok = True

    def chk(name, cond):
        nonlocal ok
        print("%-52s %s" % (name.encode("ascii", "replace").decode("ascii"), "OK" if cond else "FAIL"))
        ok &= bool(cond)

    chk("report file created", len(rep) == 1)
    txt = open(os.path.join(tmp, rep[0]), encoding="utf-8").read() if rep else ""
    chk("cfg: Trace1 = 00721BD0 with bytes 55 8B EC 83 EC 20 56 8B F1", "Trace1 = 00721BD0" in txt and "55 8B EC 83 EC 20 56 8B F1" in txt)
    chk("cfg: LookUpdate has fields", "Trace2.fields = 70 150 158 C8 CC D0 D4 D8 74 7C 90 134 138 164 1D0 618" in txt)
    chk("cfg: post-call hook at 0073F9FE", "= 0073F9FE" in txt and "CamCheckRet" in txt)
    chk("cfg: revert hook at 0073FA10 (not the 1st MOV ECX,0x28)", "= 0073FA10" in txt and "= 0073F319" not in txt and "RevertExec" in txt)
    chk("section 3 shows the CALL and the marks", "CALL по 0073f9f9" in txt and "=> 0073f9f9" in txt)
    chk("constants table: 30 and 0.05", "| 00d22bb0 | 30 |" in txt and "0.05" in txt)
    chk("constructor candidate 3D088889", "Инструкций с операндом 0x3D088889: 1" in txt)
    chk("callers of 00721bd0 level 1", "FUN_0073f310@0073f310" in txt)
    chk("decompile present", "mock decompile" in txt)
    chk("missing functions reported, no crash", "функции нет" in txt or "нет функции" in txt)
    print("TOTAL: %s" % ("ALL OK" if ok else "MISMATCH"))
    if not ok:
        print(txt[:4000].encode("ascii", "replace").decode("ascii"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
