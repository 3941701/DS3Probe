#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Макет API Ghidra для DS3_Work91.py. Строит маленькую программу с теми же узорами, что ищет скрипт:
  W1  CALL FUN_0042ED00 с ECX из глобала, CALL FUN_0042EE80 с ECX из поля через регистр, писатель глобала, инициализатор объекта;
  W2  виртуальная таблица LookUpdate, конструктор с записью vftable, FPU-запись предела, базовый конструктор, писатель +0x70 рядом с dt;
  W3  строки CMD_Set*TurnSpeed, регистрация обработчика (PUSH handler / PUSH string), запись в глобал, читатель в зоне LookUpdate;
  W4  константы double/float с читателями-инструкциями;
  W5  тройка {1/30, 1.0, 2.0} в .rdata, отдельное 1/30 с ссылкой из конструктора, вызов FUN_0040D820 с LEA ECX,[ESI+0x1E0];
  W6  вызывающие и строка в вызывающем; W7  декомпиляция.
Проверяет ЛОГИКУ скрипта и формат отчёта. Настоящую Ghidra не заменяет: форматы текста инструкций и API в макете - мои допущения
(тексты взяты из отчёта CamChain настоящей Ghidra: `MOV dword ptr [ESI + 0x1d0]`, `FSTP float ptr [ESP + 0x8]`, `CALL 0x00721bd0`).
Дополнительно: проверка запасного пути поиска байтов (findBytes сломан), защита от Python 2 (u-префиксы, запрещённый синтаксис).
Запуск:  python tests/mock_ghidra_work91.py     (код возврата 0 = всё сошлось)
"""
import ast
import io
import math
import os
import re
import struct
import sys
import tempfile
import tokenize
import types

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "ghidra", "DS3_Work91.py")
MD5 = "1802f17a2cc1c2797323632862c6fb1f"


def u32f(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]


def u64d(x):
    return struct.unpack("<Q", struct.pack("<d", x))[0]


PI32 = u32f(math.pi)                               # 0x40490fdb


class Addr(object):
    def __init__(self, v): self.v = v
    def __str__(self): return "%08x" % self.v
    __repr__ = __str__
    def __hash__(self): return hash(self.v)
    def __eq__(self, o): return isinstance(o, Addr) and o.v == self.v
    def __ne__(self, o): return not self.__eq__(o)
    def compareTo(self, o): return (self.v > o.v) - (self.v < o.v)
    def getOffset(self): return self.v
    def add(self, n): return Addr(self.v + n)


class RT(object):
    def __init__(self, kind): self.kind = kind
    def isCall(self): return self.kind == "call"
    def isRead(self): return self.kind == "read"
    def isWrite(self): return self.kind == "write"
    def isFlow(self): return self.kind == "flow"


class Ref(object):
    def __init__(self, frm, to, kind): self.frm, self.to, self.kind = Addr(frm), Addr(to), kind
    def getFromAddress(self): return self.frm
    def getToAddress(self): return self.to
    def getReferenceType(self): return RT(self.kind)


class Ins(object):
    def __init__(self, a, text, refs, raw):
        self.a, self.text, self.refs, self.raw = Addr(a), text, refs, raw
        self.mn = text.split()[0]
        self.prev = self.next = None
    def getMnemonicString(self): return self.mn
    def getAddress(self): return self.a
    def getPrevious(self): return self.prev
    def getNext(self): return self.next
    def getBytes(self): return [(b - 256 if b > 127 else b) for b in self.raw]
    def getScalar(self, i): return None
    def getReferencesFrom(self): return [Ref(self.a.v, to, k) for (k, to) in self.refs]
    def __str__(self): return self.text


class Body(object):
    def __init__(self, lo, hi): self.lo, self.hi = lo, hi
    def getNumAddresses(self): return self.hi - self.lo


class Func(object):
    def __init__(self, name, lo, hi): self.name, self.lo, self.hi = name, lo, hi
    def getName(self): return self.name
    def getEntryPoint(self): return Addr(self.lo)
    def getBody(self): return Body(self.lo, self.hi)
    def isThunk(self): return False
    def __str__(self): return self.name


class FM(object):
    def __init__(self, funcs): self.funcs = sorted(funcs, key=lambda f: f.lo)
    def getFunctions(self, fwd): return iter(self.funcs)
    def getFunctionContaining(self, a):
        for f in self.funcs:
            if f.lo <= a.v < f.hi: return f
        return None
    def getFunctionAt(self, a):
        for f in self.funcs:
            if f.lo == a.v: return f
        return None


class Block(object):
    def __init__(self, name, lo, size, ex, wr):
        self.name, self.lo, self.size, self.ex, self.wr = name, lo, size, ex, wr
        self.data = bytearray(size)
    def getName(self): return self.name
    def isExecute(self): return self.ex
    def isWrite(self): return self.wr
    def isInitialized(self): return True
    def getStart(self): return Addr(self.lo)
    def getSize(self): return self.size
    def has(self, v): return self.lo <= v < self.lo + self.size
    def getBytes(self, addr, buf):
        off = addr.v - self.lo
        for i in range(len(buf)):
            b = self.data[off + i] if off + i < self.size else 0
            buf[i] = b - 256 if b > 127 else b


class Mem(object):
    def __init__(self, blocks, break_find=False):
        self.blocks, self.break_find = blocks, break_find
    def _blk(self, v):
        for b in self.blocks:
            if b.has(v): return b
        return None
    def getBlock(self, a): return self._blk(a.v)
    def getBlocks(self): return list(self.blocks)
    def contains(self, a): return self._blk(a.v) is not None
    def _bytes(self, a, n):
        b = self._blk(a.v)
        if b is None: raise Exception("MemoryAccessException")
        off = a.v - b.lo
        return bytes(b.data[off:off + n])
    def getByte(self, a):
        x = self._bytes(a, 1)[0]
        return x - 256 if x > 127 else x
    def getInt(self, a): return struct.unpack("<i", self._bytes(a, 4))[0]
    def getLong(self, a): return struct.unpack("<q", self._bytes(a, 8))[0]
    def getMinAddress(self): return Addr(min(b.lo for b in self.blocks))
    def getMaxAddress(self): return Addr(max(b.lo + b.size for b in self.blocks) - 1)
    def findBytes(self, start, pat, mask, fwd, mon):
        if self.break_find:
            raise Exception("findBytes broken (test)")
        want = bytes([(x & 0xFF) for x in pat])
        for b in sorted(self.blocks, key=lambda x: x.lo):
            if b.lo + b.size <= start.v: continue
            off = max(0, start.v - b.lo)
            i = b.data.find(want, off)
            if i >= 0: return Addr(b.lo + i)
        return None


class Listing(object):
    def __init__(self, ins): self.ins = ins; self.by = dict((i.a.v, i) for i in ins)
    def getInstructionAt(self, a): return self.by.get(a.v)
    def getInstructionContaining(self, a):
        i = self.by.get(a.v)
        if i is not None: return i
        for x in self.ins:
            if x.a.v <= a.v < x.a.v + max(1, len(x.raw)): return x
        return None
    def getInstructions(self, x, fwd=True):
        if isinstance(x, Body): return iter([i for i in self.ins if x.lo <= i.a.v < x.hi])
        return iter(self.ins)
    def getDataContaining(self, a):
        if 0xD70000 <= a.v < 0xD7000C:
            d = types.SimpleNamespace()
            d.getDataType = lambda: types.SimpleNamespace(getName=lambda: "undefined4[3]")
            d.getMinAddress = lambda: Addr(0xD70000)
            d.getLength = lambda: 12
            return d
        return None


class Sym(object):
    def __init__(self, n): self.n = n
    def getName(self, ns=False): return self.n


class SymTab(object):
    def getPrimarySymbol(self, a): return Sym("LookClass::vftable") if a.v == 0xD40010 else None


class AF(object):
    def getAddress(self, s): return Addr(int(s, 16))


class DecRes(object):
    def __init__(self, name): self.name = name
    def decompileCompleted(self): return True
    def getDecompiledFunction(self): return self
    def getC(self): return "/* mock decompile of %s */" % self.name


class DecompInterface(object):
    def openProgram(self, p): pass
    def decompileFunction(self, f, t, m): return DecRes(f.getName())


class Mon(object):
    def checkCanceled(self): pass


class ArrayCls(object):
    @staticmethod
    def newInstance(t, n): return [0] * n


class Prog(object):
    def __init__(self, ins, funcs, refs, mem, md5):
        self.l, self.f, self.r, self.m, self.md5 = Listing(ins), FM(funcs), refs, mem, md5
    def getFunctionManager(self): return self.f
    def getReferenceManager(self): return self
    def getListing(self): return self.l
    def getMemory(self): return self.m
    def getAddressFactory(self): return AF()
    def getSymbolTable(self): return SymTab()
    def getName(self): return "mock.exe"
    def getImageBase(self): return Addr(0x400000)
    def getExecutableMD5(self): return self.md5
    def getReferencesTo(self, a): return [r for r in self.r if r.to.v == a.v]


def build(md5=MD5, break_find=False):
    text = Block(".text", 0x400000, 0x400000, True, False)
    rdata = Block(".rdata", 0xD00000, 0x200000, False, False)
    data = Block(".data", 0x1000000, 0x300000, False, True)
    mem = Mem([text, rdata, data], break_find)

    def put32(a, v):
        b = mem._blk(a)
        struct.pack_into("<I", b.data, a - b.lo, v & 0xFFFFFFFF)

    def put64(a, q):
        b = mem._blk(a)
        struct.pack_into("<Q", b.data, a - b.lo, q & 0xFFFFFFFFFFFFFFFF)

    def puts(a, s):
        b = mem._blk(a)
        b.data[a - b.lo:a - b.lo + len(s) + 1] = s.encode("ascii") + b"\0"

    INS = []
    FUNCS = []
    DREFS = []                                    # ссылки из данных: (from, to, kind)

    def F(name, lo, hi): FUNCS.append(Func(name, lo, hi))

    def I(a, t, refs=(), raw=None): INS.append(Ins(a, t, list(refs), raw if raw is not None else [0x8B, 0xC0, 0x90]))

    # ---------- LookUpdate
    F("FUN_0073f310", 0x73f310, 0x740000)
    I(0x73f310, "PUSH EBX", raw=[0x53])
    I(0x73f311, "MOV EBX,ESP", raw=[0x8B, 0xDC])
    I(0x73f313, "MOV ESI,ECX", raw=[0x8B, 0xF1])
    I(0x73f400, "LEA ECX,[ESI + 0x1e0]")
    I(0x73f406, "CALL 0x0040d820", [("call", 0x40d820)])
    I(0x73f800, "MOV ECX,dword ptr [0x011d3b88]", [("read", 0x11d3b88)])
    I(0x73f806, "PUSH 0x0")
    I(0x73f808, "CALL 0x0042ed00", [("call", 0x42ed00)])
    I(0x73f80d, "MOV EDI,dword ptr [ESI + 0x1d8]")
    I(0x73f813, "MOV ECX,EDI")
    I(0x73f815, "PUSH 0x0")
    I(0x73f817, "CALL 0x0042ee80", [("call", 0x42ee80)])
    I(0x73f900, "FLD float ptr [0x012a9aa8]", [("read", 0x12a9aa8)])
    I(0x73f906, "FMUL float ptr [ESI + 0x70]")
    I(0x73f909, "FLD float ptr [0x00d2047c]", [("read", 0xd2047c)])
    I(0x73f90f, "FLD double ptr [0x00d4c2a8]", [("read", 0xd4c2a8)])
    I(0x73f915, "FADD float ptr [0x00ed2e98]", [("read", 0xed2e98)])
    I(0x73f91b, "CALL 0x00650000", [("call", 0x650000)])
    I(0x73f920, "RET 0x4", raw=[0xC2, 0x04, 0x00])
    # ---------- таблица LookUpdate
    F("FUN_0073f100", 0x73f100, 0x73f110)
    I(0x73f100, "RET")
    F("FUN_0073f200", 0x73f200, 0x73f210)
    I(0x73f200, "RET")
    put32(0xD4000C, 0xD50000)
    put32(0xD40010, 0x73f100)
    put32(0xD40014, 0x73f310)
    put32(0xD40018, 0x73f200)
    DREFS.append((0xD40014, 0x73f310, "data"))
    # ---------- StickSmooth
    F("FUN_0040d820", 0x40d820, 0x40d900)
    I(0x40d820, "PUSH ESI", raw=[0x56])
    I(0x40d821, "FLD float ptr [0x00d53810]", [("read", 0xd53810)])
    I(0x40d827, "FDIV double ptr [0x00d22bb0]", [("read", 0xd22bb0)])
    I(0x40d82d, "RET 0xc", raw=[0xC2, 0x0C, 0x00])
    # ---------- чувствительность
    for nm, lo in (("0042ed00", 0x42ed00), ("0042ed80", 0x42ed80), ("0042ee00", 0x42ee00), ("0042ee80", 0x42ee80)):
        F("FUN_" + nm, lo, lo + 0x80)
        I(lo, "PUSH EBP", raw=[0x55])
        I(lo + 1, "MOV EBP,ESP", raw=[0x8B, 0xEC])
        I(lo + 3, "FLD float ptr [ECX + 0x60]", raw=[0xD9, 0x41, 0x60])
        I(lo + 6, "CALL 0x0042ec90", [("call", 0x42ec90)], raw=[0xE8, 0, 0, 0, 0])
        I(lo + 11, "RET 0x4", raw=[0xC2, 0x04, 0x00])
    F("FUN_0042ec90", 0x42ec90, 0x42ed00)
    I(0x42ec90, "PUSH EBP", raw=[0x55])
    I(0x42ec91, "MOV EBP,ESP", raw=[0x8B, 0xEC])
    I(0x42ec93, "FLD float ptr [EBP + 0x8]", raw=[0xD9, 0x45, 0x08])
    I(0x42ec96, "FMUL float ptr [EBP + 0xc]", raw=[0xD8, 0x4D, 0x0C])
    I(0x42ec99, "RET 0xc", raw=[0xC2, 0x0C, 0x00])
    # ControllerSensitivity -> объект
    F("FUN_004f9bc0", 0x4f9bc0, 0x4f9c40)
    I(0x4f9bc0, "PUSH ESI", raw=[0x56])
    I(0x4f9bc1, "MOV ESI,ECX", raw=[0x8B, 0xF1])
    I(0x4f9bc3, "CALL 0x004f9c40", [("call", 0x4f9c40)])
    I(0x4f9bc8, "RET 0x4", raw=[0xC2, 0x04, 0x00])
    F("FUN_004f9c40", 0x4f9c40, 0x4f9d00)
    I(0x4f9c40, "MOV dword ptr [ESI + 0x60],0x3f800000")
    I(0x4f9c47, "MOV dword ptr [ESI + 0x10],0x3f800000")
    I(0x4f9c4e, "RET")
    F("FUN_00632d90", 0x632d90, 0x632e00)
    I(0x632d90, "CALL 0x004f9bc0", [("call", 0x4f9bc0)])
    I(0x632d95, "RET")
    # писатель глобала
    F("FUN_00600000", 0x600000, 0x600040)
    I(0x600000, "MOV dword ptr [0x011d3b88],EAX", [("write", 0x11d3b88)])
    I(0x600005, "RET")
    # инициализатор объекта чувствительности
    F("FUN_00610000", 0x610000, 0x610100)
    for k, d in enumerate((0x10, 0x18, 0x1c, 0x60, 0x68, 0x6c, 0x84, 0x8c, 0x90)):
        I(0x610000 + k * 8, "MOV dword ptr [ESI + 0x%x],0x3f800000" % d)
    I(0x610080, "RET")
    # ---------- конструктор LookUpdate
    F("FUN_00620000", 0x620000, 0x620100)
    I(0x620000, "MOV dword ptr [ESI],0x00d40010", [("data", 0xd40010)])
    I(0x620006, "MOV dword ptr [ESI + 0x70],0x3f800000")
    I(0x62000d, "MOV dword ptr [ESI + 0x150],0x3f800000")
    I(0x620017, "FLD float ptr [0x00d28000]", [("read", 0xd28000)])
    I(0x62001d, "FSTP float ptr [ESI + 0xc8]")
    I(0x620020, "MOV EAX,0x40490fdb")
    I(0x620025, "MOV dword ptr [ESI + 0xcc],EAX")
    I(0x62002b, "XOR EDX,EDX")
    I(0x62002d, "MOV dword ptr [ESI + 0xd0],EDX")
    I(0x620033, "MOV ECX,ESI")
    I(0x620035, "CALL 0x00620100", [("call", 0x620100)])
    I(0x62003a, "RET")
    put32(0xD28000, PI32)
    F("FUN_00620100", 0x620100, 0x620140)
    I(0x620100, "MOV dword ptr [ECX + 0x158],0x3f800000")
    I(0x620107, "MOV dword ptr [ECX + 0xd4],0x3f800000")
    I(0x62010e, "RET")
    # писатель +0x70 рядом с dt
    F("FUN_00630000", 0x630000, 0x630040)
    I(0x630000, "FLD float ptr [0x012a9aa8]", [("read", 0x12a9aa8)])
    I(0x630006, "FMUL float ptr [ECX + 0x74]")
    I(0x630009, "FSTP float ptr [ECX + 0x70]")
    I(0x63000c, "RET")
    # ---------- W3
    puts(0xD60000, "CMD_SetRunTurnSpeed")
    puts(0xD60020, "CMD_SetWalkTurnSpeed")
    F("FUN_00640000", 0x640000, 0x640100)
    I(0x640000, "PUSH 0x006c6700")
    I(0x640005, "PUSH 0x00d60000", [("data", 0xd60000)])
    I(0x64000a, "CALL 0x00640100", [("call", 0x640100)])
    I(0x64000f, "PUSH 0x007d0670")
    I(0x640014, "PUSH 0x00d60020", [("data", 0xd60020)])
    I(0x640019, "CALL 0x00640100", [("call", 0x640100)])
    I(0x64001e, "RET")
    F("FUN_00640100", 0x640100, 0x640110)
    I(0x640100, "RET")
    F("FUN_006c6700", 0x6c6700, 0x6c6740)
    I(0x6c6700, "MOV EAX,dword ptr [ESP + 0x4]")
    I(0x6c6704, "MOV dword ptr [0x012b0000],EAX", [("write", 0x12b0000)])
    I(0x6c6709, "RET")
    F("FUN_007d0670", 0x7d0670, 0x7d0690)
    I(0x7d0670, "MOV dword ptr [ECX + 0x40],EAX")
    I(0x7d0674, "RET")
    F("FUN_007d0bf0", 0x7d0bf0, 0x7d0c00)
    I(0x7d0bf0, "RET")
    F("FUN_00559810", 0x559810, 0x559830)
    I(0x559810, "MOV dword ptr [ECX + 0x44],EAX")
    I(0x559814, "RET")
    F("FUN_00650000", 0x650000, 0x650020)
    I(0x650000, "MOV EAX,dword ptr [0x012b0000]", [("read", 0x12b0000)])
    I(0x650005, "RET")
    # ---------- W4: константы
    put64(0xD22BB0, u64d(30.0))
    put64(0xD4C2A8, u64d(-struct.unpack("<f", struct.pack("<f", math.pi))[0]))
    put64(0xD27BC0, u64d(struct.unpack("<f", struct.pack("<f", math.pi))[0]))
    put32(0xED2E98, u32f(2 * math.pi))
    put32(0xD53810, u32f(0.01))
    put32(0xD2047C, u32f(1.1920929e-07))
    put32(0xD1FF7C, u32f(-1.0))
    put64(0xD28718, u64d(-1.0))
    put64(0xD26DD8, u64d(struct.unpack("<f", struct.pack("<f", math.pi / 180))[0]))
    put64(0xD20590, u64d(0.5))
    put64(0xD320F8, u64d(10.0))
    put32(0x11D1F1C, u32f(3.0))
    F("FUN_0074baa0", 0x74baa0, 0x74bb40)
    I(0x74baa0, "FMUL double ptr [0x00d320f8]", [("read", 0xd320f8)])
    I(0x74baa6, "RET")
    # ---------- W5
    put32(0xD6FFFC, 1)
    put32(0xD70000, 0x3D088889)
    put32(0xD70004, 0x3F800000)
    put32(0xD70008, 0x40000000)
    put32(0xD71000, 0x3D088889)
    F("FUN_00660000", 0x660000, 0x660040)
    I(0x660000, "MOV ESI,0x00d6fffc", [("data", 0xd6fffc)])
    I(0x660005, "RET")
    F("FUN_00670000", 0x670000, 0x670080)
    I(0x670000, "FLD float ptr [0x00d71000]", [("read", 0xd71000)])
    I(0x670006, "FSTP float ptr [ESI + 0x4]")
    I(0x670009, "MOV dword ptr [ESI + 0x8],0x3f800000")
    I(0x670010, "MOV dword ptr [ESI + 0xc],0x40000000")
    I(0x670017, "XOR EDX,EDX")
    I(0x670019, "MOV dword ptr [ESI + 0x10],EDX")
    I(0x67001c, "RET")
    F("FUN_00671000", 0x671000, 0x671080)
    I(0x671000, "FLD1")
    I(0x671002, "FSTP float ptr [ESI + 0x4]")
    I(0x671005, "MOV dword ptr [ESI + 0x8],0x3f800000")
    I(0x67100c, "MOV dword ptr [ESI + 0xc],0x40400000")
    I(0x671013, "MOV dword ptr [ESI + 0x10],0x0")
    I(0x67101a, "RET")
    F("FUN_00680000", 0x680000, 0x680020)
    I(0x680000, "FLD1")
    I(0x680002, "FDIV double ptr [0x00d22bb0]", [("read", 0xd22bb0)])
    I(0x680008, "FSTP float ptr [ESI + 0x4]")
    I(0x68000b, "RET")
    # ---------- W6
    puts(0xD80000, "CameraMode")
    F("FUN_005906a0", 0x5906a0, 0x5906c0)
    I(0x5906a0, "RET")
    F("FUN_0059e1c0", 0x59e1c0, 0x59e200)
    I(0x59e1c0, "PUSH 0x00d80000", [("data", 0xd80000)])
    I(0x59e1c5, "CALL 0x005906a0", [("call", 0x5906a0)])
    I(0x59e1ca, "RET")
    F("FUN_00700000", 0x700000, 0x700020)
    I(0x700000, "CALL 0x0059e1c0", [("call", 0x59e1c0)])
    I(0x700005, "RET")
    for nm, lo in (("00549ea0", 0x549ea0), ("00647820", 0x647820), ("0067a420", 0x67a420)):
        F("FUN_" + nm, lo, lo + 0x20)
        I(lo, "RET")
    F("FUN_00654f70", 0x654f70, 0x654f90)
    I(0x654f70, "CALL 0x00647820", [("call", 0x647820)])
    I(0x654f75, "RET")
    # ---------- W7
    F("FUN_004fdf60", 0x4fdf60, 0x4fdfa0)
    I(0x4fdf60, "CALL 0x00aa25f0", [("call", 0xaa25f0)])
    I(0x4fdf65, "CALL 0x00aa9200", [("call", 0xaa9200)])
    I(0x4fdf6a, "RET")
    for nm, lo in (("00aa25f0", 0xaa25f0), ("00aa9200", 0xaa9200)):
        F("FUN_" + nm, lo, lo + 0x20)
        I(lo, "RET")
    F("FUN_0050c960", 0x50c960, 0x50c9a0)
    I(0x50c960, "CALL 0x004fdf60", [("call", 0x4fdf60)])
    I(0x50c965, "RET")

    INS.sort(key=lambda i: i.a.v)
    for a, b in zip(INS, INS[1:]):
        a.next, b.prev = b, a
    refs = []
    for i in INS:
        for k, to in i.refs:
            refs.append(Ref(i.a.v, to, k))
    for frm, to, k in DREFS:
        refs.append(Ref(frm, to, k))
    return Prog(INS, FUNCS, refs, mem, md5)


def run_script(md5=MD5, break_find=False):
    tmp = tempfile.mkdtemp(prefix="mockhome_")
    os.environ["HOME"] = tmp
    os.environ["USERPROFILE"] = tmp
    for name in ("ghidra", "ghidra.app", "ghidra.app.decompiler", "java", "java.lang", "java.lang.reflect"):
        sys.modules[name] = types.ModuleType(name)
    sys.modules["ghidra.app.decompiler"].DecompInterface = DecompInterface
    sys.modules["java.lang"].Byte = types.SimpleNamespace(TYPE="byte")
    sys.modules["java.lang.reflect"].Array = ArrayCls
    g = {"currentProgram": build(md5, break_find), "monitor": Mon(), "__name__": "__main__"}
    with open(SCRIPT, encoding="utf-8") as f:
        exec(compile(f.read(), SCRIPT, "exec"), g)
    rep = [x for x in os.listdir(tmp) if x.startswith("ds3_work91_")]
    txt = open(os.path.join(tmp, rep[0]), encoding="utf-8").read() if rep else ""
    return rep, txt


def static_checks(chk):
    src = io.open(SCRIPT, encoding="utf-8").read()
    bad = []
    for t in tokenize.generate_tokens(io.StringIO(src).readline):
        if t.type == tokenize.STRING and re.search(r"[^\x00-\x7f]", t.string):
            pref = re.match(r"^([a-zA-Z]*)", t.string).group(1).lower()
            if "u" not in pref:
                bad.append((t.start[0], t.string[:30]))
    chk("py2: every non-ASCII literal has a u prefix", not bad)
    if bad:
        print("   ", bad[:5])
    tree = ast.parse(src)
    forb = [type(n).__name__ for n in ast.walk(tree)
            if isinstance(n, (ast.JoinedStr, ast.Nonlocal, ast.AsyncFunctionDef, ast.Await, ast.AnnAssign, ast.NamedExpr, ast.YieldFrom))]
    kwonly = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and (n.args.kwonlyargs or n.args.posonlyargs)]
    chk("py2: no f-strings / nonlocal / async / walrus / kw-only args", not forb and not kwonly)
    nonascii_ident = [n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and not n.id.isascii()]
    chk("py2: ASCII identifiers only", not nonascii_ident)
    has_cat = "# @category DS3Probe" in src
    chk("ghidra header: @category DS3Probe", has_cat)


def main():
    ok = True

    def chk(name, cond):
        nonlocal ok
        print("%-74s %s" % (name.encode("ascii", "replace").decode("ascii"), "OK" if cond else "FAIL"))
        ok &= bool(cond)

    static_checks(chk)
    rep, txt = run_script()
    chk("report file created", len(rep) == 1 and rep[0] == "ds3_work91_1802f17a.md")
    chk("summary has all 7 rows", all(("| W%d |" % i) in txt for i in range(1, 8)))
    chk("summary says what cannot be automated", "Чего скрипт не может" in txt)
    st = re.findall(r"\| (W\d) \| [^|]* \| (\S+) \|", txt)
    chk("no section failed", "упала" not in txt and all(s != "ОШИБКА" for _, s in st))

    # ---- W1
    chk("W1: ED00 call found, ECX = *(DAT_011d3b88)", "ECX у вызова `0042ed00` (@0073f808) = *(DAT_011d3b88)" in txt)
    chk("W1: global writer decompiled", "### FUN_00600000@00600000  - пишет глобал 011d3b88" in txt)
    chk("W1: EE80 chain goes ECX<-EDI<-[ESI+0x1d8]<-ESI<-ECX(entry)",
        re.search(r"ECX <- MOV ECX,EDI.*\n- EDI <- MOV EDI,dword ptr \[ESI \+ 0x1d8\].*\n- ESI <- MOV ESI,ECX.*\n- ECX: до входа в функцию не менялся", txt) is not None)
    chk("W1: EE80 expression is *(this+0x1d8)", "ECX у вызова `0042ee80` (@0073f817) = *(this+0x1d8)" in txt)
    chk("W1: disassembly marks the CALL and the ECX definition", "=> 0073f808" in txt and "=> 0073f800" in txt)
    chk("W1: field writes in FUN_004f9bc0 callee found", "FUN_004f9c40 [ESI+0x60] @004f9c40" in txt and "0x3f800000" in txt)
    chk("W1: callers of FUN_004f9bc0 listed", "FUN_00632d90@00632d90" in txt)
    chk("W1: sensitivity-object initialiser ranked first", "### FUN_00610000@00610000 через ESI: полей масштаба 6 из 8" in txt)
    chk("W1: cfg Trace3 = 0042ED00 with 12 bytes", "Trace3 = 0042ED00" in txt and "Trace3.bytes = 55 8B EC D9 41 60 E8 00 00 00 00 C2" in txt)
    chk("W1: cfg SensCurve a0..a2", "Trace6.name = SensCurve" in txt and "Trace6.args = 3" in txt)

    # ---- W2
    chk("W2: vtable of LookUpdate found (slot index 1)", "слот `00d40014` (индекс 1, смещение +0x4), таблица начинается в `00d40010`, длина 3 слотов, символ: LookClass::vftable" in txt)
    chk("W2: constructor found by vftable store", "конструктор/деструктор: FUN_00620000@00620000, запись vftable @00620000" in txt)
    chk("W2: +0x70 = 1.0 from constructor", re.search(r"\[ESI\+0x70\] @00620006: 0x3f800000 \(int 1065353216 / float 1 = 1\) <==", txt) is not None)
    chk("W2: +0xC8 pi through FLD DAT / FSTP", "[ESI+0xc8] @0062001d: 3.14159274 (DAT_00d28000 (float)) = pi <==" in txt)
    chk("W2: +0xCC pi through register", "[ESI+0xcc] @00620025: 0x40490fdb" in txt and "= pi) <==" in txt)
    chk("W2: +0xD0 zero through XOR", re.search(r"\[ESI\+0xd0\] @0062002d: 0x00000000 \(int 0 / float 0\) <==", txt) is not None)
    chk("W2: base constructor stores +0x158 and +0xD4", "FUN_00620100@00620100 через ECX: +0xd4, +0x158" in txt)
    chk("W2: summary has +0x150 value", "+0x150 (масштаб рыскания) = 0x3f800000" in txt)
    chk("W2: dt-adjacent +0x70 writer found", "FUN_00630000@00630000 [ECX+0x70] @00630009" in txt and "[dt рядом: ДА]" in txt)
    chk("W2: LookUpdate dt and +0x70 usages listed", "<== глобальный dt" in txt and "FMUL float ptr [ESI + 0x70]" in txt)
    chk("W2: writers ranked (constructor first)", "### FUN_00620000@00620000 через ESI: совпало" in txt)

    # ---- W3
    chk("W3: both strings found", '"CMD_SetRunTurnSpeed"' in txt and '"CMD_SetWalkTurnSpeed"' in txt)
    chk("W3: handler found next to the string push (nearest candidate)", "### FUN_006c6700@006c6700  (CMD_SetActionTurnSpeed; CMD_SetRunTurnSpeed)" in txt)
    chk("W3: neighbour registration is not mixed in", "### FUN_007d0670@007d0670  (CMD_SetWalkTurnSpeed; CMD_SetWalkTurnSpeed (1))" in txt)
    chk("W3: register function (CALL target) is not a handler", "### FUN_00640100" not in txt)
    chk("W3: handler global write and reachable reader", "запись в глобал `012b0000`" in txt and "ЧИТАЕТСЯ достижимой из LookUpdate функцией: глобал `012b0000` читает FUN_00650000@00650000" in txt)
    chk("W3: table row for FUN_006c6700 has a reader in the zone", re.search(r"\| FUN_006c6700 \| [^|]* \| 0 \| 1 \| 1 \| 0 \|", txt) is not None)
    chk("W3: known handler FUN_007d0670 shows field write", "запись [ECX+0x40] @007d0670" in txt)

    # ---- W4
    chk("W4: 00d22bb0 is double 30 (by FDIV double ptr)", re.search(r"\| 00d22bb0 \| double \| 30 \|", txt) is not None)
    chk("W4: 00d4c2a8 double matches -pi", re.search(r"\| 00d4c2a8 \| double \| -3\.14159274 \|[^\n]*\| -pi \|", txt) is not None)
    chk("W4: 00ed2e98 float matches 2*pi", re.search(r"\| 00ed2e98 \| float \| 6\.28318548 \|[^\n]*\| 2\*pi \|", txt) is not None)
    chk("W4: unread 00d26dd8 recognised as pi/180 by value", re.search(r"\| 00d26dd8 \| double \(по значению\) \|[^\n]*\| (pi/180|0\.0174533) \|", txt) is not None)
    chk("W4: 00d320f8 is double 10 (read by FMUL double ptr)", re.search(r"\| 00d320f8 \| double \| 10 \|", txt) is not None)
    chk("W4: auto constants found (00d2047c from LookUpdate)", "| 00d2047c |" in txt and "автоматически" in txt)
    chk("W4: hex column holds both dwords", "40000000_00000000" not in txt and "403E0000_00000000" in txt)

    # ---- W5
    chk("W5: two 1/30 hits, one triple", "вхождений 2; из них с продолжением `00 00 80 3F 00 00 00 40` (win=1/30, blend=1.0, clamp=2.0): 1" in txt)
    chk("W5: triple marked", "<== ТРОЙКА 1/30, 1.0, 2.0" in txt)
    chk("W5: struct base reference found (-4)", "на начало структуры -4" in txt and "FUN_00660000" in txt)
    chk("W5: reader of the lone 1/30 found with context", "ссылка на `00d71000` (точно на 1/30): READ `00670000` в FUN_00670000@00670000" in txt)
    chk("W5: exact constructor candidate", "### ТОЧНО: FUN_00670000@00670000 через ESI" in txt)
    chk("W5: decoy only partial", "- частично: FUN_00671000@00671000 через ESI" in txt)
    chk("W5: readers of 30.0 listed", "READ `00680002` в FUN_00680000@00680000" in txt)
    chk("W5: StickSmooth caller: this = (this+0x1e0)", "вызов FUN_0040D820 @0073f406: this = (this+0x1e0)" in txt)
    chk("W5: Data containing the hit printed", "Данные: тип undefined4[3]" in txt)

    # ---- W6 / W7
    chk("W6: caller of LookB listed with string", "FUN_0059e1c0: \"CameraMode\"" in txt)
    chk("W6: level 2 for LookB", "уровень 2 (1): FUN_00700000@00700000" in txt)
    chk("W6: LookUpdate in vtable with constructor", "адрес функции лежит в таблице `00d40010` (слот 4, индекс 1" in txt and "конструктор: FUN_00620000@00620000" in txt)
    chk("W6: non-call reference to LookUpdate listed", "DATA `00d40014`" in txt)
    chk("W7: three functions decompiled", all(("### FUN_%s@%s" % (x, x)) in txt for x in ("00aa25f0", "00aa9200", "0050c960")))

    # ---- запасной путь поиска байтов и MD5-заглушка
    rep2, txt2 = run_script(break_find=True)
    chk("fallback search (findBytes broken) gives the same W5 and W2 facts",
        "вхождений 2; из них с продолжением" in txt2 and "слот `00d40014`" in txt2 and '"CMD_SetRunTurnSpeed"' in txt2)
    rep3, txt3 = run_script(md5="00" * 16)
    chk("wrong MD5: empty report with warning", "MD5 не равен" in txt3 and "W1." not in txt3)

    print("TOTAL: %s" % ("ALL OK" if ok else "MISMATCH"))
    if not ok:
        open(os.path.join(tempfile.gettempdir(), "work91_mock_report.md"), "w", encoding="utf-8").write(txt)
        print("report saved to", os.path.join(tempfile.gettempdir(), "work91_mock_report.md"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
