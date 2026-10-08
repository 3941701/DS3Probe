#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_di.py - разбор захватов DS3Probe v4: DirectInput-мышь, курсорный аккумулятор, конвейер "стик", трассировщики.

Вход: папка сессии ds3probe_logs\\<время> (или отдельные файлы ds3probe_cap_NNN_*.csv).
Для каждого захвата NNN читаются, если есть:
  _di.csv      t_ms,raw_dx,raw_dy,game_dx,game_dy,mode,out_dx,out_dy
               game_* = что отдал DirectInput ДО подмены, out_* = что получила игра (после подмены), mode = режим F9
  _acc.csv     кадры Mouse_GetState (курсорный путь): game_dx/dy = аккумулятор
  _stickv.csv  FUN_0040E680: t_ms,arg0_hex,id,active,x_out,y_out,acc_x,acc_y
  _sticks.csv  FUN_0040D820: t_ms,dt,x_in,y_in,x_out,y_out,id,win,blend,clamp,active,w0..w7,ret_hex
  _trace.csv   трассировщики из cfg

Коды режимов v4: 0 PASS, 1 DI-ZERO, 2 DI-xA, 3 DI-xB, 4 DI-xC, 5 ACC-ZERO.

Что печатается (каждый блок отвечает на свой вопрос):
  [A] DI vs курсорный путь   одно ли и то же они несут (доля совпавших кадров, отношение сумм по корзинам скорости, сдвиг по кадрам)
  [B] режимы DI              сработала ли подмена: сумма out/сумма game ~ K (ZERO ~ 0)
  [C] передаточная кривая    |вход DI| -> |выход стика| по корзинам: линейна ли она, есть ли ПОЛКА (плато) и где
  [D] режимы и стик          как ведёт себя выход стика при DI-ZERO / DI-xK (камера питается от DI?)
  [E] трассировщики          сколько вызовов, какие адреса возврата

Запуск:  python analyze_di.py <папка сессии>  [--axis x|y] [--max-pair-ms 30]
Код возврата 0, если файлы разобраны (вердикты - в тексте, это не тест).
"""
import argparse
import bisect
import csv
import glob
import math
import os
import re
import statistics
import sys

MODE_NAMES = {0: "PASS", 1: "DI-ZERO", 2: "DI-xA", 3: "DI-xB", 4: "DI-xC", 5: "ACC-ZERO"}
EDGES = [0, 1, 3, 10, 30, 100, 200, 400, 800, 10 ** 9]


def read_csv(path):
    meta, body = [], []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for line in f:
            (meta if line.startswith("#") else body).append(line.rstrip("\r\n"))
    rows = []
    for d in csv.DictReader(body):
        rows.append(d)
    return meta, rows


def fnum(d, k, default=0.0):
    v = d.get(k)
    if v is None or v == "":
        return default
    try:
        return float(v)
    except ValueError:
        try:
            return float(int(v, 16))
        except ValueError:
            return default


def meta_get(meta, key, default=None):
    for line in meta:
        m = re.search(key + r"=([^\s;]+)", line)
        if m:
            return m.group(1)
    return default


def corr(a, b):
    n = min(len(a), len(b))
    if n < 3:
        return float("nan")
    sa = sum(x * x for x in a[:n])
    sb = sum(x * x for x in b[:n])
    if sa <= 0 or sb <= 0:
        return float("nan")
    return sum(x * y for x, y in zip(a[:n], b[:n])) / math.sqrt(sa * sb)


def bin_index(v):
    a = abs(v)
    for i in range(len(EDGES) - 1):
        if EDGES[i] <= a < EDGES[i + 1]:
            return i
    return len(EDGES) - 2


def bin_label(i):
    lo, hi = EDGES[i], EDGES[i + 1]
    return "[%d,%s)" % (lo, "inf" if hi >= 10 ** 9 else str(hi))


def pct(v, p):
    if not v:
        return float("nan")
    s = sorted(v)
    k = min(len(s) - 1, max(0, int(round(p * (len(s) - 1)))))
    return s[k]


class Cap(object):
    def __init__(self, idx):
        self.idx = idx
        self.di = []      # (t, bx, by, ox, oy, mode)
        self.acc = []     # (t, ax, ay, mode)
        self.stickv = []  # (t, x, y, accx, accy, active, id)
        self.sticks = []  # (t, dt, xin, yin, xout, yout, clamp, active, id)
        self.trace = []   # (t, id, ecx, ret)
        self.meta = []
        self.raw_ref = None
        self.legacy_di = False


def load_session(paths):
    caps = {}
    for p in paths:
        m = re.search(r"cap_(\d+)_(di|acc|stickv|sticks|trace)\.csv$", os.path.basename(p))
        if not m:
            continue
        idx, kind = int(m.group(1)), m.group(2)
        cap = caps.setdefault(idx, Cap(idx))
        meta, rows = read_csv(p)
        if not cap.meta:
            cap.meta = meta
        if kind == "di":
            legacy = bool(rows) and ("out_dx" not in rows[0])
            cap.legacy_di = legacy
            if legacy:   # v3: нет столбцов mode/out_*: подмены не было, out = game, режим F9 v3 лежит в _acc.csv
                cap.di = [(fnum(r, "t_ms"), fnum(r, "game_dx"), fnum(r, "game_dy"), fnum(r, "game_dx"), fnum(r, "game_dy"), 0) for r in rows]
            else:
                cap.di = [(fnum(r, "t_ms"), fnum(r, "game_dx"), fnum(r, "game_dy"), fnum(r, "out_dx"), fnum(r, "out_dy"), int(fnum(r, "mode"))) for r in rows]
        elif kind == "acc":
            cap.acc = [(fnum(r, "t_ms"), fnum(r, "game_dx"), fnum(r, "game_dy"), int(fnum(r, "mode"))) for r in rows]
        elif kind == "stickv":
            cap.stickv = [(fnum(r, "t_ms"), fnum(r, "x_out"), fnum(r, "y_out"), fnum(r, "acc_x"), fnum(r, "acc_y"), int(fnum(r, "active")), int(fnum(r, "id"))) for r in rows]
        elif kind == "sticks":
            cap.sticks = [(fnum(r, "t_ms"), fnum(r, "dt"), fnum(r, "x_in"), fnum(r, "y_in"), fnum(r, "x_out"), fnum(r, "y_out"), fnum(r, "clamp"), int(fnum(r, "active")), int(fnum(r, "id"))) for r in rows]
        elif kind == "trace":
            cap.trace = [(fnum(r, "t_ms"), int(fnum(r, "id")), r.get("ecx", ""), r.get("ret", "")) for r in rows]
    for c in caps.values():
        rr = meta_get(c.meta, "raw_reference")
        c.raw_ref = rr
    return [caps[k] for k in sorted(caps)]


# ---------------------------------------------------------------- [A] DI vs курсорный путь
def block_a(cap, axis, out):
    if not cap.di or not cap.acc:
        out("  [A] нужны оба файла (_di и _acc) - пропущено")
        return
    ci = 1 if axis == "x" else 2
    di = [r[ci] for r in cap.di]
    ac = [r[ci] for r in cap.acc]
    n = min(len(di), len(ac))
    eq = sum(1 for a, d in zip(ac, di) if a == d)
    close = sum(1 for a, d in zip(ac, di) if abs(a - d) <= max(2.0, 0.1 * abs(d)))
    out("  [A] кадров DI=%d acc=%d; совпали точно %d (%.1f%%), в пределах max(2;10%%) %d (%.1f%%)" % (len(di), len(ac), eq, 100.0 * eq / max(1, n), close, 100.0 * close / max(1, n)))
    lags = []
    for lag in range(-3, 4):
        a, d = [], []
        for i in range(max(0, -lag), n - max(0, lag)):
            a.append(ac[i])
            d.append(di[i + lag])
        lags.append((lag, corr(a, d)))
    best = max(lags, key=lambda x: (x[1] if x[1] == x[1] else -1))
    out("      сдвиг acc относительно DI (кадров): лучший %+d, корреляция %.4f (по сдвигам: %s)" % (best[0], best[1], " ".join("%+d:%.3f" % l for l in lags)))
    rows = []
    for lo, hi in [(1, 15), (15, 60), (60, 150), (150, 300), (300, 500), (500, 10 ** 9)]:
        sa = sd = 0.0
        k = 0
        for a, d in zip(ac, di):
            if lo <= abs(d) < hi:
                sa += abs(a)
                sd += abs(d)
                k += 1
        if k:
            rows.append("|DI|%s: n=%d acc/DI=%.3f" % (bin_label_pair(lo, hi), k, sa / sd))
    out("      отношение сумм по корзинам: " + "; ".join(rows))
    out("      вывод: %s" % ("DI и курсорный путь несут одно и то же (потерь/сжатия между ними нет)" if close / max(1, n) > 0.9 else "ДИ и курсорный путь РАСХОДЯТСЯ - см. долю совпавших кадров"))


def bin_label_pair(lo, hi):
    return "[%d,%s)" % (lo, "inf" if hi >= 10 ** 9 else str(hi))


# ---------------------------------------------------------------- [B] режимы DI
def block_b(cap, axis, out):
    if not cap.di:
        out("  [B] нет _di.csv")
        return
    if cap.legacy_di:
        out("  [B] _di.csv формата v3 (без столбцов mode/out_*): подмены DI в этом захвате не было, блок пропущен")
        return
    ci_in, ci_out = (1, 3) if axis == "x" else (2, 4)
    by_mode = {}
    for r in cap.di:
        by_mode.setdefault(r[5], []).append(r)
    for m in sorted(by_mode):
        rows = by_mode[m]
        si = sum(abs(r[ci_in]) for r in rows)
        so = sum(abs(r[ci_out]) for r in rows)
        out("  [B] режим %-8s кадров %5d | sum|game|=%9.0f sum|out|=%9.0f | out/game=%s | max|game|=%.0f max|out|=%.0f" % (
            MODE_NAMES.get(m, str(m)), len(rows), si, so, ("%.3f" % (so / si)) if si > 0 else "n/a",
            max(abs(r[ci_in]) for r in rows), max(abs(r[ci_out]) for r in rows)))


# ---------------------------------------------------------------- [C], [D] передаточная кривая DI -> стик
def pair_stick(cap, stick_rows, axis, max_ms, t_idx, out_idx_x, out_idx_y, mode_filter=None):
    """Каждую запись стика парим с ПОСЛЕДНИМ чтением DI не позже неё; на кадр DI берём запись с наибольшим |out|."""
    if not cap.di or not stick_rows:
        return []
    ts = [r[0] for r in cap.di]
    best = {}
    for s in stick_rows:
        t = s[t_idx]
        k = bisect.bisect_right(ts, t) - 1
        if k < 0 or t - ts[k] > max_ms:
            continue
        v = s[out_idx_x] if axis == "x" else s[out_idx_y]
        if k not in best or abs(v) > abs(best[k][1]):
            best[k] = (k, v)
    res = []
    for k, (_, v) in best.items():
        d = cap.di[k]
        mode = d[5]
        if mode_filter is not None and mode not in mode_filter:
            continue
        res.append((d[3] if axis == "x" else d[4], v, mode, d[1] if axis == "x" else d[2]))  # (вход после подмены, выход стика, режим, вход до подмены)
    return res


def transfer_table(pairs, out, title):
    if len(pairs) < 20:
        out("  %s: мало пар (%d) для таблицы" % (title, len(pairs)))
        return None
    bins = {}
    for vin, vout, mode, vin0 in pairs:
        bins.setdefault(bin_index(vin), []).append((abs(vin), abs(vout)))
    gmax = max(abs(p[1]) for p in pairs) or 1.0
    out("  %s (пар %d, максимум |выхода| %.4g)" % (title, len(pairs), gmax))
    out("      корзина |вход|     n    медиана|вх|  медиана|вых|   p95|вых|    max|вых|   медиана(|вых|/|вх|)")
    rows = []
    for i in sorted(bins):
        v = bins[i]
        ins = [a for a, _ in v]
        outs = [b for _, b in v]
        ratios = [b / a for a, b in v if a > 0]
        mr = statistics.median(ratios) if ratios else float("nan")
        out("      %-14s %5d   %10.4g  %10.4g  %10.4g  %10.4g   %14.4g" % (
            bin_label(i), len(v), statistics.median(ins), statistics.median(outs), pct(outs, 0.95), max(outs), mr))
        if len(v) >= 5 and mr == mr:
            rows.append({"i": i, "n": len(v), "ratio": mr, "min": statistics.median(ins), "mout": statistics.median(outs)})
    return rows, gmax


def verdict_curve(res, out):
    """Сжатие: отношение вых/вх в быстрых корзинах упало ниже 60% опорного (опора - корзины 1..4, то есть до 100 отсчётов/кадр).
    Плато: медиана выхода в верхней корзине не больше чем на 15% выше, чем в корзине, где вход был в 1.5+ раза меньше."""
    if not res:
        return
    rows, gmax = res
    if len(rows) < 3:
        out("      вердикт: данных в корзинах мало")
        return
    low = [r["ratio"] for r in rows if 1 <= r["i"] <= 4]
    base = statistics.median(low) if low else float("nan")
    if base != base or base <= 0:
        out("      вердикт: нет опорных малых скоростей")
        return
    high = [r for r in rows if r["i"] >= 5]
    flags = []
    for r in high:
        if r["ratio"] < 0.6 * base:
            flags.append("корзина %s: вых/вх = %.3g при опорном %.3g (сжатие в %.1f раза)" % (bin_label(r["i"]), r["ratio"], base, base / r["ratio"]))
    plateau = False
    cand = [r for r in rows if r["i"] >= 3]
    if len(cand) >= 2:
        top = cand[-1]
        for r in cand[:-1]:
            if r["mout"] >= 0.85 * top["mout"] and top["min"] >= 1.5 * r["min"]:
                plateau = True
                flags.append("ПЛАТО: с входа ~%.0f выход перестал расти (медиана вых %.4g при входе ~%.0f, %.4g при входе ~%.0f)" % (
                    r["min"], r["mout"], r["min"], top["mout"], top["min"]))
                break
    if flags:
        out("      ВЕРДИКТ: выход стика НЕ линеен по входу DI: " + "; ".join(flags))
    else:
        out("      ВЕРДИКТ: выход стика пропорционален входу DI до наблюдаемых скоростей (сжатия и плато не найдено)")


def block_c(cap, axis, max_ms, out):
    for name, rows, ti, ox, oy in (("стик FUN_0040E680 (_stickv)", [(r[0], r[1], r[2]) for r in cap.stickv], 0, 1, 2),
                                   ("стик FUN_0040D820 (_sticks)", [(r[0], r[4], r[5]) for r in cap.sticks], 0, 1, 2)):
        if not rows:
            continue
        pairs = pair_stick(cap, rows, axis, max_ms, ti, ox, oy, mode_filter=set([0]))
        res = transfer_table(pairs, out, "[C] PASS: |вход DI| -> |выход| " + name)
        verdict_curve(res, out)


def block_d(cap, axis, max_ms, out):
    modes_present = sorted(set(r[5] for r in cap.di))
    for name, rows in (("_stickv", [(r[0], r[1], r[2]) for r in cap.stickv]), ("_sticks", [(r[0], r[4], r[5]) for r in cap.sticks])):
        if not rows:
            continue
        for m in modes_present:
            pairs = pair_stick(cap, rows, axis, max_ms, 0, 1, 2, mode_filter=set([m]))
            if len(pairs) < 10:
                continue
            ins = [abs(p[0]) for p in pairs]
            outs = [abs(p[1]) for p in pairs]
            si = sum(ins)
            out("  [D] %-8s %-8s пар %5d: sum|вход после подмены|=%9.0f, sum|выход|=%10.4g, max|вых|=%.4g, кадров с |вых|>1e-6: %d%s" % (
                name, MODE_NAMES.get(m, str(m)), len(pairs), si, sum(outs), max(outs), sum(1 for o in outs if o > 1e-6),
                "  <- выход стика НЕ нулевой при обнулённом DI: стик питается не от DI" if (m == 1 and max(outs) > 1e-6 and si == 0) else ""))


# ---------------------------------------------------------------- [E] трассировщики
def block_e(cap, out):
    if not cap.trace:
        return
    by = {}
    for t, i, ecx, ret in cap.trace:
        by.setdefault(i, []).append((ecx, ret))
    for i in sorted(by):
        rets = {}
        ecxs = {}
        for ecx, ret in by[i]:
            rets[ret] = rets.get(ret, 0) + 1
            ecxs[ecx] = ecxs.get(ecx, 0) + 1
        out("  [E] Trace%d: %d вызовов; адреса возврата: %s; this: %s" % (
            i, len(by[i]), ", ".join("%s x%d" % kv for kv in sorted(rets.items(), key=lambda kv: -kv[1])[:6]),
            ", ".join("%s x%d" % kv for kv in sorted(ecxs.items(), key=lambda kv: -kv[1])[:4])))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="папка сессии или файлы ds3probe_cap_NNN_*.csv")
    ap.add_argument("--axis", choices=["x", "y"], default="x")
    ap.add_argument("--max-pair-ms", type=float, default=30.0, help="максимальный разрыв между чтением DI и вызовом стика при парировании")
    a = ap.parse_args(argv)
    try:   # вывод в файл/пайп на Windows иначе идёт в cp1251/cp1252 и падает на кириллице
        if not sys.stdout.isatty() and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    files = []
    for p in a.paths:
        if os.path.isdir(p):
            files += glob.glob(os.path.join(p, "ds3probe_cap_*_*.csv"))
        else:
            files.append(p)
    caps = load_session(files)
    if not caps:
        print("нет файлов ds3probe_cap_NNN_*.csv")
        return 1
    out = print
    for cap in caps:
        out("=== захват %03d ===" % cap.idx)
        out("  кадров: DI %d, acc %d; записей: stickv %d, sticks %d, trace %d; raw_reference=%s" % (len(cap.di), len(cap.acc), len(cap.stickv), len(cap.sticks), len(cap.trace), cap.raw_ref))
        block_a(cap, a.axis, out)
        block_b(cap, a.axis, out)
        block_c(cap, a.axis, a.max_pair_ms, out)
        block_d(cap, a.axis, a.max_pair_ms, out)
        block_e(cap, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
