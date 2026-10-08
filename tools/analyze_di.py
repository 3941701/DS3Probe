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
  _sticks.csv  FUN_0040D820: t_ms,dt,x_in,y_in,x_out,y_out,id,win,blend,clamp,active,w0..w7,ret_hex[,caller_hex (v4.1)]
  _trace.csv   трассировщики из cfg (v4.1: + eax, base, f0..f15 = поля по смещениям из Trace<N>.fields)

Коды режимов v4: 0 PASS, 1 DI-ZERO, 2 DI-xA, 3 DI-xB, 4 DI-xC, 5 ACC-ZERO.

Что печатается (каждый блок отвечает на свой вопрос):
  [A] DI vs курсорный путь   одно ли и то же они несут (доля совпавших кадров, отношение сумм по корзинам скорости, сдвиг по кадрам)
  [B] режимы DI              сработала ли подмена: сумма out/сумма game ~ K (ZERO ~ 0)
  [C] передаточная кривая    |вход DI| -> |выход стика| по корзинам: линейна ли она, есть ли ПОЛКА (плато) и где
  [D] режимы и стик          как ведёт себя выход стика при DI-ZERO / DI-xK (камера питается от DI?)
  [E] трассировщики          сколько вызовов, какие адреса возврата, статистика аргументов/полей (как float)
  [F] модель FUN_0040D820    сверка формулы окна с логом (ошибка должна быть ~1e-6) и сколько поворота съедает клэмп ±this[3]
  [G] рывки                  события |dx|>=8: длительность, пик, сумма, хвост обратного знака (отскок на уровне ввода?)

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
        self.sticks_full = []  # (t, dt, win, blend, clamp, xout, yout, [w0..w7], caller)
        self.trace = []   # (t, id, ecx, ret)
        self.trace_rows = []
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
            cap.sticks_full = [(fnum(r, "t_ms"), fnum(r, "dt"), fnum(r, "win"), fnum(r, "blend"), fnum(r, "clamp"), fnum(r, "x_out"), fnum(r, "y_out"),
                                [fnum(r, "w%d" % k) for k in range(8)], r.get("caller_hex", "")) for r in rows]
        elif kind == "trace":
            cap.trace = [(fnum(r, "t_ms"), int(fnum(r, "id")), r.get("ecx", ""), r.get("ret", "")) for r in rows]
            cap.trace_rows = rows
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
def hex_float(h):
    """'3F800000' -> 1.0; пустое/битое -> None"""
    try:
        import struct
        return struct.unpack("<f", struct.pack("<I", int(h, 16)))[0]
    except Exception:
        return None


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
        out("  [E] Trace%d: %d вызовов; [esp] (адрес возврата, если хук на входе): %s; ecx: %s" % (
            i, len(by[i]), ", ".join("%s x%d" % kv for kv in sorted(rets.items(), key=lambda kv: -kv[1])[:6]),
            ", ".join("%s x%d" % kv for kv in sorted(ecxs.items(), key=lambda kv: -kv[1])[:4])))
        rows_i = [r for r in cap.trace_rows if int(fnum(r, "id")) == i]
        names = ["a%d" % k for k in range(8)] + ["f%d" % k for k in range(16)] + ["eax"]
        parts = []
        for nm in names:
            vals = [hex_float(r.get(nm, "")) for r in rows_i]
            vals = [v for v in vals if v is not None and v == v and abs(v) < 1e12]
            if len(vals) < 3 or all(abs(v) < 1e-30 for v in vals):
                continue
            parts.append("%s: [%.4g..%.4g] med|.|=%.4g" % (nm, min(vals), max(vals), statistics.median([abs(v) for v in vals])))
        if parts:
            out("      значения как float (константные/нулевые не показаны): " + "; ".join(parts[:14]))


# ---------------------------------------------------------------- [F] модель FUN_0040D820
WIN_C = 30.0   # константа _DAT_00d22bb0 (подобрана по данным 20261008_082440: ошибка модели < 1e-5)


def window_model(sticks_full, axis, clamp_override=None):
    """Формула FUN_0040D820 (проверена на 4 захватах):
       push: cur.x += raw/dt, cur.t += dt, cur.n += 1;  если win <= dt + cur.t(до push) - окно прокручивается (prev := cur, cur := 0).
       X_i = t_i * (x_i / n_i);   w = blend * t_cur / (t_prev + t_cur);   Xb = w*X_cur + (1-w)*X_prev;   Tb = w*t_cur + (1-w)*t_prev
       выход = clamp(Xb, +-this[3]) / (Tb * 30).
       Возвращает список (pred, Xb, Tb, real) по кадрам."""
    k = 0 if axis == "x" else 1
    res = []
    c = p = 0
    prev_ct = None
    for t, dt, win, blend, clamp, xo, yo, w, _ in sticks_full:
        cx, px, ct, pt = w[k], w[4 + k], w[2], w[6]
        if prev_ct is None:
            rotated = False
            c, p = 1, 0
        else:
            pred_rot = win <= dt + prev_ct + 1e-7
            exp_ct = (0.0 if pred_rot else prev_ct) + dt
            rotated = pred_rot if abs(exp_ct - ct) < 5e-4 else (ct < prev_ct - 1e-6)
            if rotated:
                p, c = c, 1
            else:
                c += 1
        prev_ct = ct
        mc = cx / c if c > 0 else 0.0
        Xc = ct * mc
        if p > 0 and (pt + ct) > 0:
            mp = px / p
            Xp = pt * mp
            wgt = blend * ct / (pt + ct)
            Xb = wgt * Xc + (1 - wgt) * Xp
            Tb = (1 - wgt) * pt + wgt * ct
        else:
            Xb, Tb = Xc, ct
        cl = clamp if clamp_override is None else clamp_override
        Xcl = max(-cl, min(cl, Xb))
        pred = Xcl / (Tb * WIN_C) if Tb * WIN_C > 0 else 0.0
        res.append((pred, Xb, Tb, xo if axis == "x" else yo, dt))
    return res


def block_f(cap, out):
    if len(cap.sticks_full) < 50:
        return
    for axis in ("x", "y"):
        m = window_model(cap.sticks_full, axis)
        skip = 4
        err = [abs(a - r) for a, _, _, r, _ in m[skip:]]
        nmov = sum(1 for _, _, _, r, _ in m if abs(r) > 1e-6)
        good = sum(1 for e in err if e < 1e-3)
        out("  [F] ось %s: модель окна vs лог: макс.ошибка %.2g, кадров с ошибкой <1e-3: %.2f%% (кадров с движением %d)" % (
            axis, max(err) if err else float("nan"), 100.0 * good / max(1, len(err)), nmov))
        if err and good / float(len(err)) < 0.99:
            out("      !!! модель не сходится: формула другая (другая сборка/версия?) - выводы блока F ненадёжны")
            continue
        clamp_logged = max(r[4] for r in cap.sticks_full)
        open_ = window_model(cap.sticks_full, axis, clamp_override=1e9)
        for lim in (2.0,):
            cl = window_model(cap.sticks_full, axis, clamp_override=lim)
            i_open = sum(abs(a) * dt for a, _, _, _, dt in open_)
            i_cl = sum(abs(a) * dt for a, _, _, _, dt in cl)
            n_over = sum(1 for _, xb, _, _, _ in open_ if abs(xb) > lim)
            tb = [tb_ for _, xb, tb_, _, _ in open_ if abs(xb) > lim]
            thr = (62.5 / statistics.median(tb)) if tb else float("nan")
            out("      клэмп %.1f: кадров с |Xb|>%.1f: %d из %d с движением; интеграл|вых|·dt без клэмпа %.2f, с клэмпом %.2f -> клэмп съедает %.1f%% поворота; "
                "порог %s (= 62.5/Tb: 62.5 отсчёта за окно ~2 кадра)%s" % (
                    lim, lim, n_over, nmov, i_open, i_cl, 100.0 * (1 - i_cl / i_open) if i_open > 0 else 0.0,
                    ("~%.0f отсчётов/с" % thr) if thr == thr else "не достигнут",
                    "  [в логе клэмп был открыт: F11]" if clamp_logged > 100 else ""))


# ---------------------------------------------------------------- [H] лестница клэмпа F11 (v4.1)
def block_h(cap, out):
    """F11 в v4.1 - лестница this[3]: 2 (исходный) -> 6 -> 12 -> 24 -> 1e9. Если в одном захвате встретилось 2+ значения
       клэмпа (колонка clamp в _sticks.csv), показываем по каждой ступени: кадры, кадры у потолка, максимум |вых.x|, интеграл |вых.x|*dt.
       Ступень, на которой ВПЕРВЫЕ появилось ощущение «упёрлось и отскочило» (сравните со временем нажатий F11 в ds3probe.log),
       и есть оценка предела следующего ограничителя: в единицах выхода стика max|вых.x| этой ступени."""
    sf = cap.sticks_full
    if len(sf) < 50:
        return
    levels = sorted(set(round(r[4], 3) for r in sf))
    if len(levels) < 2:
        return
    model = window_model(sf, "x")
    agg = {}
    for r, (_pred, xb, _tb, real, dt) in zip(sf, model):
        key = round(r[4], 3)
        a = agg.setdefault(key, [0, 0, 0.0, 0, 0.0])
        a[0] += 1
        if abs(real) > 1e-6:
            a[1] += 1
        a[2] = max(a[2], abs(real))
        if abs(xb) >= key * 0.999:
            a[3] += 1
        a[4] += abs(real) * dt
    out("  [H] лестница клэмпа F11 (this[3]): ступеней в захвате %d" % len(levels))
    for key in levels:
        n, nmov, mx, nceil, integ = agg[key]
        name = "открыт (1e9)" if key > 1e6 else ("%g" % key)
        out("      клэмп %-12s кадров %5d (с движением %4d) | макс|вых.x| %7.3f | кадров у потолка %4d | интеграл|вых.x|*dt %8.3f" % (name, n, nmov, mx, nceil, integ))
    out("      как читать: ступень, где «упор и отскок» начался, - первая, на которой макс|вых.x| превысил предел следующего ограничителя;"
        " отметьте время нажатий F11 в ds3probe.log и сверьте с ощущением")


# ---------------------------------------------------------------- [G] рывки
def block_g(cap, out, axis="x", thr=8, gap=2, top=5):
    if not cap.di or cap.legacy_di:
        return
    ci = 1 if axis == "x" else 2
    v = [r[ci] for r in cap.di]
    n = len(v)
    ev = []
    i = 0
    while i < n:
        if abs(v[i]) >= thr:
            j = last = i
            while j < n and (abs(v[j]) >= thr or j - last <= gap):
                if abs(v[j]) >= thr:
                    last = j
                j += 1
            ev.append((i, last))
            i = last + 1
        else:
            i += 1
    if not ev:
        return
    stats = []
    for a, b in ev:
        seg = v[a:b + 1]
        tot = sum(seg)
        sa = sum(abs(x) for x in seg)
        opp = sum(abs(x) for x in seg if x * tot < 0)
        tail = v[b + 1:b + 9]
        tail_opp = sum(abs(x) for x in tail if x * tot < 0)
        stats.append((sa, a, b, tot, max(abs(x) for x in seg), opp / sa if sa else 0.0, tail_opp / sa if sa else 0.0))
    stats.sort(reverse=True)
    big = [s_ for s_ in stats if s_[4] >= 60]
    out("  [G] ось %s: событий |dx|>=%d: %d; из них с пиком >=60 отсчётов/кадр (>=~2 порогов клэмпа): %d" % (axis, thr, len(ev), len(big)))
    out("      топ-%d по сумме: кадры a..b | длит. | Σdx | пик | обратный знак внутри | обратный знак в 8 кадрах хвоста (доля от Σ|dx|)" % top)
    for sa, a, b, tot, pk, opp, tail in stats[:top]:
        out("        %5d..%-5d | %2d | %7.0f | %4.0f | %5.1f%% | %5.1f%%" % (a, b, b - a + 1, tot, pk, 100 * opp, 100 * tail))


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
        block_f(cap, out)
        block_g(cap, out)
        block_h(cap, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
