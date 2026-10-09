#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_follow.py - разбор следящего слоя камеры по дампам v4.2+ (ds3probe_cap_NNN_dump.csv).

Что считает (по каждому захвату):
  [V1] закон слоя  x[t+1] = x[t] + a*dt*wrap(цель - x[t]) для yaw (+0x44) и pitch (+0x40) объекта-контроллера:
       подгонка a, невязка при a=7.5, число "снапов" (кадров, где слой точно встал в цель - признак работающего F4).
  [V2] отставание слоя от цели: медиана / p90 / максимум, доля кадров с ошибкой > 5 и > 100 градусов.
  [V3] привязка изменяющихся слов объекта-контроллера к углам: регрессия слова на {1, sin y cos p, cos y cos p, sin p}
       по следящим и по целевым углам; "орбита" = слово ложится на следящие углы заметно лучше, чем на целевые.
  [V4] (если есть пара) сравнение захватов "F4 вкл." и "F4 выкл.": дал ли F4 хоть какой-то эффект.
  [V5] (v4.5) эффективный вес смешивания за кадр w = (x[t+1]-x[t]) / wrap(цель[t]-x[t]) и коэффициенты ctrl+0x13C/0x140:
       оригинал w = (1-0.75)*ctrl[0x70] = 0.25*30*dt ~ 0.10; при F4 (v4.5) w ~ 1. Считается по кадрам, поэтому F4 можно
       переключать прямо внутри захвата: печатается сколько кадров с обходом и сколько с оригинальным сглаживанием.
  [V6] (v4.5, если в cfg есть трассировщик BlendOut = 0074DC6E, base=edx, dump 0 30) то, что реально уходит в SetTransform:
       yaw/pitch результата FUN_0073EF10 против цели того же кадра. Без обхода ошибка ~ (1-w)*отставание, с обходом ~ 0.
Цели берутся из дампа блока камеры (Trace4/Trace8, dump -20 300): pitch = слово блока +0x00,
yaw = atan2(слово +0x10, слово +0x18) - pi/2 (проверено на данных сессий 223501 и 234905).

Запуск:  python tools/analyze_follow.py <папка сессии> [--cap 1 [--cap 2]] [--pair 1 2]
"""
import argparse
import csv
import glob
import math
import os
import struct
import sys

ALPHA = 7.5


def wrap(a):
    return (a + math.pi) % (2 * math.pi) - math.pi


def hex_float(h):
    return struct.unpack("<f", struct.pack("<I", int(h, 16)))[0]


def read_meta_and_rows(path):
    meta, rows = [], []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                meta.append(line.rstrip("\n"))
                continue
            if line.startswith("t_ms"):
                continue
            p = line.rstrip("\n").split(",")
            if len(p) < 10:
                continue
            try:
                rows.append((float(p[0]), int(p[1]), [int(x, 16) for x in p[3:]]))
            except ValueError:
                continue
    return meta, rows


def meta_flag(meta, key):
    for m in meta:
        if m.startswith("# " + key + "="):
            return m.split("=", 1)[1].split()[0]
    return None


def load_capture(folder, cap):
    path = os.path.join(folder, "ds3probe_cap_%03d_dump.csv" % cap)
    meta, rows = read_meta_and_rows(path)
    by = {}
    for t, i, w in rows:
        by.setdefault(i, []).append((t, w))
    # id контроллера и камеры: по имени трассировщика в шапке
    ids = {}
    for m in meta:
        if m.startswith("# trace") and " name=" in m:
            n = int(m.split()[1][5:])
            ids[m.split("name=")[1].split()[0]] = n
    ctrl_id = ids.get("LookUpdate", 2)
    cam_id = ids.get("SetTransform", 4)
    blend_id = ids.get("BlendOut")
    return meta, by.get(ctrl_id, []), by.get(cam_id, []), (by.get(blend_id, []) if blend_id else [])


def series(ctrl, cam, block_word=8):
    n = min(len(ctrl), len(cam))
    t = [ctrl[i][0] for i in range(n)]
    fy = [hex_float("%x" % ctrl[i][1][17]) for i in range(n)]
    fp = [hex_float("%x" % ctrl[i][1][16]) for i in range(n)]
    ty, tp = [], []
    for i in range(n):
        w = cam[i][1]
        m12 = hex_float("%x" % w[block_word + 4])
        m14 = hex_float("%x" % w[block_word + 6])
        ty.append(wrap(math.atan2(m12, m14) - math.pi / 2))
        tp.append(hex_float("%x" % w[block_word]))
    return t, fy, fp, ty, tp, n


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(p / 100.0 * len(s)))] if s else float("nan")


def fit_alpha(x, tgt, dts):
    num = den = 0.0
    for i in range(1, len(x) - 2):
        d = wrap(tgt[i] - x[i])
        s = wrap(x[i + 1] - x[i])
        num += s * d
        den += d * d
    dt = sum(dts) / len(dts)
    return num / den / dt if den > 0 else float("nan")


def rms_model(x, tgt, dts, a=ALPHA):
    acc = 0.0
    n = 0
    for i in range(1, len(x) - 2):
        d = wrap(tgt[i] - x[i])
        r = wrap(x[i + 1] - x[i]) - a * dts[i] * d
        acc += r * r
        n += 1
    return math.degrees(math.sqrt(acc / max(n, 1)))


def lstsq3(A, y):
    """Нормальные уравнения 4x4 методом Гаусса; A - список строк по 4."""
    k = 4
    M = [[sum(r[i] * r[j] for r in A) for j in range(k)] + [sum(r[i] * v for r, v in zip(A, y))] for i in range(k)]
    for c in range(k):
        p = max(range(c, k), key=lambda r: abs(M[r][c]))
        M[c], M[p] = M[p], M[c]
        if abs(M[c][c]) < 1e-12:
            return None
        for r in range(k):
            if r != c:
                f = M[r][c] / M[c][c]
                for q in range(c, k + 1):
                    M[r][q] -= f * M[c][q]
    return [M[i][k] / M[i][i] for i in range(k)]


def reg_rms(words, yaw, pitch):
    A = [[1.0, math.sin(y) * math.cos(p), math.cos(y) * math.cos(p), math.sin(p)] for y, p in zip(yaw, pitch)]
    c = lstsq3(A, words)
    if c is None:
        return float("nan"), None
    r = sum((sum(a * b for a, b in zip(row, c)) - v) ** 2 for row, v in zip(A, words))
    return math.sqrt(r / len(words)), c


def analyze(folder, cap, out):
    meta, ctrl, cam, blend = load_capture(folder, cap)
    n0 = min(len(ctrl), len(cam))
    out.append("=== capture %03d: %d LookUpdate dumps, %d camera dumps, followfix=%s ===" % (cap, len(ctrl), len(cam), meta_flag(meta, "followfix")))
    for m in meta:
        if m.startswith("# roles") or m.startswith("# pointers") or m.startswith("# f4_stats"):
            out.append("  " + m[2:])
    if n0 < 50:
        out.append("  too few frames (need >= 50 dumps of both LookUpdate and SetTransform)")
        return None
    t, fy, fp, ty, tp, n = series(ctrl, cam)
    dts = [0.0] + [(t[i] - t[i - 1]) / 1000.0 for i in range(1, n)]
    dts_ok = [d if d > 0 else 0.0135 for d in dts]
    a_y, a_p = fit_alpha(fy, ty, dts_ok), fit_alpha(fp, tp, dts_ok)
    out.append("[V1] law  x+=a*dt*wrap(target-x): a(yaw)=%.2f a(pitch)=%.2f; rms residual at a=7.5: yaw %.3f deg, pitch %.3f deg"
               % (a_y, a_p, rms_model(fy, ty, dts), math.degrees(math.sqrt(sum((fp[i + 1] - fp[i] - ALPHA * dts[i] * (tp[i] - fp[i])) ** 2 for i in range(1, n - 2)) / max(n - 3, 1)))))
    err = [abs(math.degrees(wrap(ty[i] - fy[i]))) for i in range(n)]
    perr = [abs(math.degrees(tp[i] - fp[i])) for i in range(n)]
    snaps = sum(1 for i in range(1, n) if err[i] < 0.006 and err[i - 1] > 1.0)
    out.append("[V2] |yaw lag| deg: median %.2f p90 %.2f p99 %.2f max %.2f; frames >5deg: %d, >100deg: %d of %d; |pitch lag| p90 %.2f"
               % (pct(err, 50), pct(err, 90), pct(err, 99), max(err), sum(e > 5 for e in err), sum(e > 100 for e in err), n, pct(perr, 90)))
    out.append("     snaps to target (|err|<0.006 deg right after >1 deg): %d  <- F4 working shows many snaps, F4 not working shows 0" % snaps)
    # V3: слова контроллера
    words = list(range(len(ctrl[0][1])))
    hits = []
    for k in words:
        col = [ctrl[i][1][k] for i in range(n)]
        if len(set(col)) < 20 or k * 4 in (0x40, 0x44):
            continue
        v = [hex_float("%x" % c) for c in col]
        if not all(math.isfinite(x) and abs(x) < 1e7 for x in v):
            continue
        rf, _ = reg_rms(v, fy, fp)
        rt, _ = reg_rms(v, ty, tp)
        hits.append((k * 4, rf, rt, max(v) - min(v)))
    out.append("[V3] words of the controller object vs angles (rms of fit 1,sin y cos p,cos y cos p,sin p):")
    for off, rf, rt, rng in hits:
        tag = "ORBIT (follows the lagging angles)" if rf < 0.2 * rt and rf < 0.05 * max(rng, 1e-9) + 1e-3 else ""
        out.append("     +0x%02X range %.4g  rms(follower)=%.4g  rms(target)=%.4g  %s" % (off, rng, rf, rt, tag))
    # V5: эффективный вес смешивания по кадрам
    dt30 = [hex_float("%x" % ctrl[i][1][28]) for i in range(n)]            # ctrl+0x70 = 30*dt
    f13 = [hex_float("%x" % ctrl[i][1][79]) for i in range(n)]             # ctrl+0x13C
    f14 = [hex_float("%x" % ctrl[i][1][80]) for i in range(n)]             # ctrl+0x140
    weff, byp, orig, snap_n, big_n = [], 0, 0, 0, 0
    for i in range(n - 1):
        d = wrap(ty[i] - fy[i])
        if abs(math.degrees(d)) < 0.5:
            continue
        big_n += 1
        w = wrap(fy[i + 1] - fy[i]) / d
        weff.append(w)
        if w > 0.5:
            byp += 1
        elif w < 0.3:
            orig += 1
        if abs(math.degrees(wrap(fy[i + 1] - ty[i]))) < 0.01:
            snap_n += 1
    if weff:
        out.append("[V5] blend weight per frame (frames with |target-x| > 0.5 deg: %d): median w=%.4f p10=%.4f p90=%.4f | w>0.5 (bypass) in %d frames, w<0.3 (original ~%.3f) in %d | x[t+1]==target[t] (<0.01 deg): %d"
                   % (big_n, pct(weff, 50), pct(weff, 10), pct(weff, 90), byp, 0.25 * pct(dt30, 50), orig, snap_n))
    out.append("     ctrl+0x13C: min %.3f median %.3f max %.3f; ctrl+0x140 median %.3f; ctrl+0x70 (30*dt) median %.3f  <- original 0.75/0.75; bypass writes 1-w/dt30 (negative)"
               % (min(f13), pct(f13, 50), max(f13), pct(f14, 50), pct(dt30, 50)))
    # V6: то, что уходит в SetTransform
    bres = None
    if len(blend) >= 50:
        m = min(len(blend), n)
        by_, bp_, tby, tbp = [], [], [], []
        for i in range(m):
            w = blend[i][1]
            r0x, r0z, r2y = hex_float("%x" % w[0]), hex_float("%x" % w[2]), hex_float("%x" % w[9])
            by_.append(wrap(math.atan2(r0x, r0z) - math.pi / 2))
            bp_.append(math.asin(max(-1.0, min(1.0, -r2y))))
        ey = [abs(math.degrees(wrap(by_[i] - ty[i]))) for i in range(m)]
        ep = [abs(math.degrees(bp_[i] - tp[i])) for i in range(m)]
        el = [abs(math.degrees(wrap(by_[i] - fy[i]))) for i in range(m)]
        bres = {"p90": pct(ey, 90), "max": max(ey)}
        out.append("[V6] SetTransform argument (BlendOut, %d frames) vs target of the same frame: |yaw err| median %.3f p90 %.3f max %.3f deg; |pitch err| p90 %.3f deg; moved from the lagging x by median %.3f p90 %.3f deg"
                   % (m, pct(ey, 50), pct(ey, 90), max(ey), pct(ep, 90), pct(el, 50), pct(el, 90)))
        out.append("     (original smoothing: error ~ 0.9*lag, p90 of the lag above; bypass: error ~ 0 => the displayed orientation is no longer delayed)")
    return {"snaps": snaps, "p90": pct(err, 90), "med": pct(err, 50), "a_y": a_y, "bypass": byp, "big": big_n, "blend": bres}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("--cap", type=int, action="append", help="номер захвата (можно несколько); по умолчанию все")
    ap.add_argument("--pair", type=int, nargs=2, metavar=("F4_ON", "F4_OFF"), help="сравнить два захвата")
    a = ap.parse_args(argv)
    caps = a.cap or sorted(int(os.path.basename(p).split("_")[2]) for p in glob.glob(os.path.join(a.folder, "ds3probe_cap_*_dump.csv")))
    if a.pair:
        caps = list(a.pair)
    out = []
    res = {}
    for c in caps:
        try:
            res[c] = analyze(a.folder, c, out)
        except FileNotFoundError:
            out.append("capture %03d: no _dump.csv" % c)
    if a.pair and all(res.get(c) for c in a.pair):
        on, off = res[a.pair[0]], res[a.pair[1]]
        verdict = "F4 HAD EFFECT" if on["snaps"] > 10 or on["bypass"] > 10 or on["p90"] < 0.5 * off["p90"] else "F4 had NO effect on the follower (lag/snaps unchanged)"
        out.append("[V4] pair: F4 on  -> median %.2f p90 %.2f snaps %d | F4 off -> median %.2f p90 %.2f snaps %d  => %s"
                   % (on["med"], on["p90"], on["snaps"], off["med"], off["p90"], off["snaps"], verdict))
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
