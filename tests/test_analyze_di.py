#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Самопроверка analyze_di.py на синтетических захватах v4 (известная природа -> ожидаемый вердикт).
Сценарии:
  linear    стик = k * вход DI                      -> блок C: "пропорционален", блок D: DI-ZERO даёт нулевой выход
  plateau   стик = clamp(k * вход DI, +-C)          -> блок C: ПЛАТО/полка
  compress  стик = k * x / (1 + |x|/60)             -> блок C: сжатие
  notdi     стик питается не от DI (скрытый сигнал) -> блок D: пометка "стик питается не от DI"
  legacy    _di.csv формата v3                      -> блок B пропускается, без падения
  ladder    лестница клэмпа F11 (2/6/12/1e9)        -> блок H: 4 ступени, потолок реже на высоких ступенях, 0 на открытой
Запуск:  python tests/test_analyze_di.py     (код возврата 0 = всё сошлось)
"""
import contextlib
import io
import math
import os
import random
import re
import sys
import tempfile
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import analyze_di as ad  # noqa: E402

DT = 1000.0 / 75.0
MODES = [(0, 1.0), (1, 0.0), (2, 0.5), (4, 2.0), (0, 1.0)]   # (код режима, множитель) - по сегментам


def signal(n_per_seg, seed=7):
    """Покадровые дельты мыши: смесь медленных и резких движений с паузами."""
    rnd = random.Random(seed)
    out = []
    while len(out) < n_per_seg:
        fast = rnd.random() < 0.5
        amp = rnd.choice([400, 600, 800]) if fast else rnd.choice([60, 120, 200])
        n = rnd.randint(3, 6) if fast else rnd.randint(30, 50)
        w = [math.sin(math.pi * (k + 0.5) / n) for k in range(n)]
        s = sum(w)
        carry = 0.0
        for k in range(n):
            v = amp * w[k] / s + carry
            iv = int(round(v))
            carry = v - iv
            out.append(iv)
        out += [0] * rnd.randint(10, 25)
    return out[:n_per_seg]


def build(tmp, kind, with_stick=True, legacy=False):
    di_lines, acc_lines, sticks_lines = [], [], []
    t = 0.0
    hidden = signal(len(MODES) * 700, seed=99)
    idx = 0
    for mode, k in MODES:
        for g in signal(700, seed=3 + mode):
            ox = int(math.floor(g * k + 0.5))
            if legacy:
                di_lines.append("%.3f,%d,0,%d,0" % (t, g, g))
            else:
                di_lines.append("%.3f,%d,0,%d,0,%d,%d,0" % (t, g, g, mode, ox))
            acc_lines.append("%.3f,%d,0,%d,0,%d,%d,0,0,0,1,1,0" % (t, g, g, 0, g))
            x = float(ox)
            if kind == "linear":
                y = 0.01 * x
            elif kind == "plateau":
                y = max(-0.6, min(0.6, 0.01 * x))
            elif kind == "compress":
                y = 0.01 * x / (1.0 + abs(x) / 60.0)
            elif kind == "notdi":
                y = 0.01 * hidden[idx]
            else:
                raise ValueError(kind)
            sticks_lines.append("%.3f,0.0133,%.6f,0,%.6f,0,4,0.1,0,1e9,1,0,0,0,0,0,0,0,0,00ACB78A" % (t + 1.0, x, y))
            t += DT
            idx += 1
    d = tempfile.mkdtemp(prefix="ds3di_", dir=tmp)
    hdr = "# ds3probe v4 sha=test capture=1\n# raw_reference=DEAD\n"
    with open(os.path.join(d, "ds3probe_cap_001_di.csv"), "w") as f:
        f.write(hdr + ("t_ms,raw_dx,raw_dy,game_dx,game_dy\n" if legacy else "t_ms,raw_dx,raw_dy,game_dx,game_dy,mode,out_dx,out_dy\n"))
        f.write("\n".join(di_lines) + "\n")
    with open(os.path.join(d, "ds3probe_cap_001_acc.csv"), "w") as f:
        f.write(hdr + "t_ms,raw_dx,raw_dy,game_dx,game_dy,mode,out_dx,out_dy,look_x,look_y,sens,cap,rc\n" + "\n".join(acc_lines) + "\n")
    if with_stick:
        with open(os.path.join(d, "ds3probe_cap_001_sticks.csv"), "w") as f:
            f.write(hdr + "t_ms,dt,x_in,y_in,x_out,y_out,id,win,blend,clamp,active,w0,w1,w2,w3,w4,w5,w6,w7,ret_hex\n" + "\n".join(sticks_lines) + "\n")
    return d


def sim_rows(counts, clamps, win=1.0 / 30.0, blend=1.0, c30=30.0):
    """Симулятор FUN_0040D820 (формула из анализа 20261008): строки sticks_full для block_h/window_model."""
    cur = [0.0, 0.0, 0.0, 0]
    prev = [0.0, 0.0, 0.0, 0]
    rows = []
    t = 0.0
    for i, (cx, cl) in enumerate(zip(counts, clamps)):
        dt = 0.013 if i % 2 == 0 else 0.014
        if win <= dt + cur[2]:
            prev = cur[:]
            cur = [0.0, 0.0, 0.0, 0]
        cur[0] += 0.032 * cx / dt
        cur[2] += dt
        cur[3] += 1
        xc = cur[2] * (cur[0] / cur[3])
        if prev[3] > 0:
            xp = prev[2] * (prev[0] / prev[3])
            w = blend * cur[2] / (prev[2] + cur[2])
            xb = w * xc + (1 - w) * xp
            tb = w * cur[2] + (1 - w) * prev[2]
        else:
            xb, tb = xc, cur[2]
        o = max(-cl, min(cl, xb)) / (tb * c30)
        rows.append((t, dt, win, blend, cl, o, 0.0, [cur[0], 0.0, cur[2], 0.0, prev[0], 0.0, prev[2], 0.0], 0))
        t += dt * 1000.0
    return rows


def test_ladder():
    levels = [2.0, 6.0, 12.0, 1.0e9]
    counts, clamps = [], []
    for lv in levels:
        seg = signal(900, seed=11)
        counts += seg
        clamps += [lv] * len(seg)
    cap = types.SimpleNamespace(sticks_full=sim_rows(counts, clamps))
    lines = []
    ad.block_h(cap, lines.append)
    txt = "\n".join(lines)
    got = {}
    for l in lines:
        m = re.search(r"клэмп (\S+(?: \(1e9\))?)\s+кадров\s+(\d+).*макс\|вых\.x\|\s+([0-9.]+).*у потолка\s+(\d+)", l)
        if m:
            got[m.group(1)] = (int(m.group(2)), float(m.group(3)), int(m.group(4)))
    ok = len(got) == 4
    keys = list(got)
    if ok:
        mx = [got[k][1] for k in keys]
        ceil = [got[k][2] for k in keys]
        ok = (mx == sorted(mx) and mx[0] < mx[-1] and ceil[0] > ceil[1] >= ceil[2] and ceil[-1] == 0 and all(got[k][0] == 900 for k in keys))
    # одна ступень -> блок молчит
    cap1 = types.SimpleNamespace(sticks_full=sim_rows(counts[:900], clamps[:900]))
    lines1 = []
    ad.block_h(cap1, lines1.append)
    ok = ok and not lines1
    return expect("ladder", ok, txt + "\n" + repr(got))



def run(d):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = ad.main([d])
    return rc, buf.getvalue()


def expect(name, cond, text):
    print("%-10s %s" % (name, "OK" if cond else "FAIL"))
    if not cond:   # только ASCII: консоль CI на Windows может быть в cp1252
        print(text.encode("ascii", "replace").decode("ascii"))
    return cond


def main():
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        for kind in ("linear", "plateau", "compress", "notdi"):
            rc, txt = run(build(tmp, kind))
            c_line = [l for l in txt.splitlines() if "ВЕРДИКТ" in l]
            if kind == "linear":
                ok &= expect(kind, rc == 0 and any("пропорционален" in l for l in c_line) and "НЕ нулевой при обнулённом DI" not in txt, txt)
                ok &= expect(kind + "/B", "режим DI-xA" in txt and "out/game=0.5" in txt and "out/game=2.000" in txt, txt)
            elif kind == "plateau":
                ok &= expect(kind, any("ПЛАТО" in l for l in c_line), txt)
            elif kind == "compress":
                ok &= expect(kind, any("сжатие" in l for l in c_line), txt)
            else:
                ok &= expect(kind, "стик питается не от DI" in txt, txt)
        rc, txt = run(build(tmp, "linear", with_stick=False, legacy=True))
        ok &= expect("legacy", rc == 0 and "формата v3" in txt and "[A]" in txt, txt)
    ok &= test_ladder()
    print("TOTAL: %s" % ("ALL OK" if ok else "MISMATCH"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
