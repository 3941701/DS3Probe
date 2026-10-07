#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Самопроверка analyze_samples.py на синтетических захватах: каждый сценарий известной природы
(полка, линейность, нелинейность InputMapper, режимы RAW/ZERO) должен давать ожидаемый вердикт.
Запуск:  python tests/test_analyze.py        (код возврата 0 = всё сошлось)
"""
import argparse
import io
import math
import os
import random
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import analyze_samples as an  # noqa: E402

HEADER = "t_ms,raw_dx,raw_dy,game_dx,game_dy,mode,out_dx,out_dy,look_x,look_y,sens,cap,rc"


def bursts_profile(dt, fps_seed, slow_amp, fast_amp, fast_ms, n_each=8, seed=1):
    """Список покадровых raw-дельт: n_each медленных и n_each резких движений с паузами 400 мс."""
    rnd = random.Random(seed)
    frames = []
    pause = int(400 / dt)
    for i in range(n_each * 2):
        fast = (i % 2 == 1)
        amp = (fast_amp if fast else slow_amp) * rnd.uniform(0.9, 1.1)
        dur_ms = fast_ms if fast else 700
        n = max(2, int(round(dur_ms / dt)))
        w = [math.sin(math.pi * (k + 0.5) / n) for k in range(n)]
        s = sum(w)
        carry = 0.0
        for k in range(n):
            v = amp * w[k] / s + carry
            iv = int(round(v))
            carry = v - iv
            frames.append(iv)
        frames += [0] * pause
    return frames


def write_csv(rows, half, path):
    with open(path, "w", newline="") as f:
        f.write("# ds3probe v3 sha=test capture=1\n# client=%dx%d half=%d,%d\n# pairing=wm_mousemove mapper=ok mode_at_start=PASS rawscale=1.0000\n"
                "# conditions: synthetic\n" % ((half + 1) * 2, 1080, half, 539))
        f.write(HEADER + "\n")
        for r in rows:
            f.write(r + "\n")


def scenario(kind, half=959, fps=60.0, sens=1.0, k=0.01):
    dt = 1000.0 / fps
    if kind == "saturation":
        raw = bursts_profile(dt, 1, 300, 4000, 100)
    else:
        raw = bursts_profile(dt, 1, 300, 1500, 250)
    rows = []
    out_prev = 0.0
    t = 0.0
    segs = [("PASS", raw)]
    if kind == "modes":
        segs = [("PASS", raw), ("RAW", raw), ("ZERO", raw)]
    outs = []
    for mode, seq in segs:
        for rx in seq:
            gx = rx
            if kind == "saturation":
                gx = max(-half, min(half, rx))
            if mode == "PASS":
                ox, m = gx, 0
            elif mode == "RAW":
                ox, m = int(rx * 0.9), 1
            else:
                ox, m = 0, 2
            outs.append((t, rx, gx, ox, m))
            t += dt
    # look в строке n+1 = результат out строки n (запаздывание на кадр)
    prev_look = 0.0
    for t, rx, gx, ox, m in outs:
        if kind == "mapper_nonlinear":
            look_next = (ox * sens * k) / (1.0 + abs(ox) / 120.0)
        else:
            look_next = ox * sens * k
        rows.append("%.3f,%d,0,%d,0,%d,%d,0,%.5f,0,%.5f,1,0" % (t, rx, gx, m, ox, prev_look, sens))
        prev_look = look_next
    return rows


def run(kind, **kw):
    half = kw.get("half", 959)
    rows = scenario(kind, **kw)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "cap.csv")
        write_csv(rows, half, p)
        loaded, meta = an.load_csv(p)
        assert len(loaded) == len(rows), "CSV round-trip lost rows"
        a = argparse.Namespace(gap=120.0, min_path=30.0, half_width=0, half_height=0, dpi=0)
        buf = io.StringIO()
        res = an.analyze(loaded, an.parse_meta(meta), a, out=lambda s: buf.write(s + "\n"))
    return res, buf.getvalue()


def check(name, cond, text=""):
    print(("ok   " if cond else "FAIL ") + name)
    if not cond:
        print(text)
    return cond


def main():
    ok = True
    res, txt = run("saturation", fps=30.0)
    ok &= check("saturation @30FPS -> l1=SATURATION", res["l1"] == "SATURATION", txt)
    res, txt = run("linear", fps=60.0)
    ok &= check("linear -> l1=LINEAR, l2=LINEAR", res["l1"] == "LINEAR" and res["l2"] == "LINEAR", txt)
    res, txt = run("mapper_nonlinear", fps=60.0)
    ok &= check("nonlinear mapper -> l1=LINEAR, l2=NONLINEAR", res["l1"] == "LINEAR" and res["l2"] == "NONLINEAR", txt)
    res, txt = run("modes", fps=60.0)
    ok &= check("modes -> zero=ACC_ONLY, raw=OK", res["zero"] == "ACC_ONLY" and res["raw"] == "OK", txt)
    # пустой и старый 5-колоночный CSV не должны падать
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "old.csv")
        with open(p, "w") as f:
            f.write("t_ms,raw_dx,raw_dy,game_dx,game_dy\n1.0,5,0,5,0\n2.0,0,0,0,0\n")
        rows, meta = an.load_csv(p)
        a = argparse.Namespace(gap=120.0, min_path=30.0, half_width=0, half_height=0, dpi=0)
        res = an.analyze(rows, an.parse_meta(meta), a, out=lambda s: None)
        ok &= check("old 5-column csv / too few frames -> NO DATA without crash", res["l1"] == "NO DATA")
    print("ALL OK" if ok else "SOME TESTS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
