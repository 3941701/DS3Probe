#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Самопроверка tools/analyze_gain.py на синтетической записи: земля (yaw 3.940, pitch 1.833, LookPitch 2.15 в шапке, F2 на 1 с 2.1 с),
магнитная поверхность (pitch 1.309), невесомость (1.8326, ZeroGYaw 2.15), прицел с разгоном M (yaw до 2, pitch до 4),
шаг yaw через границу +-pi (a1 = шаг + 2*pi) и запись без аргументов ApplyRotDelta (Trace1.args = 0).
Запуск:  python tests/test_analyze_gain.py   (код возврата 0 = всё сошлось)
"""
import contextlib
import io
import math
import os
import random
import re
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import analyze_gain as ag  # noqa: E402

K_YAW, K_PITCH, K_SURF, K_FLY = 3.9401, 1.8326, 1.3090, 1.8326


def fh(f):
    return "%08X" % struct.unpack("<I", struct.pack("<f", f))[0]


def trace_row(t, ret, a0, a1, args):
    a = [fh(a0), fh(a1)] + ["00000000"] * 6
    return ",".join(["%.3f" % t, "1", "06B11BB0", "00000000", ret] + a[:8] + ["00000000"] * 16 + ["00000000", "06B11BB0"] + ["00000000"] * 16)


def stick_row(t, dt, x, y, caller):
    return ",".join(["%.3f" % t, "%.6f" % dt, "%.6f" % (x / 3), "%.6f" % (y / 3), "%.6f" % x, "%.6f" % y, "1", "0.033333", "1.0", "2.0", "1"]
                    + ["0.000000"] * 8 + ["00192001", caller])


def make_session(folder, args=6, seed=7):
    rnd = random.Random(seed)
    hdr = ["# ds3probe v4.10 sha=test capture=1",
           "# trace1 name=ApplyRotDelta addr=00721BD0 args=%d this_dwords=3 base=ecx fields=" % args,
           "# zerog_scale yaw=2.15 pitch=1 scaled_calls=10 (test)",
           "# lookpitch=2.15 scaled_calls=10 (test)",
           "# lookpitch_changes (F2; ms from capture start=new value): 2100.0=1"]
    sticks, trace = [], []
    t, dt = 0.0, 0.014
    my = mp = 1.0
    for i in range(1200):
        t += dt * 1000.0
        seg = i // 300   # 0 земля, 1 поверхность, 2 невесомость, 3 прицел
        x = rnd.uniform(-3, 3) if rnd.random() < 0.8 else 0.0
        y = rnd.uniform(-2, 2) if rnd.random() < 0.7 else 0.0
        if seg in (0, 1):
            sticks.append(stick_row(t, dt, x, y, "0073F407"))
            kp = K_PITCH if seg == 0 else K_SURF
            a1 = -K_YAW * x * dt
            if i % 97 == 5:
                a1 += 2 * math.pi   # шаг через границу +-pi, как в 220909
            trace.append(trace_row(t + 0.001, "0073FA14", kp * y * dt, a1, args))
        elif seg == 2:
            sticks.append(stick_row(t, dt, x, y, "0054F806"))
            trace.append(trace_row(t + 0.002, "0054FCC6", K_FLY * y * dt, -K_FLY * x * dt, args))
            trace.append(trace_row(t + 0.003, "00721DFA", 0.5, 0.5, args))   # чужой возврат: не должен попасть в счёт
        else:
            if i < 1000:
                x = 2.5   # долгая быстрая проводка: разгон доходит до потолков
            big = abs(x) > 1.0
            my = min(2.0, my + 0.05) if big else max(1.0, my - 0.05)
            mp = min(4.0, mp * 1.036) if big else max(1.0, mp * 0.945)
            sticks.append(stick_row(t, dt, x, y, "00549F2E"))
            trace.append(trace_row(t + 0.001, "00552176", mp * ag.AIM_BASE_PITCH * y * dt, -my * ag.AIM_BASE_YAW * x * dt, args))
            trace.append(trace_row(t + 0.002, "00552222", mp * ag.AIM_BASE_PITCH * y * dt, 0.0, args))
    with open(os.path.join(folder, "ds3probe_cap_001_sticks.csv"), "w") as f:
        f.write("\n".join(hdr + ["t_ms,dt,x_in,y_in,x_out,y_out,id,win,blend,clamp,active,w0,w1,w2,w3,w4,w5,w6,w7,ret_hex,caller_hex"] + sticks) + "\n")
    th = ["t_ms,id,ecx,edx,ret"] + ["a%d" % k for k in range(8)] + ["t%d" % k for k in range(16)] + ["eax", "base"] + ["f%d" % k for k in range(16)]
    with open(os.path.join(folder, "ds3probe_cap_001_trace.csv"), "w") as f:
        f.write("\n".join(hdr + [",".join(th)] + trace) + "\n")
    with open(os.path.join(folder, "ds3probe.log"), "w") as f:
        f.write("[    1.571] InputMapper #1: this=04884CB0 sens@+17C=0.5860 MouseState=058EC274 look=(0.0000,0.0000) wheel=0.0000\n")


def run(folder):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = ag.main([folder])
    return rc, buf.getvalue()


def section(text, name):
    m = re.search(r"\[" + re.escape(name) + r"\](.*?)(?=\n  \[|\Z)", text, re.S)
    return m.group(1) if m else ""


def medians(sec):
    return {ax: float(v) for ax, v in re.findall(r"(yaw|pitch)\s+(?:k игры|M = k/[0-9.]+:) n=\s*\d+\s+медиана ([0-9.]+)", sec)}


def main():
    fails = []

    def check(cond, msg):
        print(("ok    " if cond else "FAIL  ") + msg)
        if not cond:
            fails.append(msg)

    with tempfile.TemporaryDirectory() as d:
        make_session(d)
        rc, out = run(d)
        check(rc == 0, "код возврата 0 при записи с аргументами")
        check("ползунок меню примерно 27" in out, "sens@+17C 0.586 -> ползунок 27")
        g = section(out, "земля/поверхность")
        med = medians(g)
        check(abs(med.get("yaw", 0) - K_YAW) < 1e-3, "земля yaw k = 3.940 (шаг через +-pi сведён)")
        check("мин 3.94" in g.split("pitch")[0], "в yaw нет выбросов от шага через +-pi")
        check("1.833 x" in g and "1.309 x" in g, "pitch: оба кластера, земля 1.833 и поверхность 1.309")
        check(re.search(r"около 1\.83, множитель 2\.15: n=\d+, k итог 3\.940\d, итог yaw/pitch = 1\.000", g) is not None,
              "pitch: до смены F2 LookPitch 2.15 из шапки, оси равны")
        check(re.search(r"около 1\.83, множитель 1: n=\d+, k итог 1\.8326, итог yaw/pitch = 2\.150", g) is not None,
              "pitch: после смены F2 на 1 вертикаль в 2.15 раза медленнее")
        check(re.search(r"около 1\.31, множитель 1: n=\d+, k итог 1\.3090, итог yaw/pitch = 3\.010", g) is not None,
              "pitch: магнитная поверхность, итог yaw/pitch 3.01")
        check("2.1 с -> 1" in g, "pitch: смены F2 перечислены")
        z = section(out, "невесомость")
        medz = medians(z)
        check(abs(medz.get("yaw", 0) - K_FLY) < 1e-3 and abs(medz.get("pitch", 0) - K_FLY) < 1e-3, "невесомость k = 1.8326 по обеим осям, чужой возврат 00721DFA не учтён")
        check("= 3.9401" in z or "= 3.9400" in z, "невесомость: k итог yaw = 1.8326 * 2.15")
        a = section(out, "прицел")
        maxes = [float(v) for v in re.findall(r"макс ([0-9.]+)", a)]
        check(len(maxes) == 2 and abs(maxes[0] - 2.0) < 1e-3 and abs(maxes[1] - 4.0) < 1e-3, "прицел: максимум M yaw 2.0, pitch 4.0")
        check("<=4.05:" in a and not re.search(r">4.05:[1-9]", a), "прицел: корзины M, выше 4.05 пусто")
    with tempfile.TemporaryDirectory() as d:
        make_session(d, args=0)
        rc, out = run(d)
        check(rc == 1 and "Trace1.args = 2" in out, "запись без аргументов: подсказка про Trace1.args и код 1")

    print("\nИТОГ: %s" % ("всё сошлось" if not fails else "%d ошибок" % len(fails)))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
