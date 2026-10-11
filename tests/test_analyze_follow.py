#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Самопроверка tools/analyze_follow.py на синтетическом дампе: следящий слой x += 7.5*dt*wrap(цель-x),
положение объекта на орбите вокруг следящих углов. Сценарии: слой работает (F4 выкл.) и слой "снапится" в цель (F4 работает,
вес смешивания 1, v4.5). Проверяются V1..V6: закон, орбита, вердикт пары, эффективный вес за кадр, аргумент SetTransform (BlendOut).
Запуск:  python tests/test_analyze_follow.py   (код возврата 0 = всё сошлось)
"""
import io
import math
import os
import random
import struct
import sys
import tempfile
import contextlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import analyze_follow as af  # noqa: E402


def fh(f):
    return "%08X" % struct.unpack("<I", struct.pack("<f", f))[0]


def make_capture(folder, cap, snap, n=600, seed=3):
    rnd = random.Random(seed)
    dt = 0.0135
    yaw_t, pit_t, x_y, x_p = 0.3, 0.1, 0.3, 0.1
    hdr = ["# ds3probe v4.5 sha=test capture=%d" % cap,
           "# trace2 name=LookUpdate addr=0073F310 args=2 this_dwords=0 base=ecx fields= dump=0,300 dumpfrom=0",
           "# trace4 name=SetTransform addr=0073CEB0 args=4 this_dwords=4 base=ecx fields= dump=-20,300 dumpfrom=8",
           "# trace6 name=BlendOut addr=0074DC6E args=0 this_dwords=0 base=edx fields= dump=0,30 dumpfrom=0",
           "# followfix=%d" % (1 if snap else 0), "t_ms,id,ptr,words..."]
    rows = []
    vel = 0.0
    for i in range(n):
        if i % 80 == 10:
            vel = rnd.choice([-1, 1]) * rnd.uniform(1.0, 2.5)
        if i % 80 == 25:
            vel = 0.0
        yaw_t = af.wrap(yaw_t + vel * dt)
        pit_t = max(-0.7, min(0.7, pit_t + 0.01 * math.sin(i / 20.0)))
        ctrl = [0] * 192
        w = ["00000000"] * 192
        w[16] = fh(x_p); w[17] = fh(x_y)
        w[28] = fh(0.405)                                   # ctrl+0x70 = 30*dt
        w[79] = w[80] = fh(1.0 - 1.0 / 0.405 if snap else 0.75)   # ctrl+0x13C / 0x140
        # положение на орбите по ЛЕТЯЩИМ (следящим) углам
        w[8] = fh(122.0 - 3.0 * math.sin(x_y) * math.cos(x_p))
        w[9] = fh(322.0 + 2.2 * math.sin(x_p))
        w[10] = fh(-285.0 - 3.0 * math.cos(x_y) * math.cos(x_p))
        cam = ["00000000"] * 192
        cam[8] = fh(pit_t)
        # слово блока +0x10 / +0x18: atan2(m12, m14) - pi/2 = yaw_t  =>  m12 = sin(yaw_t + pi/2), m14 = cos(yaw_t + pi/2)
        cam[12] = fh(math.sin(yaw_t + math.pi / 2)); cam[14] = fh(math.cos(yaw_t + math.pi / 2))
        t = i * dt * 1000.0
        wt = 1.0 if snap else 0.25 * 0.405
        b_y = af.wrap(x_y + wt * af.wrap(yaw_t - x_y))
        b_p = x_p + wt * (pit_t - x_p)
        blend = ["00000000"] * 12
        blend[0] = fh(math.sin(b_y + math.pi / 2)); blend[2] = fh(math.cos(b_y + math.pi / 2)); blend[9] = fh(-math.sin(b_p))
        rows.append("%.3f,2,00000000,%s" % (t, ",".join(w)))
        rows.append("%.3f,4,00000000,%s" % (t + 0.1, ",".join(cam)))
        rows.append("%.3f,6,00000000,%s" % (t + 0.2, ",".join(blend)))
        # обновление слоя в конце кадра (v4.5: вес смешивания 1 при F4, иначе 0.25*30*dt = 7.5*dt)
        x_y, x_p = b_y, b_p
    with open(os.path.join(folder, "ds3probe_cap_%03d_dump.csv" % cap), "w") as f:
        f.write("\n".join(hdr + rows) + "\n")


def run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        af.main(argv)
    return buf.getvalue()


def main():
    ok = True
    with tempfile.TemporaryDirectory() as d:
        make_capture(d, 1, snap=True)
        make_capture(d, 2, snap=False)
        out = run([d, "--pair", "1", "2"])
        checks = [
            ("law a~7.5 in the working capture", "a(yaw)=7.50" in out),
            ("orbit detected on controller words", "ORBIT" in out),
            ("pair verdict: F4 had effect", "F4 HAD EFFECT" in out),
            ("V5: bypass frames found in the F4 capture", "[V5]" in out and "w>0.5 (bypass) in 0 frames" not in out.split("=== capture 002")[0]),
            ("V5: no bypass frames in the plain capture", "w>0.5 (bypass) in 0 frames" in out.split("=== capture 002")[1]),
            ("V6: SetTransform argument matches the target with F4", "[V6]" in out and "|yaw err| median 0.000" in out.split("=== capture 002")[0]),
        ]
        out2 = run([d, "--pair", "2", "2"])
        checks.append(("pair verdict: no effect when both captures are the same", "NO effect" in out2))
        for name, res in checks:
            print(("OK   " if res else "FAIL ") + name)
            ok = ok and res
        if not ok:
            print(out)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
