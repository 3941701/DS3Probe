#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Самопроверка tools/analyze_follow.py на синтетическом дампе: следящий слой x += 7.5*dt*wrap(цель-x),
положение объекта на орбите вокруг следящих углов. Сценарии: слой работает (F4 выкл.) и слой "снапится" в цель (F4 работает).
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
    hdr = ["# ds3probe v4.4 sha=test capture=%d" % cap,
           "# trace2 name=LookUpdate addr=0073F310 args=2 this_dwords=0 base=ecx fields= dump=0,300 dumpfrom=0",
           "# trace4 name=SetTransform addr=0073CEB0 args=4 this_dwords=4 base=ecx fields= dump=-20,300 dumpfrom=8",
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
        # положение на орбите по ЛЕТЯЩИМ (следящим) углам
        w[8] = fh(122.0 - 3.0 * math.sin(x_y) * math.cos(x_p))
        w[9] = fh(322.0 + 2.2 * math.sin(x_p))
        w[10] = fh(-285.0 - 3.0 * math.cos(x_y) * math.cos(x_p))
        cam = ["00000000"] * 192
        cam[8] = fh(pit_t)
        # слово блока +0x10 / +0x18: atan2(m12, m14) - pi/2 = yaw_t  =>  m12 = sin(yaw_t + pi/2), m14 = cos(yaw_t + pi/2)
        cam[12] = fh(math.sin(yaw_t + math.pi / 2)); cam[14] = fh(math.cos(yaw_t + math.pi / 2))
        t = i * dt * 1000.0
        rows.append("%.3f,2,00000000,%s" % (t, ",".join(w)))
        rows.append("%.3f,4,00000000,%s" % (t + 0.1, ",".join(cam)))
        # обновление слоя в конце кадра
        x_y = af.wrap(x_y + 7.5 * dt * af.wrap(yaw_t - x_y))
        x_p = x_p + 7.5 * dt * (pit_t - x_p)
        if snap:
            x_y, x_p = yaw_t, pit_t
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
