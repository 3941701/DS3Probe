#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_gain.py - усиление камеры по осям (k, рад/с на единицу выхода сглаживателя) и разгон прицела M по записи v4.7+.

Что нужно в записи: трассировщик ApplyRotDelta (addr=00721BD0) с аргументами (Trace.args >= 2; в play-cfg args = 0, тогда
k не посчитать - так и будет написано) и колонка caller_hex в _sticks.csv (v4.1+).

Как считается: каждая строка ApplyRotDelta с известным адресом возврата сопоставляется с последним вызовом сглаживателя
от "своего" вызывающего, не дальше 30 мс назад (на реальных записях разрыв 0.001-0.08 мс, вызов идёт в том же кадре):
    режим                 вызывающий  возврат ApplyRotDelta    pitch            yaw
    земля / поверхность   0073F407    0073FA14                 a0/(y_out*dt)    -a1/(x_out*dt)
    невесомость           0054F806    0054FCC6                 a0/(y_out*dt)    -a1/(x_out*dt)
    прицел                00549F2E    00552176, 00552222       a0/(y_out*dt)    -a1/(x_out*dt) (только 00552176)
Нормы при ползунке 50 (раздел 5.1 среза): земля yaw 3.940, pitch 1.833; магнитная поверхность pitch 1.309; невесомость
1.8326 по обеим осям; прицел yaw 1.745*M_y (M_y 1..2), pitch 1.396*M_p (M_p 1..4).

x_out/y_out в CSV записаны ПОСЛЕ множителей DS3Probe (ZeroGYaw/ZeroGPitch для невесомости, LookPitch для вертикали обычной
камеры), поэтому "k игры" - собственная константа игры, а "k итог" = k игры * множитель - то, что получает игрок на единицу
выхода сглаживателя до множителя. Аргументы прицела в CSV - значения игры ДО подмены AimLinear (камера получает M = 1).

Запуск:  python tools/analyze_gain.py <папка сессии> [--cap N] [--min-out 0.05]
  --min-out: кадры с меньшим |выходом| по оси не идут в k обычной камеры и полёта; M прицела считается по всем кадрам с |выход| >= 1e-4.
"""
import argparse
import bisect
import glob
import math
import os
import re
import struct
import sys

APPLY_ADDR = "00721BD0"
MAX_GAP_MS = 30.0
AIM_BASE_YAW = math.radians(100.0)    # 1.745329
AIM_BASE_PITCH = math.radians(80.0)   # 1.396263
AIM_MIN_OUT = 1e-4
M_BINS = (1.05, 1.5, 2.0, 3.0, 4.05)  # те же корзины, что в строке "AimLinear gain histogram" лога

# режим: (вызывающий сглаживатель, {возврат: (считать pitch, считать yaw)})
MODES = (
    ("земля/поверхность", "0073F407", {"0073FA14": (True, True)}),
    ("невесомость", "0054F806", {"0054FCC6": (True, True)}),
    ("прицел", "00549F2E", {"00552176": (True, True), "00552222": (True, False)}),
)

# известные значения k (рад/с на единицу), чтобы подписать кластеры
KNOWN = (
    (3.9401, "земля/поверхность yaw (3.5 град * 30 * 2.149)"),
    (1.8326, "земля pitch / невесомость (3.5 град * 30)"),
    (1.3090, "магнитная поверхность pitch (2.5 град * 30)"),
)


def wrap(a):
    return (a + math.pi) % (2 * math.pi) - math.pi


def hex_float(h):
    return struct.unpack("<f", struct.pack("<I", int(h, 16) & 0xFFFFFFFF))[0]


def read_csv(path):
    """Возвращает (строки мета '#', заголовок, список строк-словарей)."""
    meta, head, rows = [], None, []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line.startswith("#"):
                meta.append(line)
                continue
            p = line.split(",")
            if head is None:
                if p and p[0] == "t_ms":
                    head = p
                continue
            if len(p) < len(head):
                continue
            rows.append(dict(zip(head, p)))
    return meta, head or [], rows


def parse_meta(meta):
    info = {"apply_id": None, "apply_args": None, "zerog": (1.0, 1.0), "lookpitch": 1.0, "lookpitch_changes": [], "version": ""}
    for m in meta:
        mv = re.match(r"# ds3probe (\S+)", m)
        if mv:
            info["version"] = mv.group(1)
        mt = re.match(r"# trace(\d+) name=\S* addr=([0-9A-Fa-f]{8}) args=(\d+)", m)
        if mt and mt.group(2).upper() == APPLY_ADDR:
            info["apply_id"] = mt.group(1)
            info["apply_args"] = int(mt.group(3))
        mz = re.match(r"# zerog_scale yaw=([-0-9.eE+]+) pitch=([-0-9.eE+]+)", m)
        if mz:
            info["zerog"] = (float(mz.group(1)), float(mz.group(2)))
        ml = re.match(r"# lookpitch=([-0-9.eE+]+)", m)
        if ml:
            info["lookpitch"] = float(ml.group(1))
        if m.startswith("# lookpitch_changes"):   # v4.10: смены F2 внутри захвата, "мс=значение"
            info["lookpitch_changes"] = sorted((float(a), float(b)) for a, b in re.findall(r"([0-9.]+)=([0-9.eE+-]+)", m.split(":", 1)[-1]))
    return info


def scale_at(start, changes, t):
    """Множитель в момент t: значение в начале захвата, затем последняя смена F2 не позже t."""
    v = start
    for tc, vc in changes:
        if tc <= t:
            v = vc
        else:
            break
    return v


def pct(sorted_vals, q):
    if not sorted_vals:
        return float("nan")
    i = min(len(sorted_vals) - 1, max(0, int(round(q * (len(sorted_vals) - 1)))))
    return sorted_vals[i]


def summary(vals):
    v = sorted(vals)
    return "n=%5d  медиана %.4f  p5 %.4f  p95 %.4f  мин %.4f  макс %.4f" % (len(v), pct(v, 0.5), pct(v, 0.05), pct(v, 0.95), v[0], v[-1])


def clusters(vals, top=3):
    """Самые частые значения (округление до 0.001) с подписью, если похоже на известное."""
    cnt = {}
    for x in vals:
        key = round(x, 3)
        cnt[key] = cnt.get(key, 0) + 1
    out = []
    for key, n in sorted(cnt.items(), key=lambda kv: -kv[1])[:top]:
        label = ""
        for ref, name in KNOWN:
            if abs(key - ref) < 0.002:
                label = " = " + name
        out.append("%.3f x%d%s" % (key, n, label))
    return ", ".join(out)


def m_hist(ms):
    counts = [0] * (len(M_BINS) + 1)
    for m in ms:
        i = 0
        while i < len(M_BINS) and m > M_BINS[i] + 1e-3:   # допуск: M = 2.0000002 из float считаем "<=2"
            i += 1
        counts[i] += 1
    names = ["<=%g" % b for b in M_BINS] + [">%g" % M_BINS[-1]]
    return " ".join("%s:%d" % (n, c) for n, c in zip(names, counts))


def sens_from_log(folder):
    path = os.path.join(folder, "ds3probe.log")
    vals = []
    if not os.path.isfile(path):
        return vals
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.search(r"sens@\+17C=([-0-9.]+)", line)
            if m:
                v = float(m.group(1))
                if v not in vals:
                    vals.append(v)
    return vals


def analyze_capture(folder, cap, min_out, out):
    pre = os.path.join(folder, "ds3probe_cap_%03d" % cap)
    sticks_p, trace_p = pre + "_sticks.csv", pre + "_trace.csv"
    out.write("\n=== захват %d ===\n" % cap)
    if not os.path.isfile(sticks_p) or not os.path.isfile(trace_p):
        out.write("  нет %s или %s\n" % (os.path.basename(sticks_p), os.path.basename(trace_p)))
        return None
    meta, thead, trows = read_csv(trace_p)
    _, shead, srows = read_csv(sticks_p)
    info = parse_meta(meta)
    out.write("  версия %s; LookPitch %g; ZeroGYaw %g, ZeroGPitch %g (из шапки)\n" % (info["version"] or "?", info["lookpitch"], info["zerog"][0], info["zerog"][1]))
    if "caller_hex" not in shead:
        out.write("  в _sticks.csv нет caller_hex (запись старше v4.1): режимы не различить\n")
        return None
    if info["apply_id"] is None:
        out.write("  в cfg нет трассировщика ApplyRotDelta (addr=%s): k не посчитать\n" % APPLY_ADDR)
        return None
    if (info["apply_args"] or 0) < 2:
        out.write("  ApplyRotDelta записан без аргументов (Trace%s.args = %s): k не посчитать. Для замера поставь Trace%s.args = 2 или больше.\n"
                  % (info["apply_id"], info["apply_args"], info["apply_id"]))
        return None

    by_caller = {}
    for r in srows:
        try:
            by_caller.setdefault(r["caller_hex"].upper(), []).append((float(r["t_ms"]), float(r["dt"]), float(r["x_out"]), float(r["y_out"])))
        except (KeyError, ValueError):
            continue
    for v in by_caller.values():
        v.sort()

    result = {}
    for mode, caller, rets in MODES:
        st = by_caller.get(caller, [])
        ts = [s[0] for s in st]
        kp, ky, t_first, t_last, paired, unpaired = [], [], None, None, 0, 0
        kp_scale = []   # множитель вертикали DS3Probe в кадре каждого значения kp
        for r in trows:
            if r.get("id") != info["apply_id"]:
                continue
            ret = r.get("ret", "").upper()
            if ret not in rets:
                continue
            try:
                t = float(r["t_ms"])
                # шаг угла приходит и как "цель - старый угол" через границу +-pi (a1 = -0.03 + 2*pi): сводим в (-pi, pi]
                a0, a1 = wrap(hex_float(r["a0"])), wrap(hex_float(r["a1"]))
            except (KeyError, ValueError):
                continue
            i = bisect.bisect_right(ts, t) - 1
            if i < 0 or t - ts[i] > MAX_GAP_MS:
                unpaired += 1
                continue
            paired += 1
            _, dt, x, y = st[i]
            if dt <= 0:
                continue
            t_first = t if t_first is None else t_first
            t_last = t
            want_p, want_y = rets[ret]
            # прицел: разгон копится и при почти нулевом выходе по оси (220909: M_p = 4.0 при y_out около 0), поэтому для M порог
            # почти нулевой - отношение точное, шума нет; для k обычной камеры и полёта порог --min-out
            lim = AIM_MIN_OUT if mode == "прицел" else min_out
            if want_p and abs(y) >= lim and math.isfinite(a0):
                kp.append(a0 / (y * dt))
                if mode == "невесомость":
                    kp_scale.append(info["zerog"][1])
                else:
                    kp_scale.append(scale_at(info["lookpitch"], info["lookpitch_changes"], t))
            if want_y and abs(x) >= lim and math.isfinite(a1):
                ky.append(-a1 / (x * dt))
        if not paired:
            continue
        out.write("\n  [%s] вызовов ApplyRotDelta %d (без пары %d), %.1f-%.1f с\n" % (mode, paired, unpaired, (t_first or 0) / 1000.0, (t_last or 0) / 1000.0))
        if mode == "прицел":
            for name, ks, base in (("yaw  ", ky, AIM_BASE_YAW), ("pitch", kp, AIM_BASE_PITCH)):
                if not ks:
                    out.write("    %s нет кадров с |выход| >= %g\n" % (name, AIM_MIN_OUT))
                    continue
                ms = [k / base for k in ks]
                out.write("    %s M = k/%.4f: %s\n" % (name, base, summary(ms)))
                out.write("          корзины M (все кадры, без фильтров): %s\n" % m_hist(ms))
            out.write("    (значения игры до подмены AimLinear; с AimLinear камера получает M = 1)\n")
            result[mode] = {"yaw": ky, "pitch": kp}
            continue
        scale_y = info["zerog"][0] if mode == "невесомость" else 1.0
        if not ky:
            out.write("    yaw   нет кадров с |выход| >= %g\n" % min_out)
        else:
            out.write("    yaw   k игры %s\n" % summary(ky))
            out.write("          частые значения: %s\n" % clusters(ky))
            if scale_y != 1.0:
                out.write("          k итог = медиана * множитель DS3Probe %g = %.4f\n" % (scale_y, pct(sorted(ky), 0.5) * scale_y))
        yaw_eff = pct(sorted(ky), 0.5) * scale_y if ky else None
        if not kp:
            out.write("    pitch нет кадров с |выход| >= %g\n" % min_out)
        else:
            out.write("    pitch k игры %s\n" % summary(kp))
            out.write("          частые значения: %s\n" % clusters(kp))
            # группы: собственное значение игры (земля 1.833 / поверхность 1.309 / ...) x множитель DS3Probe в этом кадре
            groups = {}
            for k, sc in zip(kp, kp_scale):
                groups.setdefault((round(k, 2), sc), []).append(k * sc)
            for (kg, sc), effs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
                if len(effs) < max(5, 0.02 * len(kp)):
                    continue
                med = pct(sorted(effs), 0.5)
                line = "          k игры около %.2f, множитель %g: n=%d, k итог %.4f" % (kg, sc, len(effs), med)
                if yaw_eff:
                    line += ", итог yaw/pitch = %.3f" % (yaw_eff / med)
                out.write(line + "\n")
            if info["lookpitch_changes"] and mode != "невесомость":
                out.write("          смены LookPitch (F2) в захвате: %s\n" % ", ".join("%.1f с -> %g" % (tc / 1000.0, vc) for tc, vc in info["lookpitch_changes"]))
        out.write("    (итог yaw/pitch = 1.0 - оси одинаковы на единицу выхода сглаживателя)\n")
        result[mode] = {"yaw": ky, "pitch": kp}
    if not result:
        out.write("  нет пар ApplyRotDelta - сглаживатель ни в одном известном режиме\n")
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description="Усиление камеры по осям и разгон прицела по записи DS3Probe")
    ap.add_argument("folder", help="папка сессии с ds3probe_cap_NNN_*.csv")
    ap.add_argument("--cap", type=int, action="append", help="номер захвата (по умолчанию все)")
    ap.add_argument("--min-out", type=float, default=0.05, help="минимальный |выход сглаживателя| для кадра (по умолчанию 0.05)")
    a = ap.parse_args(argv)
    out = sys.stdout
    caps = a.cap
    if not caps:
        caps = sorted({int(m.group(1)) for p in glob.glob(os.path.join(a.folder, "ds3probe_cap_*_sticks.csv"))
                       for m in [re.search(r"ds3probe_cap_(\d+)_sticks\.csv$", p)] if m})
    if not caps:
        out.write("в %s нет ds3probe_cap_NNN_sticks.csv\n" % a.folder)
        return 2
    sens = sens_from_log(a.folder)
    if sens:
        # ВЫВОД по коду меню: sens@+17C = ползунок/100 * 1.8 + 0.1 (50 -> 1.0); не проверено записью при другом положении ползунка
        out.write("sens@+17C из лога: %s (ползунок меню примерно %s)\n" % (
            ", ".join("%.4f" % s for s in sens), ", ".join("%.0f" % ((s - 0.1) / 1.8 * 100.0) for s in sens)))
    any_ok = False
    for c in caps:
        if analyze_capture(a.folder, c, a.min_out, out):
            any_ok = True
    return 0 if any_ok else 1


if __name__ == "__main__":
    sys.exit(main())
