#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_samples.py v3 - разбор ds3probe_cap_NNN_acc.csv (DS3Probe v3).

Колонки CSV (шапка из строк '# ...' пропускается, из неё берутся client=WxH и half=):
  t_ms, raw_dx, raw_dy  - Raw Input, спаренный с кадром (эталон: что сделала рука)
  game_dx, game_dy      - что игра накопила в аккумуляторе из позиции курсора Windows (ДО нашей подмены)
  mode                  - 0 PASS (игра как есть), 1 RAW (аккумулятор := raw*RawScale), 2 ZERO (аккумулятор := 0)
  out_dx, out_dy        - что игра получила на самом деле (в PASS = game)
  look_x, look_y, sens  - MouseState.lookX/Y и множитель, прочитанные при входе в InputMapper_Update
                          (то есть результат ПРЕДЫДУЩЕГО вызова: look идёт с запаздыванием на кадр; скрипт сам подбирает 0/1)
  cap, rc               - байты FlagCaptured / FlagRecenter (рабочие имена; 255 = не читались)

Что считается (каждый уровень отвечает на свой вопрос):
  Уровень 1  raw -> game   потеря ДО аккумулятора: упор в полку (половина клиентской области за кадр) или нелинейность по скорости
  Уровень 2  out -> look   линейность InputMapper_Update (множитель sens): падает ли look/out на больших входах
  Режимы     RAW / ZERO    подтверждение, что подмена сработала (out ~ raw*scale; в ZERO look ~ 0)
  Уровень 3  look -> камера в этом CSV не виден: если 1 и 2 линейны, а ощущение осталось - причина в потребителе MouseState.

Запуск:  python analyze_samples.py ds3probe_cap_001_acc.csv [ещё файлы] [--half-width 959 --half-height 539] [--dpi 800]
"""
import argparse
import csv
import math
import re
import statistics
import sys

NAN = float("nan")
MODE_NAMES = {0: "PASS", 1: "RAW", 2: "ZERO"}


class Row(object):
    __slots__ = ("t", "rx", "ry", "gx", "gy", "mode", "ox", "oy", "lx", "ly", "sens", "cap", "rc")


def _num(d, key, default=NAN):
    v = d.get(key)
    if v is None or v == "":
        return default
    try:
        return float(v)
    except ValueError:
        return default


def load_csv(path, t_off=0.0):
    meta, body = [], []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for line in f:
            (meta if line.startswith("#") else body).append(line)
    rows = []
    for d in csv.DictReader(body):
        r = Row()
        r.t = _num(d, "t_ms", 0.0) + t_off
        r.rx, r.ry = _num(d, "raw_dx", 0.0), _num(d, "raw_dy", 0.0)
        r.gx, r.gy = _num(d, "game_dx", 0.0), _num(d, "game_dy", 0.0)
        r.mode = int(_num(d, "mode", 0.0))
        r.ox, r.oy = _num(d, "out_dx", r.gx), _num(d, "out_dy", r.gy)
        r.lx, r.ly, r.sens = _num(d, "look_x"), _num(d, "look_y"), _num(d, "sens")
        r.cap, r.rc = _num(d, "cap", 255.0), _num(d, "rc", 255.0)
        rows.append(r)
    return rows, meta


def parse_meta(meta_lines):
    text = "\n".join(meta_lines)
    out = {"client": None, "half": None, "conditions": [], "pairing": None}
    m = re.search(r"client=(\d+)x(\d+)", text)
    if m:
        out["client"] = (int(m.group(1)), int(m.group(2)))
    m = re.search(r"half=(-?\d+),(-?\d+)", text)
    if m:
        out["half"] = (int(m.group(1)), int(m.group(2)))
    m = re.search(r"pairing=(\S+)", text)
    if m:
        out["pairing"] = m.group(1)
    for line in meta_lines:
        if "conditions:" in line:
            out["conditions"].append(line.split("conditions:", 1)[1].strip())
    return out


# ------------------------------------------------------------------ статистика
def median(v):
    v = [x for x in v if not math.isnan(x)]
    return statistics.median(v) if v else NAN


def percentile(v, p):
    v = sorted(x for x in v if not math.isnan(x))
    if not v:
        return NAN
    k = (len(v) - 1) * p / 100.0
    lo, hi = int(math.floor(k)), int(math.ceil(k))
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def ranks(v):
    order = sorted(range(len(v)), key=lambda i: v[i])
    r = [0.0] * len(v)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
            j += 1
        for k in range(i, j + 1):
            r[order[k]] = (i + j) / 2.0     # средние ранги: постоянный ratio не даёт ложный rho=1
        i = j + 1
    return r


def spearman(xs, ys):
    if len(xs) < 3:
        return 0.0
    rx, ry = ranks(xs), ranks(ys)
    mx, my = statistics.mean(rx), statistics.mean(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den if den else 0.0


def linfit(xs, ys):
    """МНК через ноль: y = k*x. Возвращает (k, R2 относительно нуля)."""
    sxx = sum(x * x for x in xs)
    if sxx == 0:
        return NAN, NAN
    k = sum(x * y for x, y in zip(xs, ys)) / sxx
    ss_res = sum((y - k * x) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum(y * y for y in ys)
    return k, (1.0 - ss_res / ss_tot) if ss_tot else NAN


# ------------------------------------------------------------------ уровень 1
def bin_edges(half):
    e = [0, 5, 15, 40, 100, 200, 400, 800, 1600]
    if half and half > 0:
        e = [x for x in e if x < half * 0.8] + [half]
        e = sorted(set(e))
    e.append(float("inf"))
    return e


def level1_axis(rows, axis, half):
    """Покадровая таблица |raw| -> |game| для одной оси. Возвращает (строки таблицы, найдена ли полка)."""
    rv = [abs(getattr(r, "r" + axis)) for r in rows]
    gv = [abs(getattr(r, "g" + axis)) for r in rows]
    edges = bin_edges(half)
    table = []
    for i in range(len(edges) - 1):
        lo, hi = edges[i], edges[i + 1]
        sel = [(a, b) for a, b in zip(rv, gv) if a > 0 and lo <= a < hi]
        if not sel:
            continue
        sr, sg = sum(a for a, _ in sel), sum(b for _, b in sel)
        table.append({"lo": lo, "hi": hi, "n": len(sel), "ratio": sg / sr if sr else NAN,
                      "p50": median([b for _, b in sel]), "max": max(b for _, b in sel)})
    ceiling = False
    detail = ""
    if half and half > 0:
        over = [(a, b) for a, b in zip(rv, gv) if a > half * 1.1]
        if len(over) >= 3:
            med_g = median([b for _, b in over])
            ratio = sum(b for _, b in over) / sum(a for a, _ in over)
            # полка: при raw выше половины клиента game застревает у половины клиента и сильно меньше raw
            if med_g <= half * 1.05 and ratio < 0.8:
                ceiling = True
            detail = "кадров с |raw| > half: %d, медиана |game| там: %.0f (half=%d), ratio=%.2f" % (len(over), med_g, half, ratio)
        else:
            detail = "кадров с |raw| > half мало (%d): полка не проверяема, нужны более резкие движения" % len(over)
    return table, ceiling, detail


def split_segments(rows):
    """Куски подряд идущих кадров с одним режимом."""
    seg, out = [], []
    for r in rows:
        if seg and r.mode != seg[-1].mode:
            out.append(seg)
            seg = []
        seg.append(r)
    if seg:
        out.append(seg)
    return out


def split_bursts(rows, gap_ms):
    bursts, cur, last_t = [], [], None
    for r in rows:
        active = r.rx != 0 or r.ry != 0 or r.gx != 0 or r.gy != 0
        if not active:
            continue
        if cur and r.t - last_t > gap_ms:
            bursts.append(cur)
            cur = []
        cur.append(r)
        last_t = r.t
    if cur:
        bursts.append(cur)
    return bursts


def burst_stats(b, dt):
    path_raw = sum(math.hypot(r.rx, r.ry) for r in b)
    path_game = sum(math.hypot(r.gx, r.gy) for r in b)
    peak = 0.0
    for i in range(len(b)):
        w = b[i:i + 3]
        wdur = (w[-1].t - w[0].t) + dt
        peak = max(peak, sum(math.hypot(r.rx, r.ry) for r in w) / wdur)
    return {"path_raw": path_raw, "path_game": path_game, "peak": peak,
            "ratio": path_game / path_raw if path_raw > 0 else NAN}


def level1_bursts(rows, dt, gap_ms, min_path):
    bursts = []
    for seg in split_segments(rows):
        bursts += [burst_stats(b, dt) for b in split_bursts(seg, gap_ms)]
    bursts = [b for b in bursts if b["path_raw"] >= min_path and not math.isnan(b["ratio"])]
    if len(bursts) < 6:
        return None
    bursts.sort(key=lambda b: b["peak"])
    third = max(1, len(bursts) // 3)
    slow, fast = bursts[:third], bursts[-third:]
    rs, rf = median([b["ratio"] for b in slow]), median([b["ratio"] for b in fast])
    rho = spearman([b["peak"] for b in bursts], [b["ratio"] for b in bursts])
    return {"n": len(bursts), "ratio_slow": rs, "ratio_fast": rf, "drop": rf / rs if rs else NAN, "rho": rho,
            "peak_slow": median([b["peak"] for b in slow]), "peak_fast": median([b["peak"] for b in fast])}


# ------------------------------------------------------------------ уровень 2
def level2(rows):
    """out -> look. look в строке n+L соответствует out в строке n; L подбираем (0 или 1)."""
    best = None
    for lag in (0, 1):
        xs, ys = [], []
        for i in range(len(rows) - lag):
            a, b = rows[i], rows[i + lag]
            if b.mode not in (0, 1) or math.isnan(b.lx) or math.isnan(b.sens):
                continue
            xs.append(a.ox * b.sens)
            ys.append(b.lx)
        if len(xs) < 30 or sum(abs(x) for x in xs) == 0:
            continue
        k, r2 = linfit(xs, ys)
        if not math.isnan(r2) and (best is None or r2 > best["r2"]):
            best = {"lag": lag, "k": k, "r2": r2, "xs": xs, "ys": ys}
    if not best:
        return None
    # k по корзинам |out*sens|: у линейного звена постоянна
    edges = [0, 5, 15, 40, 100, 200, 400, 800, float("inf")]
    bins = []
    for i in range(len(edges) - 1):
        sel = [(x, y) for x, y in zip(best["xs"], best["ys"]) if x != 0 and edges[i] <= abs(x) < edges[i + 1]]
        if len(sel) >= 5:
            bins.append({"lo": edges[i], "hi": edges[i + 1], "n": len(sel),
                         "k": sum(abs(y) for _, y in sel) / sum(abs(x) for x, _ in sel)})
    best["bins"] = bins
    ks = [b["k"] for b in bins]
    best["spread"] = (max(ks) / min(ks)) if len(ks) >= 2 and min(ks) > 0 else NAN
    best["trend_down"] = len(ks) >= 3 and ks[-1] < 0.85 * ks[0]
    return best


# ------------------------------------------------------------------ вывод
def fmt_edges(lo, hi):
    return "%g-%s" % (lo, "inf" if hi == float("inf") else "%g" % hi)


def analyze(rows, meta, a, out=print):
    res = {"l1": "NO DATA", "l2": "NO DATA", "zero": "NO DATA", "raw": "NO DATA", "fps": NAN}
    if len(rows) < 10:
        out("Слишком мало кадров (%d). Захват пустой или Mouse_GetState не вызывался; смотри лог (1s: ...)." % len(rows))
        return res
    dts = [rows[i + 1].t - rows[i].t for i in range(len(rows) - 1) if rows[i + 1].t > rows[i].t]
    dt = median(dts)
    res["fps"] = 1000.0 / dt if dt else NAN
    half_x = a.half_width or (meta["half"][0] if meta.get("half") else None)
    half_y = a.half_height or (meta["half"][1] if meta.get("half") else None)

    out("кадров: %d, медианный интервал %.2f мс (~%.0f FPS), клиент %s, half=(%s,%s), pairing=%s" % (
        len(rows), dt, res["fps"], "x".join(map(str, meta["client"])) if meta.get("client") else "?", half_x, half_y, meta.get("pairing")))
    for c in meta.get("conditions", [])[:1]:
        out("условия: " + c)
    modes = {}
    for r in rows:
        modes[r.mode] = modes.get(r.mode, 0) + 1
    out("кадры по режимам: " + ", ".join("%s=%d" % (MODE_NAMES.get(k, k), v) for k, v in sorted(modes.items())))
    if meta.get("pairing") and str(meta["pairing"]).startswith("direct"):
        out("ВНИМАНИЕ: pairing=direct - хук Mouse_WndMsg не сработал, покадровое соответствие raw/game шумное (суммы и всплески остаются верными).")
    sx = sum(r.rx for r in rows)
    gx = sum(r.gx for r in rows)
    if sx and gx and (sx > 0) != (gx > 0):
        out("ВНИМАНИЕ: сумма raw_dx и game_dx разного знака - проверь направление осей до выводов.")
    if a.dpi:
        thr = (half_x or 0) / dt if dt else 0
        out("порог по X при %g dpi: %.2f счёта/мс = %.2f м/с" % (a.dpi, thr, thr * 1000.0 / a.dpi * 0.0254))

    # ---------------- уровень 1
    out("\n== УРОВЕНЬ 1: raw -> game (потеря до аккумулятора) ==")
    any_ceiling = False
    for axis, half in (("x", half_x), ("y", half_y)):
        table, ceiling, detail = level1_axis(rows, axis, half)
        out("ось %s%s" % (axis.upper(), ": " + detail if detail else ""))
        out("  %-12s %6s %8s %8s %8s" % ("|raw|/кадр", "n", "sum_g/r", "p50|game|", "max|game|"))
        for t in table:
            out("  %-12s %6d %8.2f %8.0f %8.0f" % (fmt_edges(t["lo"], t["hi"]), t["n"], t["ratio"], t["p50"], t["max"]))
        any_ceiling = any_ceiling or ceiling
    bs = level1_bursts(rows, dt, a.gap, a.min_path)
    if bs:
        out("всплески (%d): ratio медленные=%.3f быстрые=%.3f (x%.2f), rho(скорость, ratio)=%.2f; пик медленных %.2f, быстрых %.2f счёта/мс" % (
            bs["n"], bs["ratio_slow"], bs["ratio_fast"], bs["drop"], bs["rho"], bs["peak_slow"], bs["peak_fast"]))
    else:
        out("всплесков мало для сравнения медленных и быстрых (нужно >= 6 с паузами > %g мс)." % a.gap)
    if any_ceiling:
        res["l1"] = "SATURATION"
        out("  -> ПОЛКА: при |raw| выше половины клиентской области игра получает не больше ~half за кадр. Потеря ДО аккумулятора; "
            "порог зависит от FPS (ниже FPS - раньше упор). Лечится заменой источника (режим RAW в Mouse_GetState).")
    elif bs and bs["drop"] < 0.85 and bs["rho"] < -0.4:
        res["l1"] = "NONLINEAR"
        out("  -> Нелинейность без явной полки: быстрые всплески теряют %.0f%%. Потеря до аккумулятора (центровка/пропуск сообщений)." % ((1 - bs["drop"]) * 100))
    elif bs or half_x:
        res["l1"] = "LINEAR"
        out("  -> Уровень 1 линеен на снятых движениях (полки нет, зависимости от скорости нет). Если резких движений в захвате не было - повтори.")

    # ---------------- уровень 2
    out("\n== УРОВЕНЬ 2: out -> look (InputMapper_Update) ==")
    l2 = level2(rows)
    if not l2:
        out("нет колонок look/sens или MouseState не читался (в логе 'MouseState capture DISABLED'?) - уровень не оценён.")
    else:
        out("look[n+%d] ~ k * out[n]*sens: k=%.3f, R2=%.3f (запаздывание look подобрано автоматически)" % (l2["lag"], l2["k"], l2["r2"]))
        out("  %-12s %6s %8s" % ("|out*sens|", "n", "|look|/|out*sens|"))
        for b in l2["bins"]:
            out("  %-12s %6d %8.3f" % (fmt_edges(b["lo"], b["hi"]), b["n"], b["k"]))
        if l2["r2"] < 0.9:
            res["l2"] = "UNCLEAR"
            out("  -> R2 низкий: look не пропорционален out*sens. Либо смещения MouseState неверны, либо InputMapper делает что-то ещё (кривая, сглаживание).")
        elif l2["trend_down"] or (not math.isnan(l2["spread"]) and l2["spread"] > 1.3):
            res["l2"] = "NONLINEAR"
            out("  -> look/out падает на больших входах (разброс k x%.2f): нелинейность ВНУТРИ InputMapper/MouseState." % l2["spread"])
        else:
            res["l2"] = "LINEAR"
            out("  -> InputMapper линеен (разброс k x%.2f)." % (l2["spread"] if not math.isnan(l2["spread"]) else 1.0))

    # ---------------- режимы
    raw_rows = [r for r in rows if r.mode == 1]
    zero_rows = [r for r in rows if r.mode == 2]
    pass_rows = [r for r in rows if r.mode == 0]
    out("\n== РЕЖИМЫ ==")
    if raw_rows:
        sr = sum(math.hypot(r.rx, r.ry) for r in raw_rows)
        so = sum(math.hypot(r.ox, r.oy) for r in raw_rows)
        sg = sum(math.hypot(r.gx, r.gy) for r in raw_rows)
        out("RAW: %d кадров, out/raw = %.3f (ожидается RawScale), game/raw = %.3f (что игра дала бы сама)" % (len(raw_rows), so / sr if sr else NAN, sg / sr if sr else NAN))
        res["raw"] = "OK" if sr and so > 0 else "BAD"
    else:
        out("RAW: кадров нет (F9 не нажимали)")
    if zero_rows:
        looks = [abs(r.lx) + abs(r.ly) for r in zero_rows if not math.isnan(r.lx)]
        base = [abs(r.lx) + abs(r.ly) for r in pass_rows if not math.isnan(r.lx)]
        if looks:
            mz, mp = percentile(looks, 95), percentile(base, 95) if base else NAN
            out("ZERO: %d кадров, 95-й перцентиль |look| = %.4f (в PASS %.4f)" % (len(zero_rows), mz, mp))
            if not math.isnan(mp) and mp > 0 and mz < 0.05 * mp:
                res["zero"] = "ACC_ONLY"
                out("  -> MouseState питается только аккумулятором. (Вращается ли КАМЕРА в ZERO - смотри глазами: если вращается, есть другой путь в камеру.)")
            else:
                res["zero"] = "OTHER_SOURCE"
                out("  -> look не обнулился при acc=0: у MouseState есть другой источник (проверь DirectInput: _di.csv, ветка FUN_008912c0).")
        else:
            out("ZERO: %d кадров, но look не читался (MouseState capture отключён) - смотри глазами, вращается ли камера." % len(zero_rows))
    else:
        out("ZERO: кадров нет (F9 дважды)")

    out("\n== ЧТО ДАЛЬШЕ ==")
    l1, l2v = res["l1"], res["l2"]
    if l1 == "SATURATION":
        out("Полка найдена. Проверь субъективно режим RAW: если 'отрицательное ускорение' исчезло - фикс первого уровня закрывает проблему (дальше - оценка сглаживания и зависимости от FPS).")
    elif l1 in ("LINEAR", "NO DATA") and l2v == "NONLINEAR":
        out("До аккумулятора линейно, нелинейность в InputMapper/MouseState: искать кривую/кламп на пути out -> look.")
    elif l1 == "LINEAR" and l2v in ("LINEAR", "NO DATA", "UNCLEAR"):
        out("Уровни 1-2 линейны (или не оценены): причина ниже по цепочке, в потребителе MouseState (камера: сглаживание, ограничение скорости поворота, множитель frame time).")
    elif l1 == "NONLINEAR":
        out("Нелинейность до аккумулятора без полки: смотри FPS-зависимость и пропуск WM_MOUSEMOVE; режим RAW всё равно обойдёт этот участок.")
    else:
        out("Данных мало. Повтори захват: по 10 медленных и резких движений на одну дистанцию, пауза > %g мс между ними." % a.gap)
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="+")
    ap.add_argument("--gap", type=float, default=120.0, help="пауза (мс), разделяющая всплески")
    ap.add_argument("--min-path", type=float, default=30.0, help="отбросить всплески короче (в счётах)")
    ap.add_argument("--half-width", type=int, default=0, help="половина ширины клиента - 1 (по умолчанию из шапки CSV)")
    ap.add_argument("--half-height", type=int, default=0, help="половина высоты клиента - 1")
    ap.add_argument("--dpi", type=float, default=0, help="dpi мыши, чтобы перевести порог в м/с")
    a = ap.parse_args(argv)

    rows, meta_lines, t_off = [], [], 0.0
    for p in a.csv:
        r, m = load_csv(p, t_off)
        if r:
            t_off = r[-1].t + 1000.0
        rows += r
        meta_lines += m
    res = analyze(rows, parse_meta(meta_lines), a)
    return 0 if res["l1"] != "NO DATA" else 1


if __name__ == "__main__":
    sys.exit(main())
