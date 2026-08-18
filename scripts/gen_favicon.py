#!/usr/bin/env python3
"""Generate TinySIEM favicon set (pure stdlib, no Pillow/cairosvg needed).

Writes into ui/assets/:
  favicon.svg          — hand-authored vector (browser icon)
  favicon-32.png       — transparent-bg PNG fallback (32x32)
  apple-touch-icon.png — solid dark-bg PNG for iOS home screen (180x180)

The PNGs are rasterized from the same geometry as the SVG via supersampling.
"""
import math, os, struct, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "ui", "assets")

# ---- palette (matches ui/shared.css tokens) ----
SHIELD_FILL = (18, 19, 31, 255)      # --surface #12131f
SHIELD_STROKE = (77, 159, 255, 255)  # --accent #4d9fff
PULSE = (61, 220, 132, 255)          # --green #3ddc84
BG = (13, 14, 23, 255)               # --bg #0d0e17

# Shield outline (64-grid, 10 points, clockwise from top center)
SHIELD = [(32, 4), (56, 11), (56, 32), (55, 46), (46, 56), (32, 61),
          (18, 56), (9, 46), (8, 32), (8, 11)]
# Pulse polyline (64-grid)
PULSE_PTS = [(13, 36), (25, 36), (30, 25), (37, 44), (42, 35), (51, 35)]

STROKE_W = 4.0  # shield stroke width in 64-grid units


def seg_dist(px, py, ax, ay, bx, by):
    vx, vy = bx - ax, by - ay
    wx, wy = px - ax, py - ay
    L2 = vx * vx + vy * vy
    if L2 == 0:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, (wx * vx + wy * vy) / L2))
    return math.hypot(px - (ax + t * vx), py - (ay + t * vy))


def point_in_poly(px, py, poly):
    inside = False
    n = len(poly)
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if ((yi > py) != (yj > py)) and (px < (xj - xi) * (py - yi) / (yj - yi) + xi):
            inside = not inside
        j = i
    return inside


def edge_dist(px, py, poly):
    return min(seg_dist(px, py, poly[i][0], poly[i][1],
                        poly[(i + 1) % len(poly)][0], poly[(i + 1) % len(poly)][1])
               for i in range(len(poly)))


def pulse_dist(px, py):
    return min(seg_dist(px, py, PULSE_PTS[i][0], PULSE_PTS[i][1],
                        PULSE_PTS[i + 1][0], PULSE_PTS[i + 1][1])
               for i in range(len(PULSE_PTS) - 1))


def sample(px, py):
    """Color at point (64-grid coords). Returns RGBA tuple."""
    if point_in_poly(px, py, SHIELD):
        d = edge_dist(px, py, SHIELD)
        if d < STROKE_W / 2 + 0.5:      # stroke edge (AA band)
            t = max(0.0, min(1.0, (d - (STROKE_W / 2 - 0.5)) / 1.0))
            return tuple(int(SHIELD_FILL[i] + (SHIELD_STROKE[i] - SHIELD_FILL[i]) * t)
                         for i in range(4))
        pd = pulse_dist(px, py)
        if pd < 2.0 + 0.5:
            t = max(0.0, min(1.0, (pd - 1.5) / 1.0))
            return tuple(int(SHIELD_FILL[i] + (PULSE[i] - SHIELD_FILL[i]) * t)
                         for i in range(4))
        return SHIELD_FILL
    d = edge_dist(px, py, SHIELD)
    if d < STROKE_W / 2 + 0.5:
        t = max(0.0, min(1.0, (d - (STROKE_W / 2 - 0.5)) / 1.0))
        a = int((1.0 - t) * 255)
        return (SHIELD_STROKE[0], SHIELD_STROKE[1], SHIELD_STROKE[2], a)
    return (0, 0, 0, 0)


def rasterize(size, solid_bg=False):
    SS = 4  # supersample
    rows = []
    for oy in range(size):
        row = []
        for ox in range(size):
            r = g = b = a = 0
            for sy in range(SS):
                for sx in range(SS):
                    px = (ox + (sx + 0.5) / SS) * 64.0 / size
                    py = (oy + (sy + 0.5) / SS) * 64.0 / size
                    c = sample(px, py)
                    r += c[0] * c[3]; g += c[1] * c[3]; b += c[2] * c[3]; a += c[3]
            n = SS * SS
            if solid_bg:
                # composite over solid dark bg
                aa = a / n / 255.0
                pr = int(BG[0] + (r / n / 255.0 - BG[0]) * aa + 0.5)
                pg = int(BG[1] + (g / n / 255.0 - BG[1]) * aa + 0.5)
                pb = int(BG[2] + (b / n / 255.0 - BG[2]) * aa + 0.5)
                row.append((pr, pg, pb, 255))
            else:
                row.append((int(r / n / 255.0 + 0.5), int(g / n / 255.0 + 0.5),
                            int(b / n / 255.0 + 0.5), int(a / n + 0.5)))
        rows.append(row)
    return rows


def png_chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def write_png(path, size, rows):
    raw = b""
    for row in rows:
        raw += b"\x00"
        for r, g, b, a in row:
            raw += bytes((r, g, b, a))
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(png_chunk(b"IHDR", ihdr))
        f.write(png_chunk(b"IDAT", zlib.compress(raw, 9)))
        f.write(png_chunk(b"IEND", b""))


def svg_art():
    def poly(pts, close=True):
        return " ".join(f"{x},{y}" for x, y in pts) + (" Z" if close else "")
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <path d="M {poly(SHIELD)}" fill="#12131f" stroke="#4d9fff" stroke-width="4" stroke-linejoin="round"/>
  <path d="M {poly(PULSE_PTS, close=False)}" fill="none" stroke="#3ddc84" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
</svg>'''


def main():
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "favicon.svg"), "w") as f:
        f.write(svg_art())
    write_png(os.path.join(OUT, "favicon-32.png"), 32, rasterize(32))
    write_png(os.path.join(OUT, "apple-touch-icon.png"), 180, rasterize(180, solid_bg=True))
    print("generated:", sorted(os.listdir(OUT)))


if __name__ == "__main__":
    main()
