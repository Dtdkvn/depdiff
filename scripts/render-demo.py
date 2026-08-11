"""Render the deterministic README terminal demo. Requires Pillow."""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "assets" / "demo.gif"
WIDTH, HEIGHT = 1000, 580
BG = "#07100e"
PANEL = "#0d1815"
LINE = "#20332c"
TEXT = "#effbf5"
MUTED = "#78958a"
GREEN = "#60f0b2"
RED = "#ff6577"
ORANGE = "#ff9367"
YELLOW = "#f5c451"
CYAN = "#6bd6e8"


def font(size: int, bold: bool = False):
    candidates = [
        Path("C:/Windows/Fonts/CascadiaMono.ttf"),
        Path("C:/Windows/Fonts/CascadiaCode.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default(size=size)


NORMAL = font(20)
SMALL = font(15)
TITLE = font(15, True)
BOLD = font(20, True)
HUGE = font(42, True)


LINES = [
    [(GREEN, "$ "), (TEXT, "npx depdiff-audit compare demo-widget@1.0.0 demo-widget@1.1.0")],
    [(MUTED, "  Resolving verified package snapshots…")],
    [(MUTED, "  Comparing 7 files · parsing JavaScript · profiling capabilities…")],
    [(TEXT, "  demo-widget  "), (MUTED, "1.0.0 → 1.1.0")],
    [(RED, "  100/100 CRITICAL"), (MUTED, "  ·  13 new findings  ·  package code executed: "), (GREEN, "no")],
    [(RED, "  CRITICAL  "), (TEXT, "New child process capability"), (MUTED, "  scripts/install.js:2")],
    [(RED, "  CRITICAL  "), (TEXT, "New dynamic code execution"), (MUTED, "  scripts/install.js:11")],
    [(ORANGE, "  HIGH      "), (TEXT, "New postinstall lifecycle script"), (MUTED, "  package.json")],
    [(ORANGE, "  HIGH      "), (TEXT, "1 new network destination"), (MUTED, "  collector.example.invalid")],
    [(YELLOW, "  MEDIUM    "), (TEXT, "New filesystem capability"), (MUTED, "  scripts/install.js:3")],
    [(GREEN, "  ✓ "), (TEXT, "HTML report  "), (CYAN, "depdiff-report.html")],
]


def draw_frame(visible: int, scan: float = 0.0) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    glow = Image.new("RGBA", image.size, (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse((650, -220, 1180, 310), fill=(54, 220, 151, 36))
    glow = glow.filter(ImageFilter.GaussianBlur(80))
    image = Image.alpha_composite(image.convert("RGBA"), glow)
    d = ImageDraw.Draw(image)
    d.rounded_rectangle((32, 28, WIDTH - 32, HEIGHT - 28), radius=18, fill=PANEL, outline=LINE, width=2)
    d.rounded_rectangle((32, 28, WIDTH - 32, 78), radius=18, fill="#111f1b")
    d.rectangle((32, 60, WIDTH - 32, 78), fill="#111f1b")
    for x, color in [(55, RED), (78, YELLOW), (101, GREEN)]:
        d.ellipse((x, 47, x + 11, 58), fill=color)
    d.text((WIDTH / 2, 53), "depdiff · local-first update audit", font=TITLE, fill=MUTED, anchor="mm")
    d.text((62, 104), "STATIC PACKAGE DELTA", font=SMALL, fill=GREEN)
    d.text((62, 132), "No install. No execution. Just evidence.", font=HUGE, fill=TEXT)
    y = 208
    for line in LINES[:visible]:
        x = 62
        for color, text in line:
            d.text((x, y), text, font=BOLD if color in (RED, ORANGE, YELLOW) else NORMAL, fill=color)
            x += d.textlength(text, font=BOLD if color in (RED, ORANGE, YELLOW) else NORMAL)
        y += 31
    if 0 < scan < 1:
        scan_y = 198 + int(scan * 320)
        d.rectangle((49, scan_y, WIDTH - 49, scan_y + 2), fill="#60f0b25e")
    d.text((WIDTH - 61, HEIGHT - 53), "depdiff v0.1.0", font=SMALL, fill=MUTED, anchor="rs")
    return image.convert("P", palette=Image.Palette.ADAPTIVE, colors=128)


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    frames = []
    durations = []
    for visible in range(1, 4):
        frames.append(draw_frame(visible, visible / 4))
        durations.append(750)
    for visible in range(4, len(LINES) + 1):
        frames.append(draw_frame(visible))
        durations.append(720 if visible < len(LINES) else 4200)
    frames[0].save(
        OUTPUT,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    print(OUTPUT)


if __name__ == "__main__":
    main()
