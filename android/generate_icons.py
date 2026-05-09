"""Generate Android launcher icons from `resources/icon.png`.

Запускайте из корня репозитория: ``python android/generate_icons.py``.

Что делает:

* legacy ``mipmap-<density>/ic_launcher.png`` и ``ic_launcher_round.png``
  для лончеров, которые не используют adaptive icons;
* ``mipmap-<density>/ic_launcher_foreground.png`` — это та же картинка,
  но с дополнительными прозрачными полями, чтобы при адаптивной маске
  108 dp (safe zone 66 dp) рисунок не обрезался.

Пишется один-в-один из исходного 256×256 PNG, никаких эффектов /
паддингов не применяется кроме аккуратного inset под safe zone.

Запускать руками после правки ``resources/icon.png``. Скрипт
идемпотентный — перезаписывает файлы.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "resources" / "icon.png"
RES = REPO / "android" / "app" / "src" / "main" / "res"

# Базовый размер launcher-иконки (mdpi) — 48 dp.
LEGACY_BASE_DP = 48
# Adaptive foreground = 108 dp (включая safe zone 66 dp).
ADAPTIVE_BASE_DP = 108

DENSITIES: list[tuple[str, float]] = [
    ("mdpi", 1.0),
    ("hdpi", 1.5),
    ("xhdpi", 2.0),
    ("xxhdpi", 3.0),
    ("xxxhdpi", 4.0),
]


def write_legacy(src: Image.Image) -> None:
    """Готовит ``ic_launcher.png`` / ``ic_launcher_round.png`` под все плотности."""
    for name, scale in DENSITIES:
        size = int(round(LEGACY_BASE_DP * scale))
        out_dir = RES / f"mipmap-{name}"
        out_dir.mkdir(parents=True, exist_ok=True)
        scaled = src.resize((size, size), Image.LANCZOS)
        scaled.save(out_dir / "ic_launcher.png", optimize=True)
        # round-вариант — тот же файл; современные лончеры одинаково их
        # маскируют, отдельная маска не нужна.
        scaled.save(out_dir / "ic_launcher_round.png", optimize=True)


def write_adaptive_foreground(src: Image.Image) -> None:
    """Adaptive icon foreground: 108 dp полотно, safe-zone центром 66 dp.

    Картинка вписывается в ~70 dp (~64% от 108) — достаточно, чтобы любая
    круглая / squircle-маска лончера не съела периметр.
    """
    inner_ratio = 64 / 108  # ~0.59 — чуть больше safe zone, как делает Android Studio
    for name, scale in DENSITIES:
        canvas_px = int(round(ADAPTIVE_BASE_DP * scale))
        inner_px = int(round(canvas_px * inner_ratio))
        out_dir = RES / f"mipmap-{name}"
        out_dir.mkdir(parents=True, exist_ok=True)

        canvas = Image.new("RGBA", (canvas_px, canvas_px), (0, 0, 0, 0))
        scaled = src.resize((inner_px, inner_px), Image.LANCZOS)
        offset = ((canvas_px - inner_px) // 2, (canvas_px - inner_px) // 2)
        canvas.paste(scaled, offset, scaled)
        canvas.save(out_dir / "ic_launcher_foreground.png", optimize=True)


def main() -> None:
    if not SRC.exists():
        raise SystemExit(f"Не найден исходник иконки: {SRC}")
    src = Image.open(SRC).convert("RGBA")
    print(f"Источник: {SRC}  ({src.size[0]}x{src.size[1]})")
    write_legacy(src)
    print("• legacy mipmap-* / ic_launcher.png + ic_launcher_round.png")
    write_adaptive_foreground(src)
    print("• adaptive mipmap-* / ic_launcher_foreground.png")
    print("Готово.")


if __name__ == "__main__":
    main()
