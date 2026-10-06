#!/usr/bin/env python3
"""Generate icon assets (icon0.png, icon.ico, favicons) from assets/icon.svg."""

import os
import shutil
import struct
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVG_ICON = os.path.join(REPO, "installer", "assets", "icon.svg")
ICON0_PNG = os.path.join(REPO, "installer", "assets", "icon0.png")
ICON_ICO = os.path.join(REPO, "installer", "assets", "icon.ico")
FAVICON_INSTALLER = os.path.join(REPO, "installer", "frontend", "installer-page", "favicon.svg")
LOGO_INSTALLER = os.path.join(REPO, "installer", "frontend", "installer-page", "logo.svg")

ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]


def build_ico(pngs):
    """Assemble PNG blobs into a Windows .ico (Vista+ PNG-in-ICO format)."""
    header = struct.pack("<HHH", 0, 1, len(pngs))
    entries = b""
    offset = 6 + 16 * len(pngs)
    for size, data in pngs:
        w = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    return header + entries + b"".join(data for _, data in pngs)


def rsvg_render(svg_path, size):
    """Render the SVG to PNG bytes at the given size via rsvg-convert."""
    return subprocess.run(
        ["rsvg-convert", "-w", str(size), "-h", str(size), svg_path],
        check=True,
        capture_output=True,
    ).stdout


def ql_render(svg_path, size):
    """Render via QuickLook on macOS."""
    tmpdir = tempfile.mkdtemp(prefix="wkrl-icon-")
    try:
        tmp_svg = os.path.join(tmpdir, os.urandom(4).hex() + ".svg")
        shutil.copyfile(svg_path, tmp_svg)
        subprocess.run(["qlmanage", "-t", "-s", str(size), "-o", tmpdir, tmp_svg],
                       check=True, capture_output=True)
        rendered = os.path.join(tmpdir, os.path.basename(tmp_svg) + ".png")
        with open(rendered, "rb") as f:
            return f.read()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def find_renderer():
    if shutil.which("rsvg-convert"):
        return rsvg_render
    if sys.platform == "darwin" and shutil.which("qlmanage"):
        return ql_render
    return None


def generate():
    if not os.path.isfile(SVG_ICON):
        print(f"Error: {SVG_ICON} not found.")
        sys.exit(1)

    renderer = find_renderer()
    if renderer is not None:
        # 1. Render PNG 512x512
        png512 = renderer(SVG_ICON, 512)
        with open(ICON0_PNG, "wb") as f:
            f.write(png512)

        # 2. Render multi-size ICO
        pngs = [(sz, renderer(SVG_ICON, sz)) for sz in ICO_SIZES]
        with open(ICON_ICO, "wb") as f:
            f.write(build_ico(pngs))
    else:
        # Fallback if neither rsvg-convert nor qlmanage is found
        try:
            from PIL import Image
            if os.path.isfile(ICON0_PNG):
                img = Image.open(ICON0_PNG)
                img.save(ICON_ICO, sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
        except ImportError:
            if not os.path.isfile(ICON0_PNG) or not os.path.isfile(ICON_ICO):
                print("Error: No SVG renderer (rsvg-convert, qlmanage) found to generate icon0.png / icon.ico.")
                sys.exit(1)

    # 3. Copy SVG icon as favicon and logo for installer page
    for target in (FAVICON_INSTALLER, LOGO_INSTALLER):
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(SVG_ICON, target)

    print(f"Generated icon assets from {os.path.relpath(SVG_ICON, REPO)}:")
    print(f"  {os.path.relpath(ICON0_PNG, REPO)} ({os.path.getsize(ICON0_PNG)} bytes)")
    print(f"  {os.path.relpath(ICON_ICO, REPO)} ({os.path.getsize(ICON_ICO)} bytes)")


if __name__ == "__main__":
    generate()
