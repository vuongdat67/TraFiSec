from pathlib import Path

from PIL import Image

for name in ["fig1_architecture.png", "fig2_evidence_example.png"]:
    p = Path(__file__).resolve().parent.parent / "figures" / name
    source = Image.open(p).convert("RGBA")
    im = Image.alpha_composite(Image.new("RGBA", source.size, "white"), source).convert("RGB")
    w, h = im.size
    colors = im.getcolors(maxcolors=w * h)
    ncolors = len(colors) if colors else -1
    px = im.get_flattened_data()
    ink = sum(1 for r, g, b in px if not (r > 245 and g > 245 and b > 245))
    print(f"{name}: {w}x{h}, distinct colors={ncolors}, ink_fraction={ink / (w * h):.3f}")
    for label, (x, y) in {"TL": (2, 2), "TR": (w - 3, 2), "BL": (2, h - 3), "BR": (w - 3, h - 3)}.items():
        print(f"   {label} corner: {im.getpixel((x, y))}")
