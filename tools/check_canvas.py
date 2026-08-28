"""Verify every label's absolute box fits inside the SVG viewBox (no clipping)."""
import sys
import xml.etree.ElementTree as ET

SVG = "{http://www.w3.org/2000/svg}"

def main(path):
    tree = ET.parse(path)
    root = tree.getroot()
    vb = (root.get("viewBox") or "0 0 800 600").split()
    _, _, W, H = (float(x) for x in vb)
    # build parent map
    parent = {}
    for p in root.iter():
        for c in p:
            parent[c] = p
    def abs_translate(el):
        chain = []
        cur = el
        while cur is not None:
            chain.append(cur)
            cur = parent.get(cur)
        x = y = 0.0
        for node in reversed(chain):
            t = node.get("transform") or ""
            for m in t.split("translate(")[1:]:
                args = m.split(")")[0].split(",")
                if len(args) >= 2:
                    x += float(args[0].strip())
                    y += float(args[1].strip())
        return x, y
    bad = 0
    total = 0
    for el in root.iter(SVG + "foreignObject"):
        w, h = el.get("width"), el.get("height")
        if not w or not h:
            continue
        w, h = float(w), float(h)
        if w <= 0 or h <= 0:
            continue
        x, y = abs_translate(el)
        total += 1
        if x < -2 or y < -2 or x + w > W + 2 or y + h > H + 2:
            bad += 1
            text = "".join(el.itertext())[:32]
            print(f"  CLIP [{x:.0f},{y:.0f}]-[{x+w:.0f},{y+h:.0f}] vs canvas {W:.0f}x{H:.0f} : '{text}'")
    print(f"{path}: {total} labels checked, {bad} outside viewBox (viewBox {W:.0f}x{H:.0f})")
    return 1 if bad else 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
