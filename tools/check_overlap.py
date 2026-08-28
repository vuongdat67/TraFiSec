"""Check rendered SVG for overlapping label boxes.

Builds a parent map, composes `transform="translate(x,y)"` up the ancestor
chain so coords are absolute. dagre layout should produce zero overlaps.
"""
import sys
import itertools
import xml.etree.ElementTree as ET

SVG = "{http://www.w3.org/2000/svg}"

def build_parent_map(root):
    parent = {}
    for p in root.iter():
        for c in p:
            parent[c] = p
    return parent

def abs_translate(el, parent):
    parts = []
    cur = el
    while cur is not None:
        parts.append(cur)
        cur = parent.get(cur)
    x = y = 0.0
    for node in reversed(parts):
        t = node.get("transform") or ""
        for m in t.split("translate(")[1:]:
            args = m.split(")")[0].split(",")
            if len(args) >= 2:
                x += float(args[0].strip())
                y += float(args[1].strip())
    return x, y

def main(path):
    tree = ET.parse(path)
    root = tree.getroot()
    parent = build_parent_map(root)
    boxes = []
    for el in root.iter(SVG + "foreignObject"):
        w, h = el.get("width"), el.get("height")
        if not w or not h:
            continue
        w, h = float(w), float(h)
        if w <= 0 or h <= 0:
            continue
        x, y = abs_translate(el, parent)
        text = "".join(el.itertext())[:28].strip()
        boxes.append((x, y, x + w, y + h, text))
    n_overlap = 0
    for (ax0, ay0, ax1, ay1, ta), (bx0, by0, bx1, by1, tb) in itertools.combinations(boxes, 2):
        if not (ax1 <= bx0 or bx1 <= ax0 or ay1 <= by0 or by1 <= ay0):
            n_overlap += 1
            if n_overlap <= 8:
                print(f"  OVERLAP [{ax0:.0f},{ay0:.0f}]-[{ax1:.0f},{ay1:.0f}] '{ta}'  <->  [{bx0:.0f},{by0:.0f}]-[{bx1:.0f},{by1:.0f}] '{tb}'")
    print(f"{path}: {len(boxes)} labels, {n_overlap} overlaps")
    return 1 if n_overlap else 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
