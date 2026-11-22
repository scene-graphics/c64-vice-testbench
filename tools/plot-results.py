#!/usr/bin/env python3
"""Render the shared-suite scene.graphics results as a deterministic SVG."""

import argparse
from collections import Counter
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BUILDS = (
    ("scene.graphics", "scene.graphics WASM rc1"),
)
OUTCOMES = (
    ("pass", "Passed", "#147b68"),
    ("fail", "Failed", "#b84a4c"),
    ("missing_reference", "Missing reference", "#67728d"),
)


def render():
    with (ROOT / "vice-results.csv").open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    if [int(row["VICE original"]) for row in rows] != list(range(1544)):
        raise ValueError("Expected all 1,544 originals in order")
    scope = [row["VICE original"] for row in rows if row[BUILDS[0][1]] != "not_applicable"]
    if len(scope) != 1392:
        raise ValueError("Expected 1,392 applicable originals")

    svg = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 790 184" role="img" aria-labelledby="title desc">',
           '<title id="title">scene.graphics VICE test results</title>',
           '<desc id="desc">Passes, failures and missing references on the same 1,392 applicable cases.</desc>',
           '<rect width="790" height="184" rx="12" fill="#f7f8fa"/>',
           '<g font-family="system-ui, sans-serif" fill="#192133">',
           '<text x="24" y="38" font-size="22" font-weight="700">scene.graphics VICE test results</text>',
           '<text x="24" y="63" font-size="13" fill="#516078">1,392 applicable cases</text>']
    for n, (label, column) in enumerate(BUILDS):
        applicable = [row for row in rows if row[column] != "not_applicable"]
        if [row["VICE original"] for row in applicable] != scope:
            raise ValueError(f"Case scope differs for {label}")
        counts = Counter(row[column] for row in applicable)
        if counts.keys() - {key for key, _, _ in OUTCOMES}:
            raise ValueError(f"Unknown verdict for {label}")
        y = 88 + n * 44
        svg.append(f'<text x="24" y="{y + 16}" font-size="14">{label}</text>')
        x = 184
        for key, outcome, color in OUTCOMES:
            count = counts[key]
            if not count:
                continue
            width = 462 * count / len(scope)
            svg.append(f'<rect x="{x:.3f}" y="{y}" width="{width:.3f}" height="22" fill="{color}"><title>{outcome}: {count:,}</title></rect>')
            x += width
        svg.append(f'<text x="765" y="{y + 16}" text-anchor="end" font-size="14" font-weight="650">{counts["pass"] / len(scope):.1%}</text>')

    for x, (_, label, color) in zip((24, 150, 270), OUTCOMES):
        svg.append(f'<rect x="{x}" y="149" width="12" height="12" fill="{color}"/>')
        svg.append(f'<text x="{x + 19}" y="160" font-size="13">{label}</text>')
    return "\n".join([*svg, "</g>", "</svg>", ""])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = ROOT / "screenshots/vice-results.svg"
    chart = render()
    if args.check:
        if not target.is_file() or target.read_text(encoding="utf-8") != chart:
            parser.error("Chart is stale. Run python3 tools/plot-results.py")
    else:
        target.write_text(chart, encoding="utf-8")


if __name__ == "__main__":
    main()
