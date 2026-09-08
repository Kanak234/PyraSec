# PyraSec 3D Viewer

A single, self-contained HTML viewer for the pyramid visualisation. No build
step, no server, no dependencies — it runs straight from `file://` and matches
the scanner's own no-dependency stance. Findings become a 3D pyramid: folders
are layers (project root at the apex, deepest nesting at the widest base),
files are blocks coloured by their worst finding (red critical / amber warning /
green secure), and a block's height grows with its finding count.

## Fastest path — one command

    pyrasec pyramid . --open

This scans the current directory, builds a standalone viewer with the scan data
baked in, and opens it in your browser. Because the data is inlined into the
HTML, it works offline on `file://` where browsers block `fetch()`.

To keep the files instead of using a temp path:

    pyrasec pyramid . -o report.html --open
    # writes report.html (self-contained) and report.json (raw data)

## Manual path

    pyrasec pyramid . -o pyramid.json      # generate the data
    # then open pyrasec/viz/viewer.html and either:
    #   - click "Choose file" and pick pyramid.json, or
    #   - drag pyramid.json onto the page

Serving over http also auto-loads a sibling pyramid.json:

    cd pyrasec/viz && python3 -m http.server
    # visit http://localhost:8000/viewer.html  (put pyramid.json in the same dir)

## In the viewer

- **Drag** to orbit, **scroll** to zoom, **arrow keys** also rotate.
- **Click a block** to inspect that file in the right rail.
- **Tabs**: Findings (severity counts + flagged files), Layers (depth breakdown
  with a severity bar per level), Attack surface, and a per-directory Heatmap.
- **Spin** for a slow auto-rotate (good for a demo screen).
- **Save image** exports the current view as a PNG for slides.

## A note on the demo score

Scanning PyraSec itself reports 98/100 (A+) with two LOW SEC005 findings — the
<!-- pyrasec:ignore-next-line SEC005 -->
Visa test number `4111 1111 1111 1111`, which appears in README.md and as the
test fixture inside the SEC005 rule. These are correctly downgraded to LOW at
0.3 confidence (the rule recognises well-known test PANs); the scanner reports
them rather than hiding them, which is the right call for a PCI check. To show a
clean 100 in a demo, exclude that one rule:

    pyrasec pyramid . --disable SEC005 --open
