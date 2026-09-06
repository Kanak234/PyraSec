"""Self-contained HTML report.

Zero external requests — no CDN, no webfont, no analytics beacon. Everything
is inlined. Two reasons that matters here: a security report often contains
paths and evidence you would rather not hand to a third-party CDN log, and a
hackathon demo table has unreliable wifi.

The pyramid is drawn as SVG using an isometric projection of the same block
coordinates the Three.js frontend consumes, so the report and the live app
always agree. Projection: screen_x = (x − z)·cos30°, screen_y = (x + z)·sin30° − y.
"""

from __future__ import annotations

import html
import math
from collections import defaultdict

from ..core.models import ScanResult, Severity
from ..engine.scoring import ScoreBreakdown
from ..viz.pyramid import BAND_COLORS, SEVERITY_COLORS, build_pyramid

COS30 = math.cos(math.radians(30))
SIN30 = math.sin(math.radians(30))

BG = "#0B1226"
PANEL = "#141F3D"
PANEL_LINE = "#243356"
TEXT = "#E8EDF7"
MUTED = "#8A99B8"
TEAL = "#2EE6B0"


def render_html(result: ScanResult, breakdown: ScoreBreakdown | None = None) -> str:
    pyramid = build_pyramid(result)
    counts = result.by_severity()
    findings = result.sorted_findings()

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PyraSec — {html.escape(_project_name(result))}</title>
<style>{_CSS}</style>
</head>
<body>
<header class="hero">
  <div>
    <div class="kicker">PyraSec &middot; Security Report</div>
    <h1>{html.escape(_project_name(result))}</h1>
    <p class="path">{html.escape(result.root)}</p>
    <p class="meta">{result.stats.files_scanned} files &middot; {result.stats.dirs_scanned} folders
       &middot; {result.stats.duration_seconds}s &middot; profile: {html.escape(result.profile)}
       &middot; {html.escape(result.started_at)}</p>
  </div>
  <div class="score-card" style="--ring:{_score_color(result.score)}">
    <div class="score">{result.score:g}</div>
    <div class="grade">{html.escape(result.grade)}</div>
    <div class="score-label">security score</div>
  </div>
</header>

<section class="strip">
  {_stat_card("Critical", counts["critical"], SEVERITY_COLORS[Severity.CRITICAL])}
  {_stat_card("High", counts["high"], SEVERITY_COLORS[Severity.HIGH])}
  {_stat_card("Medium", counts["medium"], SEVERITY_COLORS[Severity.MEDIUM])}
  {_stat_card("Low", counts["low"], SEVERITY_COLORS[Severity.LOW])}
  {_stat_card("Total", len(findings), TEAL)}
</section>

<section class="panel">
  <h2>Project pyramid</h2>
  <p class="sub">Folders become layers &middot; files become blocks &middot; colour is the worst finding on that file</p>
  {_render_pyramid_svg(pyramid)}
  <div class="legend">
    <span><i style="background:{BAND_COLORS['critical']}"></i> Critical</span>
    <span><i style="background:{BAND_COLORS['warning']}"></i> Warning</span>
    <span><i style="background:{BAND_COLORS['secure']}"></i> Secure</span>
  </div>
</section>

{_score_panel(breakdown)}
{_heatmap_panel(result)}

<section class="panel">
  <h2>Findings</h2>
  <p class="sub">{len(findings)} finding(s), worst first. Evidence is redacted &mdash; the report never carries the secret.</p>
  {"".join(_finding_card(f, i) for i, f in enumerate(findings, 1)) or '<p class="empty">No findings. Nothing in this tree matched a rule.</p>'}
</section>

<footer>
  PyraSec {html.escape(result.scanner_version)} &middot; deterministic rule-based analysis &middot;
  built by Team CipherStack &middot; no AI, no ML, no LLM in the detection path
</footer>
</body></html>"""


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------


def _render_pyramid_svg(pyramid: dict, width: int = 940, height: int = 460) -> str:
    blocks = pyramid["blocks"]
    if not blocks:
        return '<p class="empty">No files to render.</p>'

    # Isometric projection. Screen-Y increases upward here, so a taller layer
    # (larger world y) lands higher in the image and the apex is at the top.
    projected = []
    for block in blocks:
        sx = (block["x"] - block["z"]) * COS30
        sy = block["y"] - (block["x"] + block["z"]) * SIN30
        projected.append((sx, sy, block))

    xs = [p[0] for p in projected]
    ys = [p[1] for p in projected]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    span_x = max(max_x - min_x, 1e-6)
    span_y = max(max_y - min_y, 1e-6)
    pad = 40
    scale = min((width - 2 * pad) / span_x, (height - 2 * pad) / span_y)

    # Painter's algorithm: blocks further from the camera (larger x+z) are
    # drawn first so nearer ones overlap them, then lower layers before higher.
    projected.sort(key=lambda p: (-(p[2]["x"] + p[2]["z"]), p[2]["y"]))

    parts = [f'<svg class="pyramid" viewBox="0 0 {width} {height}" role="img" aria-label="Project security pyramid">']
    parts.append(f'<rect width="{width}" height="{height}" fill="{PANEL}" rx="12"/>')

    for sx, sy, block in projected:
        px = pad + (sx - min_x) * scale
        py = height - pad - (sy - min_y) * scale
        size = max(block["size"] * scale * 0.22, 2.4)
        color = block["color"]
        title = html.escape(f'{block["path"]} · {block["finding_count"]} finding(s) · {block["mode"]}')
        parts.append(
            f'<g class="blk"><title>{title}</title>'
            f'<polygon points="{_diamond(px, py, size)}" fill="{color}" '
            f'fill-opacity="{0.95 if block["finding_count"] else 0.42}" '
            f'stroke="{BG}" stroke-width="0.7"/></g>'
        )

    for layer in pyramid["layers"]:
        ly = height - pad - (layer["y"] - min_y) * scale
        parts.append(
            f'<text x="{width - pad + 6}" y="{ly + 4}" fill="{MUTED}" font-size="10" '
            f'text-anchor="end" opacity="0.7">{html.escape(layer["label"])}</text>'
        )

    parts.append("</svg>")
    return "".join(parts)


def _diamond(cx: float, cy: float, size: float) -> str:
    """Isometric top face of a cube."""
    w, h = size, size * SIN30 / COS30
    return f"{cx},{cy - h} {cx + w},{cy} {cx},{cy + h} {cx - w},{cy}"


def _score_panel(breakdown: ScoreBreakdown | None) -> str:
    if breakdown is None:
        return ""
    rows = "".join(
        f"<tr><td>{html.escape(sev)}</td><td>{breakdown.count_by_severity.get(sev, 0)}</td>"
        f"<td>{penalty:.2f}</td></tr>"
        for sev, penalty in breakdown.penalty_by_severity.items()
        if breakdown.count_by_severity.get(sev, 0)
    )
    return f"""<section class="panel">
  <h2>How this score was calculated</h2>
  <p class="sub">Every input is printable. Same tree in, same number out.</p>
  <pre class="formula">score = 100 × e^(−density / 12)    where density = total_penalty / (1 + log₁₀(files))</pre>
  <table class="tbl"><thead><tr><th>Severity</th><th>Count</th><th>Penalty</th></tr></thead>
  <tbody>{rows}<tr class="total"><td>total</td><td>{sum(breakdown.count_by_severity.values())}</td>
  <td>{breakdown.total_penalty:.2f}</td></tr></tbody></table>
  <p class="sub">Penalty density {breakdown.density:.3f} over {breakdown.file_count} files
     &rarr; score {breakdown.score:g} ({html.escape(breakdown.grade)})</p>
</section>"""


def _heatmap_panel(result: ScanResult) -> str:
    by_dir: dict[str, dict[str, int]] = defaultdict(lambda: {s.value: 0 for s in Severity})
    for finding in result.findings:
        directory = finding.path.rsplit("/", 1)[0] if "/" in finding.path else "."
        by_dir[directory][finding.severity.value] += 1
    if not by_dir:
        return ""

    ordered = sorted(
        by_dir.items(),
        key=lambda kv: -(kv[1]["critical"] * 10 + kv[1]["high"] * 6 + kv[1]["medium"] * 3 + kv[1]["low"]),
    )[:20]
    peak = max(sum(v.values()) for _, v in ordered) or 1

    rows = []
    for directory, counts in ordered:
        cells = "".join(
            f'<td><span class="cell" style="background:{SEVERITY_COLORS[Severity(sev)]};'
            f'opacity:{0.15 + 0.85 * min(counts[sev] / peak, 1):.2f}">{counts[sev] or ""}</span></td>'
            for sev in ("critical", "high", "medium", "low")
        )
        rows.append(f'<tr><td class="dir">{html.escape(directory)}/</td>{cells}</tr>')

    return f"""<section class="panel">
  <h2>Risk heatmap</h2>
  <p class="sub">Which folders concentrate the risk</p>
  <table class="tbl heat"><thead><tr><th>Directory</th><th>Critical</th><th>High</th>
  <th>Medium</th><th>Low</th></tr></thead><tbody>{"".join(rows)}</tbody></table>
</section>"""


def _finding_card(finding, index: int) -> str:
    color = SEVERITY_COLORS[finding.severity]
    location = html.escape(finding.path)
    if finding.line:
        location += f":{finding.line}"

    steps = "".join(f"<li>{html.escape(step)}</li>" for step in finding.remediation.steps)
    example = (
        f'<pre class="code">{html.escape(finding.remediation.example.rstrip())}</pre>'
        if finding.remediation.example else ""
    )
    tags = "".join(
        f'<span class="tag">{html.escape(t)}</span>'
        for t in filter(None, [finding.cwe, finding.owasp, finding.mitre])
    )
    evidence = (
        f'<div class="evidence"><span>evidence</span><code>{html.escape(finding.evidence)}</code></div>'
        if finding.evidence else ""
    )

    return f"""<article class="finding" style="--sev:{color}">
  <div class="fhead">
    <span class="num">{index:02d}</span>
    <span class="pill" style="background:{color}">{finding.severity.value}</span>
    <span class="rid">{html.escape(finding.rule_id)}</span>
    <h3>{html.escape(finding.title)}</h3>
  </div>
  <div class="loc">{location}
    <span class="cvss">CVSS {finding.effective_cvss:g}</span>
    <span class="conf">confidence {finding.confidence:g}</span>
  </div>
  {evidence}
  <p class="desc">{html.escape(finding.description)}</p>
  <div class="fix">
    <strong>{html.escape(finding.remediation.summary)}</strong>
    <ol>{steps}</ol>
    {example}
  </div>
  <div class="tags">{tags}</div>
</article>"""


def _stat_card(label: str, value: int, color: str) -> str:
    return (
        f'<div class="stat" style="--c:{color}"><div class="v">{value}</div>'
        f'<div class="l">{html.escape(label)}</div></div>'
    )


def _score_color(score: float) -> str:
    if score >= 85:
        return BAND_COLORS["secure"]
    if score >= 60:
        return BAND_COLORS["warning"]
    return BAND_COLORS["critical"]


def _project_name(result: ScanResult) -> str:
    return result.root.rstrip("/").rsplit("/", 1)[-1] or result.root


# --------------------------------------------------------------------------
# Styles
# --------------------------------------------------------------------------

_CSS = f"""
*{{box-sizing:border-box}}
body{{margin:0;background:{BG};color:{TEXT};
 font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
 padding:28px;max-width:1080px;margin-inline:auto}}
h1{{font-size:34px;margin:6px 0 4px;letter-spacing:-.02em}}
h2{{font-size:19px;margin:0 0 4px;letter-spacing:-.01em}}
h3{{font-size:15.5px;margin:0;font-weight:600}}
.kicker{{color:{TEAL};font-size:11px;letter-spacing:.18em;text-transform:uppercase;font-weight:700}}
.hero{{display:flex;justify-content:space-between;align-items:center;gap:24px;
 background:{PANEL};border:1px solid {PANEL_LINE};border-radius:16px;padding:26px 30px;margin-bottom:16px}}
.path{{color:{MUTED};font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;margin:0 0 6px}}
.meta{{color:{MUTED};font-size:12px;margin:0}}
.score-card{{text-align:center;min-width:150px;border:2px solid var(--ring);border-radius:14px;padding:14px 20px}}
.score{{font-size:48px;font-weight:800;line-height:1;color:var(--ring)}}
.grade{{font-size:17px;font-weight:700;margin-top:2px}}
.score-label{{color:{MUTED};font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;margin-top:6px}}
.strip{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px}}
.stat{{background:{PANEL};border:1px solid {PANEL_LINE};border-left:3px solid var(--c);
 border-radius:12px;padding:14px 16px}}
.stat .v{{font-size:26px;font-weight:700;color:var(--c)}}
.stat .l{{color:{MUTED};font-size:11px;letter-spacing:.1em;text-transform:uppercase}}
.panel{{background:{PANEL};border:1px solid {PANEL_LINE};border-radius:16px;padding:22px 26px;margin-bottom:16px}}
.sub{{color:{MUTED};font-size:12.5px;margin:0 0 14px}}
.pyramid{{width:100%;height:auto;display:block;border-radius:12px}}
.blk polygon{{transition:fill-opacity .15s}}
.blk:hover polygon{{fill-opacity:1;stroke:{TEXT};stroke-width:1.2}}
.legend{{display:flex;gap:18px;justify-content:center;margin-top:12px;color:{MUTED};font-size:12px}}
.legend i{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}}
.tbl{{width:100%;border-collapse:collapse;font-size:13px}}
.tbl th{{text-align:left;color:{MUTED};font-weight:600;font-size:11px;letter-spacing:.08em;
 text-transform:uppercase;padding:6px 10px;border-bottom:1px solid {PANEL_LINE}}}
.tbl td{{padding:6px 10px;border-bottom:1px solid rgba(36,51,86,.5)}}
.tbl .total td{{font-weight:700;color:{TEAL}}}
.heat .dir{{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:{TEXT}}}
.cell{{display:inline-block;min-width:34px;text-align:center;border-radius:5px;padding:2px 6px;
 color:{BG};font-weight:700;font-size:11.5px}}
.formula{{background:{BG};border:1px solid {PANEL_LINE};border-radius:8px;padding:10px 14px;
 font-size:12.5px;color:{TEAL};overflow-x:auto;margin:0 0 14px}}
.finding{{border:1px solid {PANEL_LINE};border-left:3px solid var(--sev);border-radius:12px;
 padding:16px 18px;margin-bottom:12px;background:rgba(11,18,38,.45)}}
.fhead{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}}
.num{{color:{MUTED};font-family:ui-monospace,Menlo,monospace;font-size:12px}}
.pill{{color:{BG};font-size:10px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;
 padding:2px 8px;border-radius:20px}}
.rid{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:{MUTED}}}
.loc{{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:{TEAL};margin-bottom:8px}}
.cvss,.conf{{color:{MUTED};margin-left:12px;font-size:11px}}
.evidence{{display:flex;gap:10px;align-items:center;background:{BG};border:1px solid {PANEL_LINE};
 border-radius:8px;padding:6px 10px;margin-bottom:8px;font-size:12px}}
.evidence span{{color:{MUTED};font-size:10px;letter-spacing:.1em;text-transform:uppercase}}
.evidence code{{color:{TEXT};font-family:ui-monospace,Menlo,monospace}}
.desc{{margin:0 0 10px;font-size:13.5px;color:#C6D0E4}}
.fix{{background:{BG};border:1px solid {PANEL_LINE};border-radius:10px;padding:12px 16px}}
.fix strong{{color:{TEAL};font-size:13px}}
.fix ol{{margin:8px 0 0;padding-left:20px;font-size:13px;color:#C6D0E4}}
.fix li{{margin-bottom:4px}}
.code{{background:#060B18;border:1px solid {PANEL_LINE};border-radius:8px;padding:10px 12px;
 font-size:12px;overflow-x:auto;color:{TEXT};margin:10px 0 0;
 font-family:ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}}
.tags{{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}}
.tag{{font-size:10.5px;color:{MUTED};border:1px solid {PANEL_LINE};border-radius:6px;padding:2px 7px}}
.empty{{color:{MUTED};text-align:center;padding:22px}}
footer{{color:{MUTED};font-size:11.5px;text-align:center;padding:18px 0 6px}}
@media (max-width:760px){{.hero{{flex-direction:column;align-items:flex-start}}
 .strip{{grid-template-columns:repeat(2,1fr)}}}}
"""
