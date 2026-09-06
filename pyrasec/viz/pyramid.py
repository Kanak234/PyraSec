"""Pyramid layout — the visualisation contract between Python and Three.js.

The rule from the pitch deck: **folders become layers, files become blocks**.
Each block is one file, coloured by the worst finding on it (red / amber /
green, straight from the deck's palette).

Altitude is inverted directory depth: the project root sits at the apex and
each level of nesting widens the layer below it. That is the orientation that
matches how a tree actually behaves — a handful of files at the root, more in
every level beneath — so the shape comes out as a pyramid rather than a
top-heavy mushroom. It also puts the deepest, least-reviewed corners of the
project across the widest, most visible face.

This module emits pure data — coordinates, colours, counts. No rendering, no
WebGL, no browser assumptions. The frontend consumes ``to_dict()`` directly,
and the same structure feeds the treemap, sunburst and folder-tree views.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, asdict

from ..core.models import FileRecord, Finding, ScanResult, Severity

# Palette from the PyraSec deck.
BAND_COLORS = {
    "critical": "#EF4565",
    "warning": "#FBCD63",
    "secure": "#2EE6B0",
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#EF4565",
    Severity.HIGH: "#F97362",
    Severity.MEDIUM: "#FBCD63",
    Severity.LOW: "#8FD9C0",
    Severity.INFO: "#2EE6B0",
}


@dataclass
class Block:
    """One file, rendered as a cube in the pyramid."""

    id: str
    path: str
    name: str
    layer: int
    x: float
    y: float
    z: float
    size: float
    color: str
    band: str
    severity: str
    finding_count: int
    file_size: int
    mode: str
    findings: list[str] = field(default_factory=list)  # fingerprints

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Layer:
    """One directory depth level."""

    index: int
    depth: int
    y: float
    width: float
    block_count: int
    band: str
    color: str
    critical: int = 0
    warning: int = 0
    secure: int = 0
    label: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class PyramidBuilder:
    """Converts a ScanResult into layered 3D geometry."""

    def __init__(
        self,
        result: ScanResult,
        *,
        base_width: float = 100.0,
        layer_height: float = 14.0,
        block_size: float = 4.0,
        max_blocks_per_layer: int = 400,
    ):
        self.result = result
        self.base_width = base_width
        self.layer_height = layer_height
        self.block_size = block_size
        self.max_blocks_per_layer = max_blocks_per_layer

        self._findings_by_path: dict[str, list[Finding]] = {}
        for finding in result.findings:
            self._findings_by_path.setdefault(finding.path, []).append(finding)

    # -- public ------------------------------------------------------------

    def build(self) -> dict:
        files = [r for r in self.result.files if not r.is_dir]
        if not files:
            return self._empty()

        by_depth: dict[int, list[FileRecord]] = {}
        for record in files:
            by_depth.setdefault(record.depth, []).append(record)

        depths = sorted(by_depth)
        layer_count = len(depths)
        layers: list[Layer] = []
        blocks: list[Block] = []

        for order, depth in enumerate(depths):
            # Altitude 0 is the base (deepest nesting); the last altitude is
            # the apex (project root).
            altitude = layer_count - 1 - order
            records = sorted(by_depth[depth], key=self._risk_sort_key)
            truncated = records[: self.max_blocks_per_layer]

            # Width tapers linearly from base to apex — this is what makes it
            # read as a pyramid rather than a stack of equal slabs.
            ratio = 1.0 - (altitude / max(layer_count, 1)) * 0.85
            width = self.base_width * ratio
            y = altitude * self.layer_height

            layer = Layer(
                index=altitude,
                depth=depth,
                y=round(y, 2),
                width=round(width, 2),
                block_count=len(records),
                band="secure",
                color=BAND_COLORS["secure"],
                label=self._layer_label(depth, records),
            )

            for position, record in enumerate(truncated):
                block = self._make_block(record, altitude, position, len(truncated), width, y)
                blocks.append(block)
                if block.band == "critical":
                    layer.critical += 1
                elif block.band == "warning":
                    layer.warning += 1
                else:
                    layer.secure += 1

            layer.band = (
                "critical" if layer.critical else "warning" if layer.warning else "secure"
            )
            layer.color = BAND_COLORS[layer.band]
            layers.append(layer)

        layers.sort(key=lambda l: l.index)  # base first, apex last

        return {
            "schema": "pyrasec.pyramid/1",
            "root": self.result.root,
            "score": self.result.score,
            "grade": self.result.grade,
            "palette": BAND_COLORS,
            "dimensions": {
                "base_width": self.base_width,
                "layer_height": self.layer_height,
                "height": round(len(layers) * self.layer_height, 2),
                "layer_count": len(layers),
            },
            "layers": [layer.to_dict() for layer in layers],
            "blocks": [block.to_dict() for block in blocks],
            "summary": {
                "total_files": len(files),
                "rendered_blocks": len(blocks),
                "truncated": len(files) - len(blocks),
                "by_band": {
                    band: sum(1 for b in blocks if b.band == band)
                    for band in BAND_COLORS
                },
            },
        }

    # -- internals ---------------------------------------------------------

    def _make_block(
        self,
        record: FileRecord,
        layer_index: int,
        position: int,
        total: int,
        width: float,
        y: float,
    ) -> Block:
        findings = self._findings_by_path.get(record.path, [])
        severity = Severity.worst(f.severity for f in findings) if findings else Severity.INFO

        # Blocks are laid out on a ring so every one stays clickable from the
        # outside — a solid grid would bury the interior of each layer.
        angle = (position / max(total, 1)) * math.tau
        radius = width / 2.0 * (0.55 + 0.45 * ((position % 3) / 2.0))
        x = math.cos(angle) * radius
        z = math.sin(angle) * radius

        # File size drives block volume, log-scaled so one vendored bundle
        # doesn't dwarf every source file in the project.
        scale = 1.0 + math.log10(max(record.size, 1)) / 6.0
        size = round(self.block_size * min(scale, 2.5), 2)

        return Block(
            id=f"L{layer_index}-{position}",
            path=record.path,
            name=record.name,
            layer=layer_index,
            x=round(x, 2),
            y=round(y, 2),
            z=round(z, 2),
            size=size,
            color=SEVERITY_COLORS[severity],
            band=severity.band,
            severity=severity.value,
            finding_count=len(findings),
            file_size=record.size,
            mode=record.mode_octal,
            findings=[f.fingerprint for f in findings],
        )

    def _risk_sort_key(self, record: FileRecord) -> tuple:
        findings = self._findings_by_path.get(record.path, [])
        severity = Severity.worst(f.severity for f in findings) if findings else Severity.INFO
        return (severity.rank, -len(findings), record.path)

    def _layer_label(self, depth: int, records: list[FileRecord]) -> str:
        if depth == 0:
            return "project root"
        parents = {r.parent.split("/")[depth - 1] for r in records if "/" in r.parent or r.parent}
        parents.discard("")
        if len(parents) == 1:
            return next(iter(parents)) + "/"
        return f"depth {depth} · {len(parents)} folders"

    def _empty(self) -> dict:
        return {
            "schema": "pyrasec.pyramid/1",
            "root": self.result.root,
            "score": self.result.score,
            "grade": self.result.grade,
            "palette": BAND_COLORS,
            "dimensions": {"base_width": self.base_width, "layer_height": self.layer_height,
                           "height": 0, "layer_count": 0},
            "layers": [],
            "blocks": [],
            "summary": {"total_files": 0, "rendered_blocks": 0, "truncated": 0,
                        "by_band": {b: 0 for b in BAND_COLORS}},
        }


def build_pyramid(result: ScanResult, **kwargs) -> dict:
    return PyramidBuilder(result, **kwargs).build()


# --------------------------------------------------------------------------
# Alternate layouts — same data, different projections
# --------------------------------------------------------------------------


def build_folder_tree(result: ScanResult) -> dict:
    """Nested tree with risk rolled up to every folder.

    Also the source of truth for the treemap and sunburst views: both are
    projections of this structure, so a folder's colour is consistent across
    all three visualisations.
    """
    findings_by_path: dict[str, list[Finding]] = {}
    for finding in result.findings:
        findings_by_path.setdefault(finding.path, []).append(finding)

    root: dict = {
        "name": result.root.rsplit("/", 1)[-1] or "/",
        "path": "",
        "type": "directory",
        "children": {},
        "findings": 0,
        "size": 0,
        "severity": Severity.INFO,
    }

    for record in result.files:
        if record.is_dir:
            continue
        parts = record.path.split("/")
        node = root
        for part in parts[:-1]:
            node["size"] += record.size
            child = node["children"].get(part)
            if child is None:
                child = {
                    "name": part,
                    "path": part,
                    "type": "directory",
                    "children": {},
                    "findings": 0,
                    "size": 0,
                    "severity": Severity.INFO,
                }
                node["children"][part] = child
            node = child

        node["size"] += record.size
        findings = findings_by_path.get(record.path, [])
        severity = Severity.worst(f.severity for f in findings) if findings else Severity.INFO
        node["children"][parts[-1]] = {
            "name": parts[-1],
            "path": record.path,
            "type": "file",
            "children": {},
            "findings": len(findings),
            "size": record.size,
            "severity": severity,
        }

    root["size"] = sum(r.size for r in result.files if not r.is_dir)
    _roll_up(root)
    return _serialise_tree(root)


def _roll_up(node: dict) -> tuple[int, Severity]:
    total = node["findings"]
    worst = node["severity"]
    for child in node["children"].values():
        child_total, child_worst = _roll_up(child)
        total += child_total
        if child_worst.rank < worst.rank:
            worst = child_worst
    node["findings"] = total
    node["severity"] = worst
    return total, worst


def _serialise_tree(node: dict) -> dict:
    severity: Severity = node["severity"]
    return {
        "name": node["name"],
        "path": node["path"],
        "type": node["type"],
        "size": node["size"],
        "findings": node["findings"],
        "severity": severity.value,
        "band": severity.band,
        "color": SEVERITY_COLORS[severity],
        "children": [
            _serialise_tree(child)
            for child in sorted(
                node["children"].values(),
                key=lambda c: (c["type"] != "directory", c["name"]),
            )
        ],
    }


def build_risk_heatmap(result: ScanResult, top_n: int = 30) -> dict:
    """Directory × severity matrix — the flat view judges read fastest."""
    matrix: dict[str, dict[str, int]] = {}
    for finding in result.findings:
        directory = finding.path.rsplit("/", 1)[0] if "/" in finding.path else "."
        row = matrix.setdefault(directory, {s.value: 0 for s in Severity})
        row[finding.severity.value] += 1

    rows = sorted(
        matrix.items(),
        key=lambda kv: -(kv[1]["critical"] * 10 + kv[1]["high"] * 6 + kv[1]["medium"] * 3 + kv[1]["low"]),
    )[:top_n]

    return {
        "schema": "pyrasec.heatmap/1",
        "severities": [s.value for s in Severity],
        "rows": [
            {"directory": directory, "counts": counts, "total": sum(counts.values())}
            for directory, counts in rows
        ],
    }


def build_attack_surface(result: ScanResult) -> dict:
    """Group findings into the paths an attacker would actually chain.

    Deterministic grouping by rule tag, not inference — each surface lists the
    concrete findings that make it reachable, so the claim is auditable.
    """
    surfaces = [
        ("Credential exposure", {"secret", "credential"},
         "Secrets recoverable from the repository or filesystem."),
        ("Externally reachable files", {"exposure", "placement"},
         "Files an unauthenticated request can fetch directly."),
        ("Privilege escalation", {"privesc", "permissions"},
         "Local footholds that can be widened to root or host access."),
        ("Supply chain", {"supply-chain", "dependency"},
         "Third-party code paths that can introduce attacker-controlled logic."),
        ("Infrastructure misconfiguration", {"iac", "kubernetes", "terraform", "cloud", "container"},
         "Deployment settings that weaken isolation or expose services."),
        ("Server configuration", {"webserver", "config"},
         "Web-tier settings that change what is served and to whom."),
    ]

    output = []
    for name, tags, description in surfaces:
        matched = [f for f in result.findings if tags & set(f.tags)]
        if not matched:
            continue
        worst = Severity.worst(f.severity for f in matched)
        output.append({
            "name": name,
            "description": description,
            "severity": worst.value,
            "color": SEVERITY_COLORS[worst],
            "finding_count": len(matched),
            "paths": sorted({f.path for f in matched})[:15],
            "rules": sorted({f.rule_id for f in matched}),
        })

    output.sort(key=lambda s: (Severity(s["severity"]).rank, -s["finding_count"]))
    return {"schema": "pyrasec.attack-surface/1", "surfaces": output}
