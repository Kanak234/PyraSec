"""Filesystem walker.

Step 1 of the pipeline: map every file, folder and permission. Nothing here
knows what a vulnerability is — it just produces FileRecords for the rule
engine to chew on. Kept dependency-free and iterative (no recursion) so a
200k-file monorepo doesn't blow the stack.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .models import FileRecord

# Directories that are never worth walking. Skipping them is what makes the
# difference between a 40-second scan and a 4-second one on a real repo.
DEFAULT_SKIP_DIRS = {
    "node_modules", ".git", ".hg", ".svn", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", ".gradle", "target", "vendor",
    ".terraform", ".idea", ".vscode", "site-packages", ".cache",
    "coverage", ".nyc_output", "bower_components", ".serverless",
}

# We still want to KNOW these exist (a committed .git dir is itself a finding),
# so the walker records the directory but does not descend into it.
NOTE_ONLY_DIRS = {".git", ".terraform", ".aws", ".ssh"}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svgz",
    ".pdf", ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".webm",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".class",
    ".pyc", ".pyo", ".wasm", ".jar", ".war", ".db", ".sqlite", ".sqlite3",
}

DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB — beyond this, metadata only


@dataclass
class WalkConfig:
    """Everything tunable about a walk, so scans are reproducible."""

    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_depth: int = 40
    follow_symlinks: bool = False
    skip_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_SKIP_DIRS))
    exclude_globs: list[str] = field(default_factory=list)
    include_globs: list[str] = field(default_factory=list)
    hash_files: bool = True
    respect_gitignore: bool = True


class Walker:
    """Produces FileRecords for a directory tree."""

    def __init__(self, root: str | os.PathLike[str], config: WalkConfig | None = None):
        self.root = Path(root).resolve()
        self.config = config or WalkConfig()
        self.errors: list[str] = []
        self.skipped = 0
        self._gitignore = (
            _load_gitignore(self.root) if self.config.respect_gitignore else []
        )

    # -- public ------------------------------------------------------------

    def walk(self) -> list[FileRecord]:
        """Breadth-first walk. Returns records sorted by path for determinism."""
        if not self.root.exists():
            raise FileNotFoundError(f"scan root does not exist: {self.root}")
        if not self.root.is_dir():
            raise NotADirectoryError(f"scan root is not a directory: {self.root}")

        records: list[FileRecord] = []
        queue: list[tuple[Path, int]] = [(self.root, 0)]

        while queue:
            directory, depth = queue.pop(0)
            if depth > self.config.max_depth:
                continue
            try:
                entries = sorted(os.scandir(directory), key=lambda e: e.name)
            except (PermissionError, OSError) as exc:
                self.errors.append(f"{directory}: {exc}")
                continue

            for entry in entries:
                try:
                    record = self._record_for(entry, depth)
                except (PermissionError, OSError) as exc:
                    self.errors.append(f"{entry.path}: {exc}")
                    continue
                if record is None:
                    self.skipped += 1
                    continue

                records.append(record)

                if record.is_dir and not (record.is_symlink and not self.config.follow_symlinks):
                    if entry.name in self.config.skip_dirs or entry.name in NOTE_ONLY_DIRS:
                        continue
                    queue.append((Path(entry.path), depth + 1))

        records.sort(key=lambda r: r.path)
        return records

    # -- internals ---------------------------------------------------------

    def _record_for(self, entry: os.DirEntry[str], depth: int) -> FileRecord | None:
        rel = os.path.relpath(entry.path, self.root).replace(os.sep, "/")
        if self._is_excluded(rel, entry.is_dir(follow_symlinks=False)):
            return None

        st = entry.stat(follow_symlinks=False)
        is_dir = entry.is_dir(follow_symlinks=False)
        is_link = entry.is_symlink()

        if not is_dir and self.config.include_globs:
            if not any(fnmatch.fnmatch(rel, g) for g in self.config.include_globs):
                return None

        ext = ""
        if not is_dir:
            _, _, tail = entry.name.rpartition(".")
            ext = f".{tail.lower()}" if tail and tail != entry.name else ""

        record = FileRecord(
            path=rel,
            abs_path=entry.path,
            size=st.st_size,
            mode=stat.S_IMODE(st.st_mode),
            depth=depth,
            is_dir=is_dir,
            is_symlink=is_link,
            mtime=st.st_mtime,
            extension=ext,
            owner_uid=getattr(st, "st_uid", -1),
        )

        if not is_dir and not is_link:
            record.is_binary = self._looks_binary(entry.path, ext, st.st_size)
            if self.config.hash_files and st.st_size <= self.config.max_file_size:
                record.sha256 = _sha256(entry.path)

        return record

    def _is_excluded(self, rel: str, is_dir: bool) -> bool:
        for pattern in self.config.exclude_globs:
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(f"{rel}/", pattern):
                return True
        for pattern in self._gitignore:
            if _gitignore_match(rel, pattern, is_dir):
                return True
        return False

    def _looks_binary(self, path: str, ext: str, size: int) -> bool:
        if ext in BINARY_EXTENSIONS:
            return True
        if size == 0:
            return False
        try:
            with open(path, "rb") as fh:
                chunk = fh.read(4096)
        except OSError:
            return True
        if b"\x00" in chunk:
            return True
        # High proportion of bytes outside the printable/UTF-8 range.
        text_chars = bytes(range(32, 127)) + b"\n\r\t\f\b"
        nontext = sum(1 for b in chunk if b not in text_chars and b < 128)
        return nontext / max(len(chunk), 1) > 0.30


def read_text(record: FileRecord, max_bytes: int = DEFAULT_MAX_FILE_SIZE) -> str | None:
    """Read a file as text, or None if it is binary / unreadable / too large."""
    if record.is_dir or record.is_binary or record.is_symlink:
        return None
    if record.size > max_bytes:
        return None
    try:
        with open(record.abs_path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _load_gitignore(root: Path) -> list[str]:
    """Minimal .gitignore support: literal and glob patterns, negation ignored.

    Deliberately conservative — when in doubt we scan the file rather than
    skip it. A scanner that silently skips is worse than one that is noisy.
    """
    patterns: list[str] = []
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return patterns
    try:
        for raw in gitignore.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            patterns.append(line)
    except OSError:
        pass
    return patterns


def _gitignore_match(rel: str, pattern: str, is_dir: bool) -> bool:
    dir_only = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    if dir_only and not is_dir:
        return False
    anchored = pattern.startswith("/")
    pattern = pattern.lstrip("/")

    if anchored:
        return fnmatch.fnmatch(rel, pattern) or rel.startswith(pattern + "/")
    if fnmatch.fnmatch(rel, pattern):
        return True
    # Unanchored patterns match at any depth.
    return any(fnmatch.fnmatch(part, pattern) for part in rel.split("/"))
