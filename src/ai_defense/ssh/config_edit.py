"""Pure helpers for in-place config edits via a managed, marker-delimited block.

For files that have no conf.d drop-in directory, a mitigation edits the file in
place — but only inside a block it owns, delimited by markers:

    # >>> ai-defense:<marker> >>>
    <managed lines>
    # <<< ai-defense:<marker> <<<

Keeping the block logic pure (string in → string out) makes it idempotent
(re-applying the same block is a no-op) and trivially reversible (removing the
block restores the rest of the file), and unit-testable without SSH. The
executor layers read / backup / diff / write / validate / reload and
restore-on-failure on top.
"""

from __future__ import annotations


def markers(marker: str) -> tuple[str, str]:
    return (f"# >>> ai-defense:{marker} >>>", f"# <<< ai-defense:{marker} <<<")


def _bounds(lines: list[str], marker: str) -> tuple[int, int] | None:
    begin, end = markers(marker)
    if begin in lines and end in lines:
        i, j = lines.index(begin), lines.index(end)
        if i < j:
            return i, j
    return None


def ensure_block(content: str, marker: str, body: str) -> str:
    """Insert or replace the managed block so it contains exactly ``body``.
    Idempotent: ``ensure_block(ensure_block(x)) == ensure_block(x)``."""
    begin, end = markers(marker)
    block = [begin, *body.rstrip("\n").split("\n"), end]
    lines = content.splitlines()
    span = _bounds(lines, marker)
    if span is not None:
        i, j = span
        new = lines[:i] + block + lines[j + 1:]
    else:
        sep = [""] if (lines and lines[-1].strip()) else []
        new = lines + sep + block
    return "\n".join(new) + "\n"


def remove_block(content: str, marker: str) -> str:
    """Remove the managed block (and a blank line it leaves behind). No-op if the
    block isn't present."""
    lines = content.splitlines()
    span = _bounds(lines, marker)
    if span is None:
        return content
    i, j = span
    new = lines[:i] + lines[j + 1:]
    while new and not new[-1].strip():      # trim a trailing blank
        new.pop()
    return "\n".join(new) + "\n" if new else ""
