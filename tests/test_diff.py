from pathlib import Path

from vtx_crs.core.diff import apply_unified_diff, parse_unified_diff

ORIGINAL = """import os

def run(cmd):
    result = os.system(cmd)
    return result
"""

FIXED = """import subprocess

def run(cmd):
    result = subprocess.run(cmd, shell=False)
    return result
"""


def test_parse_unified_diff(tmp_path: Path) -> None:
    diff = """--- a/vuln.py
+++ b/vuln.py
@@ -1,5 +1,5 @@
-import os
+import subprocess
 
-def run(cmd):
-    result = os.system(cmd)
+def run(cmd):
+    result = subprocess.run(cmd, shell=False)
     return result
"""
    files = parse_unified_diff(diff)
    assert len(files) == 1
    assert files[0].target_path == "vuln.py"
    assert len(files[0].hunks) == 1


def test_apply_replacement(tmp_path: Path) -> None:
    target = tmp_path / "vuln.py"
    target.write_text(ORIGINAL, encoding="utf-8")
    diff = """--- a/vuln.py
+++ b/vuln.py
@@ -1,5 +1,5 @@
-import os
+import subprocess
 
-def run(cmd):
-    result = os.system(cmd)
+def run(cmd):
+    result = subprocess.run(cmd, shell=False)
     return result
"""
    result = apply_unified_diff(diff, base_dir=tmp_path)
    assert result.success, result.message
    assert result.changed_files == ["vuln.py"]
    assert target.read_text(encoding="utf-8") == FIXED


def test_apply_interleaved_removed_lines(tmp_path: Path) -> None:
    """Removed lines sit between context lines in the original; the applier
    must match the full original block, not just context lines."""
    target = tmp_path / "a.txt"
    target.write_text("one\ntwo\nthree\nfour\nfive\n", encoding="utf-8")
    diff = """--- a/a.txt
+++ b/a.txt
@@ -1,5 +1,5 @@
 one
-two
 three
+two-and-a-half
 four
 five
"""
    result = apply_unified_diff(diff, base_dir=tmp_path)
    assert result.success, result.message
    assert target.read_text(encoding="utf-8") == "one\nthree\ntwo-and-a-half\nfour\nfive\n"


def test_apply_multiple_hunks_with_drift(tmp_path: Path) -> None:
    """Hunk 1 removes a line, so hunk 2's original line numbers no longer
    match the modified file — the fuzzy matcher must recover the position."""
    target = tmp_path / "m.txt"
    target.write_text("a\nb\nc\nd\ne\nf\n", encoding="utf-8")
    diff = """--- a/m.txt
+++ b/m.txt
@@ -1,2 +1,1 @@
-a
 b
@@ -5,2 +5,2 @@
 e
-f
+F
"""
    result = apply_unified_diff(diff, base_dir=tmp_path)
    assert result.success, result.message
    assert target.read_text(encoding="utf-8") == "b\nc\nd\ne\nF\n"


def test_apply_multi_file(tmp_path: Path) -> None:
    (tmp_path / "one.txt").write_text("x\ny\n", encoding="utf-8")
    (tmp_path / "two.txt").write_text("p\nq\n", encoding="utf-8")
    diff = """diff --git a/one.txt b/one.txt
--- a/one.txt
+++ b/one.txt
@@ -1,2 +1,2 @@
-x
+X
 y
diff --git a/two.txt b/two.txt
--- a/two.txt
+++ b/two.txt
@@ -1,2 +1,2 @@
 p
-q
+Q
"""
    result = apply_unified_diff(diff, base_dir=tmp_path)
    assert result.success, result.message
    assert result.changed_files == ["one.txt", "two.txt"]
    assert (tmp_path / "one.txt").read_text(encoding="utf-8") == "X\ny\n"
    assert (tmp_path / "two.txt").read_text(encoding="utf-8") == "p\nQ\n"


def test_dry_run_does_not_modify(tmp_path: Path) -> None:
    target = tmp_path / "vuln.py"
    target.write_text(ORIGINAL, encoding="utf-8")
    diff = """--- a/vuln.py
+++ b/vuln.py
@@ -1,5 +1,5 @@
-import os
+import subprocess
"""
    result = apply_unified_diff(diff, base_dir=tmp_path, dry_run=True)
    assert result.success
    assert result.changed_files == ["vuln.py"]
    assert target.read_text(encoding="utf-8") == ORIGINAL


def test_rejected_hunk_when_context_mismatch(tmp_path: Path) -> None:
    target = tmp_path / "vuln.py"
    target.write_text(ORIGINAL, encoding="utf-8")
    diff = """--- a/vuln.py
+++ b/vuln.py
@@ -1,5 +1,5 @@
 this line does not exist
+neither does this
"""
    result = apply_unified_diff(diff, base_dir=tmp_path)
    assert not result.success
    assert result.rejected_hunks == 1


def test_pure_addition(tmp_path: Path) -> None:
    target = tmp_path / "add.txt"
    target.write_text("line1\nline2\n", encoding="utf-8")
    diff = """--- a/add.txt
+++ b/add.txt
@@ -1,2 +1,3 @@
 line1
 line2
+line3
"""
    result = apply_unified_diff(diff, base_dir=tmp_path)
    assert result.success, result.message
    assert target.read_text(encoding="utf-8") == "line1\nline2\nline3\n"


def test_pure_addition_after_removal_hunk(tmp_path: Path) -> None:
    """A pure-addition hunk below a removal hunk must not drift (bottom-up apply)."""
    target = tmp_path / "m.txt"
    target.write_text("a\nb\nc\nd\ne\nf\n", encoding="utf-8")
    diff = """--- a/m.txt
+++ b/m.txt
@@ -1,2 +1,1 @@
-a
 b
@@ -4,1 +4,1 @@
 d
+DD
"""
    result = apply_unified_diff(diff, base_dir=tmp_path)
    assert result.success, result.message
    assert target.read_text(encoding="utf-8") == "b\nc\nd\nDD\ne\nf\n"


def test_patch_cannot_escape_base_dir(tmp_path: Path) -> None:
    """A crafted diff with ../../ must be rejected, not written outside the repo."""
    outside = tmp_path.parent / "escape_me.txt"
    outside.write_text("original\n", encoding="utf-8")
    diff = """--- a/../escape_me.txt
+++ b/../escape_me.txt
@@ -1,1 +1,1 @@
-original
+OWNED
"""
    result = apply_unified_diff(diff, base_dir=tmp_path)
    assert not result.success
    assert outside.read_text(encoding="utf-8") == "original\n"


def test_patch_preserves_crlf(tmp_path: Path) -> None:
    target = tmp_path / "win.txt"
    target.write_bytes(b"one\r\ntwo\r\n")
    diff = """--- a/win.txt
+++ b/win.txt
@@ -1,2 +1,2 @@
 one
-two
+THREE
"""
    result = apply_unified_diff(diff, base_dir=tmp_path)
    assert result.success, result.message
    assert target.read_bytes() == b"one\r\nTHREE\r\n"
