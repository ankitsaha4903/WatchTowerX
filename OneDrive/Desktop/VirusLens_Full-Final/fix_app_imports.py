# fix_app_imports.py
"""
Auto-fix for Streamlit app imports and __future__ placement.

- Creates app/__init__.py if missing
- For each .py in app/ and app/pages/:
  - Move any "from __future__ import ..." lines to the top (right after optional module docstring)
  - Insert a robust sys.path guard (so `import app` resolves) right after future imports
  - Leave the rest of file unchanged
Run from project root: python fix_app_imports.py
"""

from pathlib import Path
import re
import sys

ROOT = Path.cwd()
APP_DIR = ROOT / "app"
PAGES_DIR = APP_DIR / "pages"

if not APP_DIR.exists() or not APP_DIR.is_dir():
    print("ERROR: app/ directory not found in current working directory:", ROOT)
    sys.exit(1)

# create __init__.py if missing
init_file = APP_DIR / "__init__.py"
if not init_file.exists():
    init_file.write_text('"""app package for VirusLens UI"""\\n__all__ = []\\n', encoding="utf8")
    print("Created app/__init__.py")
else:
    print("app/__init__.py already exists")

# sys.path guard snippet to insert (keeps idempotent marker)
SYS_PATH_SNIPPET = (
    "# BEGIN: ensure project root is importable\n"
    "import sys\n"
    "from pathlib import Path\n"
    "ROOT = Path(__file__).resolve().parents[1]\n"
    "if str(ROOT) not in sys.path:\n"
    "    sys.path.insert(0, str(ROOT))\n"
    "# END: ensure project root is importable\n"
)

# function to process a single file
def process_file(p: Path):
    text = p.read_text(encoding="utf8")
    original = text

    # Collect future import lines
    future_lines = re.findall(r'^[ \t]*from __future__ import [^\n]+', text, flags=re.MULTILINE)
    # remove them from wherever they are
    text_no_future = re.sub(r'^[ \t]*from __future__ import [^\n]+\n?', '', text, flags=re.MULTILINE)

    # detect existing sys.path guard presence (marker)
    has_guard = "BEGIN: ensure project root is importable" in text_no_future

    # preserve module docstring if present
    m = re.match(r'^(?P<doc>(?:(?:[uU]?)?""".*?"""|\'\'\'.*?\'\'\')\s*\n)?(?P<body>.*)$', text_no_future, flags=re.DOTALL)
    doc = m.group("doc") or ""
    body = m.group("body") or ""

    # compose new header: docstring + future imports + sys.path guard (if missing) + rest
    unique_future = []
    for line in future_lines:
        if line not in unique_future:
            unique_future.append(line)

    future_block = ""
    if unique_future:
        future_block = "\n".join(unique_future) + "\n\n"

    guard_block = ""
    if not has_guard:
        guard_block = SYS_PATH_SNIPPET + "\n"

    new_text = doc + future_block + guard_block + body

    if new_text != original:
        p.write_text(new_text, encoding="utf8")
        print(f"Patched: {p}")
    else:
        print(f"No changes: {p}")

# Process files in app/ and app/pages/
targets = []
for p in APP_DIR.glob("*.py"):
    targets.append(p)
if PAGES_DIR.exists():
    for p in PAGES_DIR.glob("*.py"):
        targets.append(p)

if not targets:
    print("No Python files found under app/ or app/pages/")
    sys.exit(0)

for t in targets:
    process_file(t)

print("Done. Please restart Streamlit (streamlit run app/main.py).")
