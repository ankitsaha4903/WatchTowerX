# remove_extra_set_page_config.py
from pathlib import Path
import re

ROOT = Path.cwd()
APP = ROOT / "app"
PAGES = APP / "pages"

def remove_from_file(p: Path):
    text = p.read_text(encoding="utf8")
    # find set_page_config lines
    new = re.sub(r'^[ \t]*st\.set_page_config\(.*\)\s*$\n?', '', text, flags=re.MULTILINE)
    if new != text:
        p.write_text(new, encoding="utf8")
        print("Removed set_page_config from:", p)
    else:
        print("No change:", p)

# Keep set_page_config in app/main.py -> do NOT remove from main
main_file = APP / "main.py"
if not main_file.exists():
    print("Warning: app/main.py not found in", APP)
else:
    print("Keeping set_page_config in", main_file)

# Remove from pages
if PAGES.exists() and PAGES.is_dir():
    for f in PAGES.glob("*.py"):
        remove_from_file(f)
else:
    print("No pages directory:", PAGES)

# Also scan other python files inside app/ (but skip main)
for f in APP.glob("*.py"):
    if f.name == "main.py" or f.name == "__init__.py":
        continue
    remove_from_file(f)

print("Done. Please verify app/main.py contains a single st.set_page_config at the top.")
