# auto_patch_scan.py
"""
Auto-patch scan.py to call record_search(...) when a scan completes.
This script:
- Backs up scan.py -> scan.py.bak_timestamp
- Inserts "from app.db import record_search" at top if missing
- Attempts to find likely successful-scan return points and insert a call:
    record_search("url", target_variable, summary="...") 
  It tries a few heuristics: looks for 'vt_analysis_id', 'result_json', 'submit', 'submit_url',
  or places where 'return' follows success messages.

**Review the patched file after running. If anything looks wrong, restore from backup.**
"""
import re
from pathlib import Path
from datetime import datetime

ROOT = Path.cwd()
SCAN_FILE = ROOT / "scan.py"

if not SCAN_FILE.exists():
    print("scan.py not found at:", SCAN_FILE)
    raise SystemExit(1)

text = SCAN_FILE.read_text(encoding="utf8")
backup = SCAN_FILE.with_name(f"scan.py.bak_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}")
backup.write_text(text, encoding="utf8")
print("Backup written to:", backup)

# 1) Ensure import exists
import_marker = "from app.db import record_search"
if import_marker not in text:
    # try to insert after other imports (after the last import statement)
    # find last import line
    last_import = 0
    for m in re.finditer(r'^(?:from\s+\S+\s+import\s+.*|import\s+.*)', text, flags=re.MULTILINE):
        last_import = m.end()
    # insert after that position
    new_text = text[:last_import] + "\n" + import_marker + "\n" + text[last_import:]
    text = new_text
    print("Inserted record_search import")
else:
    print("record_search import already present")

# 2) Heuristic injection points
# We'll look for places that indicate a successful run: patterns like "vt_analysis_id", "result_json",
# or "scan completed" or "status = 'completed'". For each matched block, we will insert a record_search call
# referencing a likely variable name for the target (target, url, input_url, query, filepath).
#
# The insertion uses a tolerant form that checks variable existence at runtime:
# try:
#     _target_for_history = locals().get('target') or locals().get('url') or locals().get('query') or None
#     if _target_for_history:
#         record_search('url', _target_for_history, summary=f'vt_id={vt_analysis_id}' if 'vt_analysis_id' in locals() else None)
# except Exception:
#     pass
#
# We search for candidate insertion points (return statements in functions with 'vt_analysis_id' nearby).

def safe_record_snippet():
    return (
        "    # --- auto-inserted history recording (VirusLens) ---\n"
        "    try:\n"
        "        _target_for_history = None\n"
        "        for _k in ('target','url','input_url','query','filepath','file_path'):\n"
        "            if _k in locals() and locals()[_k]:\n"
        "                _target_for_history = locals()[_k]\n"
        "                break\n"
        "        _summary = None\n"
        "        if 'vt_analysis_id' in locals():\n"
        "            _summary = f\"vt_id={locals().get('vt_analysis_id')}\"\n"
        "        if 'result_json' in locals() and not _summary:\n"
        "            try:\n"
        "                import json\n"
        "                _summary = json.dumps(dict(list((locals().get('result_json') or {}) ) ) )[:200]\n"
        "            except Exception:\n"
        "                _summary = None\n"
        "        if _target_for_history:\n"
        "            try:\n"
        "                record_search('url' if str(_target_for_history).startswith('http') else 'file', _target_for_history, summary=_summary)\n"
        "            except Exception:\n"
        "                pass\n"
        "    except Exception:\n"
        "        pass\n"
        "    # --- end auto-inserted history recording ---\n"
    )

# Heuristic: find all occurrences of "vt_analysis_id" and inject shortly after the nearest following newline+end-of-statement
injections = 0
for m in re.finditer(r'(vt_analysis_id|result_json|status\s*=\s*[\'\"]completed[\'\"])', text):
    start = m.start()
    # find function block start (def ...:)
    func_start = text.rfind("def ", 0, start)
    if func_start == -1:
        continue
    # find indentation level by finding the first colon after def ..):
    func_head_end = text.find(":", func_start)
    if func_head_end == -1:
        continue
    # find the nearest return within the function (after m.end() up to next def or end)
    next_def = text.find("\ndef ", func_head_end)
    func_body_end = next_def if next_def != -1 else len(text)
    snippet_region = text[func_head_end:func_body_end]
    # attempt to find a return line location near the end of snippet_region
    ret_match = None
    for rm in re.finditer(r'^\s*return\b', snippet_region, flags=re.MULTILINE):
        ret_match = rm
    insert_pos = None
    if ret_match:
        # position relative to global text
        insert_pos = func_head_end + ret_match.end()
    else:
        # fallback: insert before the next blank line near the match end
        insert_pos = start + len(m.group(0))
        # jump to end of line
        insert_pos = text.find("\n", insert_pos)
        if insert_pos == -1:
            insert_pos = len(text)
        else:
            insert_pos += 1
    # Only inject if we don't already have the auto-insert marker in this function block
    func_block = text[func_head_end:func_body_end]
    if "auto-inserted history recording (VirusLens)" in func_block:
        continue
    text = text[:insert_pos] + "\n" + safe_record_snippet() + text[insert_pos:]
    injections += 1

# If no injections based on heuristics, add a safe call into a top-level function named "scan" or "submit_url" if found
if injections == 0:
    fallback_functions = ["def submit_url", "def scan_url", "def submit_scan", "def run_scan", "def scan("]
    for fname in fallback_functions:
        idx = text.find(fname)
        if idx != -1:
            # find the colon then insert after the first line in function
            head_end = text.find(":", idx)
            if head_end != -1:
                # find next newline
                next_nl = text.find("\n", head_end)
                insert_pos = next_nl + 1 if next_nl != -1 else head_end + 1
                # ensure we didn't already inject
                func_block_end = text.find("\ndef ", insert_pos)
                if func_block_end == -1:
                    func_block_end = len(text)
                func_block = text[head_end:func_block_end]
                if "auto-inserted history recording (VirusLens)" not in func_block:
                    text = text[:insert_pos] + safe_record_snippet() + text[insert_pos:]
                    injections += 1
                    print(f"Fallback injection into function starting at {idx} ({fname})")
                    break

SCAN_FILE.write_text(text, encoding="utf8")
print(f"Done. Inserted {injections} record_search snippets into scan.py. Please review {SCAN_FILE} and run tests.")
