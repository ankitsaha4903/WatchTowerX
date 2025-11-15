# run.py
from __future__ import annotations
import os, sys, subprocess, socket
from pathlib import Path

# --- Config defaults (can override via env) ---
ADDRESS = os.getenv("VL_ADDRESS", "192.168.150.241")       # listen on all interfaces
PORT    = int(os.getenv("VL_PORT", "8503"))        # default port
APP     = os.getenv("VL_APP", "app/main.py")       # streamlit entry

BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"

def find_cert_pair() -> tuple[str | None, str | None]:
    """
    Look for a mkcert pair in ./certs:
      - Prefer files that match the host's LAN IP(s)
      - Otherwise pick any *.pem with a matching *-key.pem
    """
    if not CERTS_DIR.exists():
        return (None, None)
    # This machine's IPs (for best-match cert)
    ips = set()
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except Exception:
        pass

    pem_files = list(CERTS_DIR.glob("*.pem"))
    key_map = {p.stem.replace("-key", ""): p for p in CERTS_DIR.glob("*-key.pem")}
    # prefer an IP-matching cert
    for pem in pem_files:
        stem = pem.stem
        if stem in ips and f"{stem}-key" in {k.stem for k in key_map.values()}:
            key = CERTS_DIR / f"{stem}-key.pem"
            if key.exists():
                return (str(pem), str(key))
    # else pick the first pair that matches stem
    for pem in pem_files:
        key = CERTS_DIR / f"{pem.stem}-key.pem"
        if key.exists():
            return (str(pem), str(key))
    return (None, None)

def main() -> int:
    cert, key = find_cert_pair()
    args = [
        sys.executable, "-m", "streamlit", "run", str(BASE_DIR / APP),
        "--server.address", ADDRESS,
        "--server.port", str(PORT),
    ]
    if cert and key:
        args += ["--server.sslCertFile", cert, "--server.sslKeyFile", key]

    # Recommended: let Streamlit keep XSRF/CORS defaults (no cross-origin errors)
    print("Launching Streamlit with:", " ".join(args))
    return subprocess.call(args)

if __name__ == "__main__":
    raise SystemExit(main())
