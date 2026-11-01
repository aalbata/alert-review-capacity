"""Write or check SHA-256 sums of every generated output (results, derived tables, figures).

  python checksums.py                        write SHA256SUMS
  python checksums.py --check                compare every output with SHA256SUMS and report differences
  python checksums.py --check --present-only compare only the outputs that exist (no dataset download)
"""

import argparse
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PATTERNS = ["calculations.csv", "backlog.csv", "results/*.csv", "data/*.csv", "data/*.csv.gz",
            "figures/*.pdf", "figures/*.png", "figures/*.svg"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def outputs():
    files = sorted({p for pat in PATTERNS for p in HERE.glob(pat)})
    return {p.relative_to(HERE).as_posix(): sha256(p) for p in files}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--present-only", action="store_true")
    args = ap.parse_args()
    current = outputs()
    target = HERE / "SHA256SUMS"
    if not args.check:
        target.write_text("".join(f"{d}  {name}\n" for name, d in current.items()), encoding="utf-8")
        print(f"wrote {len(current)} checksums")
        return
    expected = dict(line.split("  ", 1)[::-1] for line in target.read_text(encoding="utf-8").splitlines())
    expected = {k.strip(): v for k, v in expected.items()}
    if args.present_only:
        expected = {k: d for k, d in expected.items() if k in current}
    missing = sorted(set(expected) - set(current))
    differ = sorted(k for k in expected.keys() & current.keys() if expected[k] != current[k])
    extra = sorted(set(current) - set(expected))
    for k in missing:
        print("missing ", k)
    for k in differ:
        print("differs ", k)
    for k in extra:
        print("unlisted", k)
    print(f"{len(expected) - len(missing) - len(differ)} of {len(expected)} outputs identical")
    sys.exit(1 if missing or differ else 0)


if __name__ == "__main__":
    main()
