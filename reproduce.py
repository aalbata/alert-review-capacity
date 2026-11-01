"""Reproduce every number and figure.

Full path, from the raw CTU-13 files:
  1. review_capacity.py      worked example, calculations.csv, backlog.csv, Figure 1
  2. download_ctu13.py       download the 13 raw flow files into RAW_DIR and verify their checksums
  3. ctu13_experiment.py     build the host-window tables in data/ and write results/
  4. ctu13_figures.py        Figures 2 and 3
  5. checksums.py --check    compare every output with SHA256SUMS

Fast path, without the dataset: steps 1 and 4 from the shipped result files, then a check of the
outputs that exist.

Usage: python reproduce.py --raw RAW_DIR [--skip-download] [--no-check]
       python reproduce.py --fast
"""

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(*args):
    print("+", " ".join(str(a) for a in args), flush=True)
    subprocess.run([sys.executable, *map(str, args)], check=True, cwd=HERE)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--raw", type=Path, help="folder for the 13 raw CTU-13 flow files")
    mode.add_argument("--fast", action="store_true", help="regenerate from the shipped result files only")
    ap.add_argument("--skip-download", action="store_true", help="use files already in RAW_DIR")
    ap.add_argument("--no-check", action="store_true", help="do not compare outputs with SHA256SUMS")
    args = ap.parse_args()
    run(HERE / "review_capacity.py")
    if args.fast:
        run(HERE / "ctu13_figures.py")
        if not args.no_check:
            run(HERE / "checksums.py", "--check", "--present-only")
        return
    if not args.skip_download:
        run(HERE / "download_ctu13.py", args.raw.resolve())
    run(HERE / "ctu13_experiment.py", "--raw", args.raw.resolve())
    run(HERE / "ctu13_figures.py")
    if not args.no_check:
        run(HERE / "checksums.py", "--check")


if __name__ == "__main__":
    main()
