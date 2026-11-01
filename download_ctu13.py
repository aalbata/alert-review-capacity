"""Download the 13 CTU-13 labeled bidirectional flow files and verify their SHA-256 checksums.

Source: Stratosphere Laboratory, Czech Technical University in Prague,
https://www.stratosphereips.org/datasets-ctu13 (files served from mcfp.felk.cvut.cz, folder
detailed-bidirectional-flow-labels of each capture). The files are about 2.7 GB in total and are
fetched with parallel range requests. Files already present with the expected checksum are skipped.
"""

import argparse
import concurrent.futures as cf
import hashlib
import urllib.request
from pathlib import Path

BASE = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-{n}/detailed-bidirectional-flow-labels/{f}"
FILES = {
    42: ("capture20110810.binetflow", "be09f7f6a06beef0134152dc88bff85f0027db4affe07b3fbe956bbb49be5430"),
    43: ("capture20110811.binetflow", "7b5bbca3cc8acc5ac13153ec96cf0168a9e2e8ba084b36576e9853ffebb72dca"),
    44: ("capture20110812.binetflow", "0ebcd1df082bb5f85f8254c3857b02fdbb597c9b2ee7c50f908cc24ca92c0054"),
    45: ("capture20110815.binetflow", "30353fcffe971e97839ccffaa1675535490420f1ba1f65e5c90f6a815a8ab2c0"),
    46: ("capture20110815-2.binetflow", "ef5c9ed6895d4ca5aec723449dae30054ccd1f6b091713a52ffcb681ff78a02c"),
    47: ("capture20110816.binetflow", "801800eeda9a5a44868b1e3e492f93dc6d52b5d14566c1d8431c9e85d0d2adaa"),
    48: ("capture20110816-2.binetflow", "df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680"),
    49: ("capture20110816-3.binetflow", "c3884b629e152e3144c2d7250d01939c199fa8a135a88f0c775ee3be0237f01f"),
    50: ("capture20110817.binetflow", "c8de257b6207ec3624467da62e91841073256fbdad5434db5eb5667588178bab"),
    51: ("capture20110818.binetflow", "840a7030d57cb965a4e6e19c61e89b20647a4aefe5608c2da90623710e7cd74f"),
    52: ("capture20110818-2.binetflow", "cee542d4b5efe4fa1cd59b87ece5aaea9a13d8f0abe56cd07cee31590736428c"),
    53: ("capture20110819.binetflow", "1098f0addacedc321c7baefad63ef0d9a0f26630d0155087d37e8da770dd9f2e"),
    54: ("capture20110815-3.binetflow", "d1d8aaea885870c64615261bd78ebf569e7d5b41adab2a6f3008702f4ded4503"),
}
CHUNK = 8 * 1024 * 1024


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def size_of(url):
    with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=60) as r:
        return int(r.headers["Content-Length"])


def fetch_range(url, path, start, end):
    for _ in range(5):
        try:
            req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            if len(data) == end - start + 1:
                with open(path, "r+b") as f:
                    f.seek(start)
                    f.write(data)
                return
        except OSError:
            continue
    raise RuntimeError(f"failed {url} {start}-{end}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--workers", type=int, default=32)
    args = ap.parse_args()
    args.outdir.mkdir(parents=True, exist_ok=True)
    jobs, targets = [], []
    for n, (name, digest) in FILES.items():
        path = args.outdir / f"s{n}_{name}"
        targets.append((path, digest))
        if path.exists() and sha256(path) == digest:
            continue
        url = BASE.format(n=n, f=name)
        total = size_of(url)
        with open(path, "wb") as fh:
            fh.truncate(total)
        jobs += [(url, path, s, min(s + CHUNK, total) - 1) for s in range(0, total, CHUNK)]
    with cf.ThreadPoolExecutor(args.workers) as ex:
        list(ex.map(lambda j: fetch_range(*j), jobs))
    bad = [p.name for p, d in targets if sha256(p) != d]
    if bad:
        raise SystemExit(f"checksum mismatch: {', '.join(bad)}")
    print(f"all {len(targets)} files present and verified")


if __name__ == "__main__":
    main()
