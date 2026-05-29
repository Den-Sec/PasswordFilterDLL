#!/usr/bin/env python3
"""Offline builder for the PasswordFilterDLL breach Bloom filter.

Reads the Have I Been Pwned "Pwned Passwords" dump (or a plaintext wordlist) and produces
a ``breach.bloom`` file in the exact "PWBLOOM1" format the C++ reader (src/core/bloom.*)
consumes. This runs entirely offline and needs only the Python standard library, so the
artifact can be (re)built without the C++ toolchain.

FILE FORMAT  ("PWBLOOM1") - little-endian, must match src/core/include/pwfilter/bloom.hpp:
    0   8   magic   = b"PWBLOOM1"
    8   4   version = 1            (uint32)
    12  4   k                      (uint32)
    16  8   m_bits                 (uint64)
    24  8   n_items                (uint64)
    32  4   scheme  = 1            (uint32)
    36  28  reserved (zero)
    64  ..  bitset, ceil(m/8) bytes; bit i -> byte[i//8], mask 1 << (i % 8)

PROBING (Kirsch-Mitzenmacher double hashing over the SHA-1 digest):
    h1 = int.from_bytes(digest[0:8],  "little")
    h2 = int.from_bytes(digest[8:16], "little")
    for i in range(k):  idx = ((h1 + i * h2) & MASK64) % m_bits

Typical usage
-------------
Build from the HIBP SHA-1 "ordered by hash" dump (lines "HASH:count"); pass --count to
skip the line-counting pass on the ~38 GB file:

    python build_bloom.py pwnedpasswords.txt -o breach.bloom --count 1300000000 --fp 0.001

Build from a plaintext wordlist (each line is a password; SHA-1 of its UTF-8 is taken):

    python build_bloom.py wordlist.txt --plain -o sample.bloom --fp 0.001
"""

import argparse
import hashlib
import math
import struct
import sys

MAGIC = b"PWBLOOM1"
VERSION = 1
SCHEME_SHA1_LE = 1
HEADER_SIZE = 64
MASK64 = (1 << 64) - 1


def compute_params(n, p):
    """Optimal (m_bits, k); mirrors BloomBuilder::ComputeParams in the C++ core."""
    if n <= 0:
        n = 1
    if not (0.0 < p < 1.0):
        p = 0.001
    ln2 = math.log(2.0)
    m_real = -n * math.log(p) / (ln2 * ln2)
    m_bits = int(math.ceil(m_real))
    if m_bits < 8:
        m_bits = 8
    m_bits = ((m_bits + 7) // 8) * 8  # whole bytes
    # round half away from zero, to match C++ std::lround
    k = int(math.floor((m_bits / n) * ln2 + 0.5))
    k = max(1, min(64, k))
    return m_bits, k


def iter_digests(path, plain, encoding):
    """Yield 20-byte SHA-1 digests from the input file.

    plain=True : each non-empty line is a password -> SHA-1(UTF-8(password)).
    plain=False: HIBP dump lines "HASH[:count]" -> the 40-hex SHA-1 is used directly.
    """
    with open(path, "r", encoding=encoding, errors="replace", newline="") as f:
        for raw in f:
            line = raw.rstrip("\r\n")
            if not line:
                continue
            if plain:
                yield hashlib.sha1(line.encode("utf-8")).digest()
            else:
                hexhash = line.split(":", 1)[0].strip()
                if len(hexhash) != 40:
                    continue
                try:
                    yield bytes.fromhex(hexhash)
                except ValueError:
                    continue


def count_items(path, plain, encoding):
    n = 0
    for _ in iter_digests(path, plain, encoding):
        n += 1
    return n


def set_bits(bitset, digest, m_bits, k):
    h1 = int.from_bytes(digest[0:8], "little")
    h2 = int.from_bytes(digest[8:16], "little")
    for i in range(k):
        idx = ((h1 + i * h2) & MASK64) % m_bits
        bitset[idx >> 3] |= 1 << (idx & 7)


def maybe_contains(bitset, digest, m_bits, k):
    h1 = int.from_bytes(digest[0:8], "little")
    h2 = int.from_bytes(digest[8:16], "little")
    for i in range(k):
        idx = ((h1 + i * h2) & MASK64) % m_bits
        if not (bitset[idx >> 3] & (1 << (idx & 7))):
            return False
    return True


def build(args):
    n = args.count
    if n is None:
        print("Counting items (pass --count to skip this pass)...", file=sys.stderr)
        n = count_items(args.input, args.plain, args.encoding)
        print(f"  {n} items", file=sys.stderr)
    if n <= 0:
        print("error: no items to insert", file=sys.stderr)
        return 2

    m_bits, k = compute_params(n, args.fp)
    nbytes = m_bits // 8
    print(
        f"Sizing: n={n} fp={args.fp} -> m={m_bits} bits ({nbytes/1e9:.3f} GB), k={k}",
        file=sys.stderr,
    )

    bitset = bytearray(nbytes)
    inserted = 0
    for digest in iter_digests(args.input, args.plain, args.encoding):
        set_bits(bitset, digest, m_bits, k)
        inserted += 1
        if inserted % 5_000_000 == 0:
            print(f"  inserted {inserted}/{n}", file=sys.stderr)

    header = struct.pack(
        "<8sIIQQI", MAGIC, VERSION, k, m_bits, inserted, SCHEME_SHA1_LE
    ) + b"\x00" * (HEADER_SIZE - 36)
    assert len(header) == HEADER_SIZE

    with open(args.output, "wb") as out:
        out.write(header)
        out.write(bitset)
    print(f"Wrote {args.output} ({HEADER_SIZE + nbytes} bytes, {inserted} items)", file=sys.stderr)

    if args.selftest:
        misses = 0
        checked = 0
        for digest in iter_digests(args.input, args.plain, args.encoding):
            if not maybe_contains(bitset, digest, m_bits, k):
                misses += 1
            checked += 1
            if checked >= 100_000:
                break
        print(f"Selftest: {checked - misses}/{checked} found, {misses} false negatives",
              file=sys.stderr)
        if misses != 0:
            print("error: false negatives detected (bug in builder)", file=sys.stderr)
            return 3
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the PasswordFilterDLL breach Bloom filter.")
    ap.add_argument("input", help="HIBP dump (HASH:count per line) or plaintext wordlist")
    ap.add_argument("-o", "--output", required=True, help="output .bloom path")
    ap.add_argument("--plain", action="store_true",
                    help="treat each input line as a password (SHA-1 of its UTF-8)")
    ap.add_argument("--fp", type=float, default=0.001, help="target false-positive rate (default 0.001)")
    ap.add_argument("--count", type=int, default=None,
                    help="expected item count (skips the counting pass on huge dumps)")
    ap.add_argument("--encoding", default="utf-8", help="input file encoding (default utf-8)")
    ap.add_argument("--selftest", action="store_true",
                    help="after building, verify a sample of inputs are found")
    args = ap.parse_args(argv)
    return build(args)


if __name__ == "__main__":
    sys.exit(main())
