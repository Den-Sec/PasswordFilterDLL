#!/usr/bin/env python3
"""Online HIBP k-anonymity password checker - an ADMIN/DEV tool, NOT part of the filter.

The in-LSASS DLL is strictly OFFLINE: it never makes a network call. This standalone
utility queries Have I Been Pwned's online Pwned Passwords API using the **k-anonymity**
range model - it sends only the first 5 hex characters of the password's SHA-1 hash and
checks the returned suffixes locally, so the full hash (and the password) never leave the
host. Use it to:

  * spot-check individual passwords against the live corpus, and
  * validate a locally-built breach.bloom against online truth (--bloom).

Standard library only.

Examples
--------
    python pwhibp_check.py                 # prompt (hidden input), check one password
    python pwhibp_check.py --stdin         # one password per line on stdin
    python pwhibp_check.py --bloom breach.bloom   # also query the local Bloom and compare
"""

import argparse
import getpass
import hashlib
import struct
import sys
import urllib.error
import urllib.request

API = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "PasswordFilterDLL-pwhibp-check"
MASK64 = (1 << 64) - 1
BLOOM_MAGIC = b"PWBLOOM1"
BLOOM_HEADER = 64


def hibp_count(password, padding=True):
    """Return how many times the password appears in HIBP (0 = not found), via k-anonymity."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    headers = {"User-Agent": USER_AGENT}
    if padding:
        headers["Add-Padding"] = "true"  # pad the response for extra privacy
    req = urllib.request.Request(API + prefix, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = resp.read().decode("utf-8")
    for line in body.splitlines():
        sfx, _, count = line.partition(":")
        if sfx == suffix:
            try:
                n = int(count)
            except ValueError:
                n = 1
            return n  # padded entries have count 0 and never match a real suffix
    return 0


class LocalBloom:
    """Minimal reader for the breach.bloom format (see scripts/build_bloom.py)."""

    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        if len(self.data) < BLOOM_HEADER or self.data[:8] != BLOOM_MAGIC:
            raise ValueError("not a PWBLOOM1 file")
        _, ver, self.k, self.m, _, scheme = struct.unpack("<8sIIQQI", self.data[:36])
        if ver != 1 or scheme != 1 or self.m % 8 != 0:
            raise ValueError("unsupported bloom header")
        if len(self.data) != BLOOM_HEADER + self.m // 8:
            raise ValueError("bloom size mismatch")
        self.bits = self.data[BLOOM_HEADER:]

    def maybe_contains(self, password):
        d = hashlib.sha1(password.encode("utf-8")).digest()
        h1 = int.from_bytes(d[0:8], "little")
        h2 = int.from_bytes(d[8:16], "little")
        for i in range(self.k):
            idx = ((h1 + i * h2) & MASK64) % self.m
            if not (self.bits[idx >> 3] & (1 << (idx & 7))):
                return False
        return True


def passwords_from(args):
    if args.stdin:
        for line in sys.stdin:
            line = line.rstrip("\r\n")
            if line:
                yield line
    elif args.password:
        for p in args.password:
            yield p
    else:
        yield getpass.getpass("Password (hidden): ")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Online HIBP k-anonymity checker (admin/dev tool).")
    ap.add_argument("password", nargs="*", help="password(s); omit to be prompted (hidden)")
    ap.add_argument("--stdin", action="store_true", help="read one password per line from stdin")
    ap.add_argument("--bloom", metavar="FILE", help="also query a local breach.bloom and compare")
    ap.add_argument("--no-padding", action="store_true", help="disable HIBP response padding")
    args = ap.parse_args(argv)

    if args.password:
        print("warning: passwords on the command line may be saved in shell history.",
              file=sys.stderr)

    bloom = None
    if args.bloom:
        try:
            bloom = LocalBloom(args.bloom)
        except (OSError, ValueError) as e:
            print(f"error: cannot load bloom: {e}", file=sys.stderr)
            return 2

    rc = 0
    for pw in passwords_from(args):
        try:
            n = hibp_count(pw, padding=not args.no_padding)
        except urllib.error.URLError as e:
            print(f"error: HIBP request failed: {e}", file=sys.stderr)
            return 3
        online = f"BREACHED ({n} times)" if n else "not found online"
        if bloom is not None:
            local = "present" if bloom.maybe_contains(pw) else "absent"
            agree = "" if ((n > 0) == bloom.maybe_contains(pw)) else "  [MISMATCH]"
            print(f"online: {online:24} | local bloom: {local}{agree}")
        else:
            print(online)
        if n:
            rc = 1  # at least one breached
    return rc


if __name__ == "__main__":
    sys.exit(main())
