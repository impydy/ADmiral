#!/usr/bin/env python3
"""Sign ADmiral releases for the built-in updater (Ed25519). Needs the 'cryptography' package.

  python scripts/release_sign.py keygen  release-key.pem
      Create the signing key pair once. The private file is encrypted with a passphrase you are asked for
      (--no-passphrase: not encrypted). Keep it secret (never in the repository, never on the update server),
      ideally on an offline medium. The PUBLIC key (base64) is printed: put it into
      src/ADmiral.Core/AppUpdate.cs BuiltinPublicKey (the program only trusts the built-in key).

  python scripts/release_sign.py protect release-key.pem
      Encrypt an existing, unencrypted private key file with a passphrase (in place).

  python scripts/release_sign.py manifest release-key.pem dist/ADmiral-Setup-0.2.4.exe 0.2.4 \\
         [--notes "text"] [--previous latest.json] [--out latest.json] [--valid-days 90]
      Write the signed latest.json for that installer. --previous is the manifest that is currently on the
      server: its version becomes the "previous" entry, which is what enables the rollback button (keep that
      installer on the server too). The manifest carries its signing time and expires after --valid-days
      (default 90): re-sign it before then (same installer is fine), or ADmiral stops offering updates. An
      old copy replayed later is refused by ADmiral (it remembers the newest manifest it accepted).

The passphrase is asked for, or taken from the environment variable ADMIRAL_SIGN_PASSPHRASE.

Upload latest.json and the installer(s) into the same folder (http(s) or a network share) that is entered as
the update location.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import getpass
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _canonical(doc: dict) -> bytes:                      # must match ADmiral.Core.AppUpdate.Canonical
    body = {k: v for k, v in doc.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _pub_b64(priv) -> str:
    from cryptography.hazmat.primitives import serialization
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def _new_passphrase() -> bytes:
    env = os.environ.get("ADMIRAL_SIGN_PASSPHRASE")
    if env:
        return env.encode("utf-8")
    first = getpass.getpass("New passphrase for the private key: ")
    if len(first) < 12:
        sys.exit("the passphrase must be at least 12 characters")
    if getpass.getpass("Repeat the passphrase: ") != first:
        sys.exit("the passphrases differ")
    return first.encode("utf-8")


def _write_key(path: Path, priv, passphrase: bytes | None) -> None:
    from cryptography.hazmat.primitives import serialization
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    tmp.replace(path)


def load_key(path: Path):
    """The private key; an encrypted file asks for its passphrase (or reads ADMIRAL_SIGN_PASSPHRASE)."""
    from cryptography.hazmat.primitives import serialization
    data = path.read_bytes()
    if b"ENCRYPTED" not in data:
        return serialization.load_pem_private_key(data, password=None)
    pw = os.environ.get("ADMIRAL_SIGN_PASSPHRASE") or getpass.getpass(f"Passphrase of {path}: ")
    try:
        return serialization.load_pem_private_key(data, password=pw.encode("utf-8"))
    except ValueError:
        sys.exit("wrong passphrase")


def keygen(path: Path, passphrase: bytes | None = None) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if path.exists():
        sys.exit(f"{path} already exists: not overwritten")
    priv = Ed25519PrivateKey.generate()
    _write_key(path, priv, passphrase)
    print(f"private key written to {path} (keep it secret)")
    print("public key (base64):", _pub_b64(priv))


def protect(path: Path) -> None:
    priv = load_key(path)
    if b"ENCRYPTED" in path.read_bytes():
        sys.exit(f"{path} is already encrypted")
    _write_key(path, priv, _new_passphrase())
    print(f"{path} is now encrypted with the passphrase")


def manifest(key: Path, setup: Path, version: str, notes: str, previous: Path | None, out: Path,
             valid_days: int = 90) -> None:
    if not 1 <= valid_days <= 730:
        sys.exit("--valid-days must be between 1 and 730")
    priv = load_key(key)
    sha = hashlib.sha256(setup.read_bytes()).hexdigest()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    stamp = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
    doc: dict = {"version": version, "file": setup.name, "sha256": sha, "notes": notes,
                 "signed": stamp(now), "expires": stamp(now + timedelta(days=valid_days))}
    if previous:
        old = json.loads(previous.read_text(encoding="utf-8-sig"))
        if old.get("version") and old["version"] != version:
            doc["previous"] = {k: old[k] for k in ("version", "file", "sha256")}
    doc["signature"] = base64.b64encode(priv.sign(_canonical(doc))).decode()
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out}: {version}, {setup.name}, sha256 {sha}"
          + (f", previous {doc['previous']['version']}" if "previous" in doc else ", no previous version"))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("key", type=Path)
    k.add_argument("--no-passphrase", action="store_true", help="do not encrypt the private key file")
    pr = sub.add_parser("protect")
    pr.add_argument("key", type=Path)
    m = sub.add_parser("manifest")
    m.add_argument("key", type=Path)
    m.add_argument("setup", type=Path)
    m.add_argument("version")
    m.add_argument("--notes", default="")
    m.add_argument("--previous", type=Path)
    m.add_argument("--out", type=Path, default=Path("latest.json"))
    m.add_argument("--valid-days", type=int, default=90)
    a = ap.parse_args()
    if a.cmd == "keygen":
        keygen(a.key, None if a.no_passphrase else _new_passphrase())
    elif a.cmd == "protect":
        protect(a.key)
    else:
        manifest(a.key, a.setup, a.version, a.notes, a.previous, a.out, a.valid_days)


if __name__ == "__main__":
    main()
