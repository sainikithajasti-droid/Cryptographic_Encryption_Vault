#!/usr/bin/env python3
"""Cryptographic Encryption Vault - AES-256-GCM directory encryption."""

import argparse
import base64
import getpass
import hashlib
import json
import os
import secrets
import shutil
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CVLT1"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
CHUNK = 1024 * 1024
BACKUP_NAME = "vault_key_backup.json"


def derive_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=KEY_LEN, n=2**14, r=8, p=1).derive(password.encode("utf-8"))


def wrap_vault_key(vault_key: bytes, password: str) -> dict:
    salt = secrets.token_bytes(SALT_LEN)
    wrapping_key = derive_key(password, salt)
    nonce = secrets.token_bytes(NONCE_LEN)
    encrypted = AESGCM(wrapping_key).encrypt(nonce, vault_key, b"CVLT-KEY-BACKUP-v1")
    return {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "kdf": "scrypt",
        "scrypt": {"n": 16384, "r": 8, "p": 1},
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "wrapped_key": base64.b64encode(encrypted).decode(),
    }


def unwrap_vault_key(password: str, backup_path: Path) -> bytes:
    data = json.loads(backup_path.read_text(encoding="utf-8"))
    salt = base64.b64decode(data["salt"])
    nonce = base64.b64decode(data["nonce"])
    wrapped = base64.b64decode(data["wrapped_key"])
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, wrapped, b"CVLT-KEY-BACKUP-v1")


def write_backup(vault_dir: Path, vault_key: bytes, password: str) -> Path:
    vault_dir.mkdir(parents=True, exist_ok=True)
    path = vault_dir / BACKUP_NAME
    path.write_text(json.dumps(wrap_vault_key(vault_key, password), indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def encrypt_file(src: Path, dst: Path, key: bytes, relative_name: str) -> None:
    data = src.read_bytes()
    nonce = secrets.token_bytes(NONCE_LEN)
    aad = relative_name.encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, data, aad)
    dst.parent.mkdir(parents=True, exist_ok=True)
    # Header: MAGIC | nonce length | name length | nonce | relative name | ciphertext
    name_bytes = relative_name.encode("utf-8")
    header = MAGIC + struct.pack("!BH", len(nonce), len(name_bytes)) + nonce + name_bytes
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    tmp.write_bytes(header + ciphertext)
    tmp.replace(dst)


def decrypt_file(src: Path, dst: Path, key: bytes) -> None:
    raw = src.read_bytes()
    if not raw.startswith(MAGIC):
        raise ValueError("Invalid vault file format")
    nonce_len, name_len = struct.unpack("!BH", raw[5:8])
    pos = 8
    nonce = raw[pos:pos + nonce_len]
    pos += nonce_len
    name = raw[pos:pos + name_len].decode("utf-8")
    pos += name_len
    ciphertext = raw[pos:]
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, name.encode("utf-8"))
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    tmp.write_bytes(plaintext)
    tmp.replace(dst)


def iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def encrypt_directory(source: Path, vault: Path, password: str) -> tuple[int, Path]:
    if not source.is_dir():
        raise ValueError(f"Source directory does not exist: {source}")
    if vault.exists() and any(vault.iterdir()):
        raise ValueError(f"Vault directory must be empty or not exist: {vault}")
    vault.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(KEY_LEN)
    backup = write_backup(vault, key, password)
    count = 0
    for src in iter_files(source):
        rel = src.relative_to(source).as_posix()
        encrypt_file(src, vault / (rel + ".enc"), key, rel)
        count += 1
    return count, backup


def decrypt_directory(vault: Path, output: Path, password: str) -> tuple[int, list[str]]:
    backup = vault / BACKUP_NAME
    if not backup.is_file():
        raise ValueError(f"Missing secure key backup: {backup}")
    key = unwrap_vault_key(password, backup)
    output.mkdir(parents=True, exist_ok=True)
    count = 0
    restored = []
    for src in sorted(vault.rglob("*.enc")):
        rel_enc = src.relative_to(vault)
        raw = src.read_bytes()
        if not raw.startswith(MAGIC):
            continue
        name_len = struct.unpack("!H", raw[6:8])[0]
        name = raw[8 + raw[5]:8 + raw[5] + name_len].decode("utf-8")
        dst = output / name
        decrypt_file(src, dst, key)
        restored.append(name)
        count += 1
    return count, restored


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def verify_directories(original: Path, restored: Path) -> tuple[bool, list[str]]:
    original_files = sorted(p.relative_to(original).as_posix() for p in iter_files(original))
    restored_files = sorted(p.relative_to(restored).as_posix() for p in iter_files(restored))
    if original_files != restored_files:
        return False, ["File lists differ"]
    mismatches = []
    for rel in original_files:
        if sha256_file(original / rel) != sha256_file(restored / rel):
            mismatches.append(rel)
    return not mismatches, mismatches


def main():
    parser = argparse.ArgumentParser(description="AES-256-GCM recursive directory encryption vault")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt all files in a directory")
    enc.add_argument("source", type=Path)
    enc.add_argument("vault", type=Path)

    dec = sub.add_parser("decrypt", help="Restore files from a vault")
    dec.add_argument("vault", type=Path)
    dec.add_argument("output", type=Path)

    args = parser.parse_args()
    try:
        password = getpass.getpass("Master passphrase: ")
        if not password:
            raise ValueError("Passphrase cannot be empty")
        if args.command == "encrypt":
            count, backup = encrypt_directory(args.source, args.vault, password)
            print(f"[OK] Encrypted {count} file(s) using AES-256-GCM")
            print(f"[OK] Secure key backup: {backup}")
        else:
            count, restored = decrypt_directory(args.vault, args.output, password)
            print(f"[OK] Decrypted {count} file(s)")
            for name in restored:
                print(f"     restored: {name}")
    except Exception as exc:
        print(f"[ERROR] {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
