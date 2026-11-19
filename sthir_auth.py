"""Sthir accounts: password-locked key vaults.

A key never touches the disk in the clear once it is in an account. It is sealed
with a password (scrypt -> AES-256-GCM). Whoever has the sealed vault AND the
password owns the coins; nobody else does, including any server that stores a
copy. There is no "forgot password": losing both the password and every backup
means the coins are gone.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sthir import Wallet

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
MAX_N, MAX_R, MAX_P = 2 ** 16, 8, 2  # limits for vaults that arrive from outside
MIN_PASSWORD, MAX_PASSWORD = 8, 200
PREFIX = "sthir-vault:"
AAD = b"sthir-vault-1"
HEX64 = re.compile(r"[0-9a-f]{64}")
BACKUP_NAME = re.compile(r"\d{9,12}-[0-9a-f]{12}\.key")


class BadPassword(ValueError):
    pass


class Locked(ValueError):
    """Too many wrong passwords."""


# ------------------------------------------------------------------ key helpers
def new_key_hex() -> str:
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()).hex()


def wallet_from_hex(key_hex: str) -> Wallet:
    t = str(key_hex).strip().lower()
    if not HEX64.fullmatch(t):
        raise ValueError("A key is 64 characters using 0-9 and a-f.")
    return Wallet(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(t)))


# ------------------------------------------------------------------ the vault
def _kdf(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p,
                          dklen=32, maxmem=256 * 1024 * 1024)


def check_password_rules(password: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise ValueError(f"Use a password of at least {MIN_PASSWORD} characters.")
    if len(password) > MAX_PASSWORD:
        raise ValueError("That password is too long.")


def seal(key_hex: str, password: str) -> dict:
    check_password_rules(password)
    wallet_from_hex(key_hex)
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    k = _kdf(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    ct = AESGCM(k).encrypt(nonce, bytes.fromhex(key_hex.strip().lower()), AAD)
    return {"v": 1, "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex()}


def open_vault(vault: dict, password: str) -> str:
    try:
        n, r, p = int(vault["n"]), int(vault["r"]), int(vault["p"])
        salt, nonce = bytes.fromhex(vault["salt"]), bytes.fromhex(vault["nonce"])
        ct = bytes.fromhex(vault["ct"])
        if vault.get("v") != 1 or not (2 ** 10 <= n <= MAX_N) or n & (n - 1) \
                or not (1 <= r <= MAX_R) or not (1 <= p <= MAX_P) \
                or len(salt) != 16 or len(nonce) != 12 or len(ct) != 48:
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError("This backup is damaged or not a Sthir backup.")
    try:
        return AESGCM(_kdf(password, salt, n, r, p)).decrypt(nonce, ct, AAD).hex()
    except InvalidTag:
        raise BadPassword("Wrong password.")


# ------------------------------------------------------- export text for backups
def make_export(name: str, address: str, vault: dict) -> str:
    body = json.dumps({"name": name, "address": address, "vault": vault},
                      separators=(",", ":")).encode()
    return PREFIX + base64.urlsafe_b64encode(body).decode().rstrip("=")


def parse_export(text: str) -> dict:
    t = re.sub(r"\s+", "", str(text or ""))
    if not t.startswith(PREFIX) or len(t) > 4000:
        raise ValueError("This is not a Sthir backup. It should start with sthir-vault:")
    raw = t[len(PREFIX):]
    try:
        d = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        name = validate_name(d["name"])
        if not HEX64.fullmatch(str(d["address"])) or not isinstance(d["vault"], dict):
            raise ValueError
        return {"name": name, "address": d["address"], "vault": d["vault"]}
    except (ValueError, KeyError, TypeError):
        raise ValueError("This backup is damaged. Copy the whole text again.")


def relay_id(name: str, password: str) -> str:
    """Where a backup lives on a relay. Derived from name and password, so the id
    cannot be guessed or listed without the password."""
    salt = b"sthir-relay-id|" + name.strip().lower().encode()
    return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1,
                          dklen=32, maxmem=64 * 1024 * 1024).hex()


# ----------------------------------------------------------------------- names
def validate_name(name) -> str:
    n = str(name or "").strip()
    if not 1 <= len(n) <= 24:
        raise ValueError("Use a profile name of 1 to 24 characters.")
    if any(unicodedata.category(c).startswith("C") for c in n):
        raise ValueError("The profile name has characters that cannot be used.")
    return n


# ------------------------------------------------------------------- throttling
class Throttle:
    """After a few wrong passwords, make the next try wait. Doubles each time."""

    def __init__(self, free=5, base=30, cap=300, clock=time.time):
        self.free, self.base, self.cap, self.clock = free, base, cap, clock
        self.fails: dict[str, int] = {}
        self.until: dict[str, float] = {}
        self.lock = threading.Lock()

    def check(self, key: str) -> None:
        with self.lock:
            left = self.until.get(key, 0) - self.clock()
        if left > 0:
            raise Locked(f"Too many wrong passwords. Try again in {int(left) + 1} seconds.")

    def fail(self, key: str) -> None:
        with self.lock:
            n = self.fails[key] = self.fails.get(key, 0) + 1
            if n >= self.free:
                wait = min(self.base * 2 ** (n - self.free), self.cap)
                self.until[key] = self.clock() + wait

    def ok(self, key: str) -> None:
        with self.lock:
            self.fails.pop(key, None)
            self.until.pop(key, None)


# ------------------------------------------------------------------- the store
def _write_private(path: str, text: str) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class AccountStore:
    """accounts.json: every account's name, address and sealed key."""

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self.accounts: list[dict] = []
        if os.path.exists(path):
            with open(path) as f:
                self.accounts = json.load(f)["accounts"]

    def _save(self) -> None:
        _write_private(self.path, json.dumps({"version": 1, "accounts": self.accounts}))

    def listing(self) -> list[dict]:
        with self.lock:
            return [{"id": a["id"], "name": a["name"]} for a in self.accounts]

    def get(self, acct_id) -> dict | None:
        with self.lock:
            return next((a for a in self.accounts if a["id"] == acct_id), None)

    def by_name(self, name) -> dict | None:
        key = str(name).strip().lower()
        with self.lock:
            return next((a for a in self.accounts if a["name"].lower() == key), None)

    def by_address(self, address) -> dict | None:
        with self.lock:
            return next((a for a in self.accounts if a["address"] == address), None)

    def addresses(self) -> set[str]:
        with self.lock:
            return {a["address"] for a in self.accounts}

    def add(self, name: str, key_hex: str, password: str, vault: dict | None = None) -> dict:
        name = validate_name(name)
        w = wallet_from_hex(key_hex)
        with self.lock:
            if self.by_name(name):
                raise ValueError("A profile with this name already exists on this phone.")
            if self.by_address(w.address):
                raise ValueError("This wallet is already on this phone under another name.")
            vault = vault or seal(key_hex, password)
            acct = {"id": secrets.token_hex(4), "name": name, "address": w.address,
                    "vault": vault, "created": int(time.time())}
            self.accounts.append(acct)
            self._save()
            return acct

    def set_vault(self, acct_id: str, vault: dict) -> None:
        with self.lock:
            self.get(acct_id)["vault"] = vault
            self._save()

    def remove(self, acct_id: str) -> None:
        """Take an account off the active list. The sealed vault is kept in a
        separate file, so a mistaken removal can still be undone by hand."""
        with self.lock:
            a = self.get(acct_id)
            if not a:
                return
            with open(self.path + ".removed", "a") as f:
                f.write(json.dumps(dict(a, removed=int(time.time()))) + "\n")
            os.chmod(self.path + ".removed", 0o600)
            self.accounts = [x for x in self.accounts if x["id"] != acct_id]
            self._save()


# ------------------------------------------------- moving old plaintext key files
def legacy_keys(key_path: str, backup_dir: str) -> list[tuple[str, str]]:
    """(key_hex, file) for plaintext keys left by the first version: the main key
    file first, then wallet-backups. Unreadable files are skipped."""
    found, seen = [], set()
    files = [key_path]
    if os.path.isdir(backup_dir):
        files += [os.path.join(backup_dir, n) for n in sorted(os.listdir(backup_dir), reverse=True)
                  if BACKUP_NAME.fullmatch(n)]
    for path in files:
        try:
            with open(path) as f:
                k = f.read().strip().lower()
            addr = wallet_from_hex(k).address
        except (OSError, ValueError):
            continue
        if addr not in seen:
            seen.add(addr)
            found.append((k, path))
    return found


def migrate_legacy(store: AccountStore, items: list[tuple[str, str]], password: str,
                   main_name: str) -> list[str]:
    """Seal each plaintext key under `password`. Returns the plaintext files that are
    now safely inside the store; the caller removes them. Nothing is returned for a
    key until its sealed copy has been opened again and matched."""
    done = []
    for i, (k, path) in enumerate(items):
        w = wallet_from_hex(k)
        if store.by_address(w.address):
            done.append(path)
            continue
        name = main_name if i == 0 else f"Old wallet {w.address[:6]}"
        acct = store.add(name, k, password)
        if open_vault(acct["vault"], password) != k:
            raise RuntimeError("Could not verify the sealed copy; nothing was removed.")
        done.append(path)
    return done
