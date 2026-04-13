#!/usr/bin/env python3
"""btcli-compat: byte-for-byte verify btt's coldkey envelope against the
reference NaCl + argon2 primitives.

This script is the canonical proof that btt's on-disk coldkey format is
wire-compatible with btcli/btwallet. It is deliberately *not* a cargo test
and deliberately *not* importing `bittensor.*` or `btwallet.*` — those are
the packages whose supply-chain compromise (bittensor 6.12.2, July 2024)
btt exists to route around. The only python dependencies this script uses
are:

    - nacl.secret, nacl.utils, nacl.exceptions   (from pynacl)
    - argon2.low_level                           (from argon2-cffi)
    - stdlib

Both pynacl and argon2-cffi are thin ctypes-style wrappers around libsodium
and the reference argon2 C implementation, respectively. Their trust
surface is tiny and auditable, and nothing in their install scripts
attempts to run chain state.

Layout
------

    1. Generate deterministic (password, plaintext) vectors from a seed.
    2. For each vector, exercise both directions:
         A) btt encrypts, python decrypts
         B) python encrypts, btt decrypts (via `btt wallet sign`)
    3. Write a JSON report and raw per-vector blobs to `out_dir`.
    4. Exit 0 on all-pass, non-zero on any failure.

No vectors are committed into the repo. Every CI run generates fresh ones
and uploads them as workflow artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

import nacl.exceptions  # type: ignore
import nacl.secret  # type: ignore
import nacl.utils  # type: ignore
from argon2.low_level import Type as ArgonType  # type: ignore
from argon2.low_level import hash_secret_raw  # type: ignore


# ── Constants ────────────────────────────────────────────────────────────
#
# These MUST match `src/commands/wallet_keys.rs` byte-for-byte. If any of
# them drifts, the whole point of this script evaporates.
#
# Source: https://github.com/opentensor/btwallet src/keyfile.rs
# Also copied into src/commands/wallet_keys.rs as NACL_SALT.

NACL_SALT_HEX = "137183dff15a09bc9c90b5518739e9b1"
NACL_SALT = bytes.fromhex(NACL_SALT_HEX)
assert len(NACL_SALT) == 16, "NACL_SALT must be exactly 16 bytes"

NACL_PREFIX = b"$NACL"
KEY_BYTES = 32
NONCE_BYTES = 24

# libsodium argon2i13 SENSITIVE preset:
#   OPSLIMIT_SENSITIVE = 8
#   MEMLIMIT_SENSITIVE = 1073741824 bytes in newer libsodium, but btwallet
#   uses the older 512 MiB value which maps to memory_cost=524288 KiB in
#   the argon2-cffi interface (which takes KiB, not bytes).
ARGON2_T_COST = 8
ARGON2_M_COST_KIB = 524_288  # 512 MiB
ARGON2_PARALLELISM = 1
ARGON2_TYPE = ArgonType.I  # argon2i, not argon2id


# ── Verifier ─────────────────────────────────────────────────────────────


def derive_key_libsodium_sensitive(password: bytes) -> bytes:
    """Derive a 32-byte secretbox key from a password using libsodium's
    `argon2i13::derive_key` SENSITIVE preset (t=8, m=512 MiB, p=1, Argon2i).

    This function is the ground truth for the KDF. If it disagrees with
    `derive_key` in wallet_keys.rs, every vector will fail.
    """
    return hash_secret_raw(
        secret=password,
        salt=NACL_SALT,
        time_cost=ARGON2_T_COST,
        memory_cost=ARGON2_M_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_BYTES,
        type=ARGON2_TYPE,
    )


def decrypt_btt_blob(blob: bytes, password: bytes) -> bytes:
    """Decrypt a $NACL-framed blob using only pynacl primitives."""
    if not blob.startswith(NACL_PREFIX):
        raise ValueError("blob does not start with $NACL magic")
    body = blob[len(NACL_PREFIX):]
    if len(body) < NONCE_BYTES + 16:  # 16 = poly1305 tag minimum
        raise ValueError(f"blob body too short: {len(body)} bytes")
    nonce = body[:NONCE_BYTES]
    ct = body[NONCE_BYTES:]
    key = derive_key_libsodium_sensitive(password)
    box = nacl.secret.SecretBox(key)
    # SecretBox.decrypt accepts either (ciphertext, nonce) or a
    # nonce||ciphertext concat; we pass the concat form explicitly.
    return box.decrypt(nonce + ct)


def encrypt_btt_blob(plaintext: bytes, password: bytes) -> bytes:
    """Encrypt plaintext into a $NACL-framed blob using only pynacl."""
    key = derive_key_libsodium_sensitive(password)
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(NONCE_BYTES)
    # SecretBox.encrypt returns an EncryptedMessage whose .ciphertext
    # attribute is just the secretbox ciphertext (without the nonce
    # prepended). We frame the nonce explicitly ourselves to match
    # btwallet's wire format.
    encrypted = box.encrypt(plaintext, nonce)
    ct = encrypted.ciphertext
    return NACL_PREFIX + nonce + ct


# ── Vector generation ────────────────────────────────────────────────────


@dataclass
class Vector:
    index: int
    label: str
    password: bytes
    plaintext: bytes


def build_vectors(count: int, seed: bytes) -> List[Vector]:
    """Produce deterministic vectors up to `count`, covering the interesting
    slices of the password parameter space. Seed is mixed into the plaintext
    so the same seed across runs yields identical inputs (aiding debugging
    of a CI failure).
    """
    # The plaintext for every vector is the same shape: a BIP39-ish sentinel
    # plus a seed-derived tag. Using fixed-string plaintext sidesteps the
    # need to embed an english wordlist or pull in a bip39 package just to
    # exercise the envelope. The envelope doesn't care what's inside.
    def plaintext_for(i: int) -> bytes:
        tag = hashlib.sha256(seed + i.to_bytes(4, "big")).hexdigest()
        return (
            f'{{"secretPhrase":"test-vector-{i}",'
            f'"tag":"{tag}",'
            f'"ss58Address":"5TESTADDRESSPLACEHOLDERPLACEHOLDERPLACEHOLD"}}'
        ).encode("utf-8")

    catalog: List[Tuple[str, bytes]] = [
        ("ascii-alnum-16", b"CompatTest123456"),
        ("empty-password", b""),
        ("long-password-1200", b"A" * 1200),
        ("utf8-combining", "caf\u00e9\u0301 n\u00f1 \u00fc\u00dfte\u00df".encode("utf-8")),
        ("high-bytes-utf8", "\u00e9\u00e8\u00ea\u00eb\u00ef\u00ee-\u00f1\u00fc\u00f6\u00e5".encode("utf-8")),
        ("shell-meta", b";rm -rf / && echo $PWD `whoami` \"quoted\" 'sq'"),
    ]

    if count > len(catalog):
        raise SystemExit(
            f"--vector-count {count} exceeds the {len(catalog)} labels built "
            f"into check.py; grow catalog or request fewer vectors."
        )

    out: List[Vector] = []
    for i in range(count):
        label, password = catalog[i]
        out.append(
            Vector(
                index=i,
                label=label,
                password=password,
                plaintext=plaintext_for(i),
            )
        )
    return out


# ── btt driver ───────────────────────────────────────────────────────────


class BttDriver:
    """Thin wrapper over subprocess invocations of the btt binary."""

    def __init__(self, binary: Path, home: Path, verbose: bool):
        self.binary = binary.resolve()
        self.home = home
        self.verbose = verbose
        self.home.mkdir(parents=True, exist_ok=True)

    def _run(
        self,
        args: List[str],
        env_extra: Optional[dict] = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "HOME": str(self.home),
            **(env_extra or {}),
        }
        cmd = [str(self.binary), *args]
        if self.verbose:
            print(f"+ {' '.join(cmd)}  (HOME={self.home})", file=sys.stderr)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=False,
            env=env,
        )
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"btt exited {proc.returncode}\n"
                f"  cmd: {' '.join(cmd)}\n"
                f"  stdout: {proc.stdout.decode('utf-8', 'replace')}\n"
                f"  stderr: {proc.stderr.decode('utf-8', 'replace')}"
            )
        return proc

    def regen_coldkey(
        self,
        wallet_name: str,
        mnemonic: str,
        password_file: Path,
    ) -> None:
        self._run(
            [
                "wallet",
                "regen-coldkey",
                "--name",
                wallet_name,
                "--mnemonic",
                mnemonic,
                "--password-file",
                str(password_file),
            ]
        )

    def create(self, wallet_name: str, password_file: Path) -> dict:
        proc = self._run(
            [
                "wallet",
                "create",
                "--name",
                wallet_name,
                "--hotkey",
                "default",
                "--password-file",
                str(password_file),
            ]
        )
        return json.loads(proc.stdout.decode("utf-8"))

    def sign(
        self,
        wallet_name: str,
        message: str,
        password_file: Path,
    ) -> dict:
        proc = self._run(
            [
                "wallet",
                "sign",
                "--name",
                wallet_name,
                "--message",
                message,
                "--password-file",
                str(password_file),
            ]
        )
        return json.loads(proc.stdout.decode("utf-8"))

    def coldkey_path(self, wallet_name: str) -> Path:
        return self.home / ".bittensor" / "wallets" / wallet_name / "coldkey"


# ── Password file helper (tmpfs-aware, mode 0600) ───────────────────────


def write_password_file(password: bytes, scratch_dir: Path) -> Path:
    """Write `password` to a fresh temp file at mode 0600 using O_EXCL.

    Preference order for the parent directory:
      1. /dev/shm if it exists and is writable (tmpfs)
      2. `scratch_dir` otherwise

    We do not use tempfile.NamedTemporaryFile because we want `O_EXCL` and
    explicit mode bits in a single syscall, with no race between creation
    and chmod. The caller is responsible for removing the file.
    """
    candidates = [Path("/dev/shm"), scratch_dir]
    parent: Optional[Path] = None
    for c in candidates:
        if c.exists() and os.access(c, os.W_OK):
            parent = c
            break
    if parent is None:
        raise RuntimeError(f"no writable scratch dir among {candidates}")

    suffix = secrets.token_hex(8)
    path = parent / f"btt-compat-pw-{os.getpid()}-{suffix}"
    fd = os.open(
        str(path),
        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        0o600,
    )
    try:
        # Write password + \n so the first-line parser has a clean boundary.
        os.write(fd, password + b"\n")
    finally:
        os.close(fd)
    return path


def shred_and_remove(path: Path) -> None:
    """Best-effort secure delete: call `shred -u` if available, otherwise
    truncate + unlink. A tmpfs makes this mostly symbolic, but we still do
    it because tmpfs can swap on misconfigured hosts.
    """
    if not path.exists():
        return
    try:
        if shutil.which("shred") is not None:
            subprocess.run(
                ["shred", "-u", "-n", "1", str(path)],
                check=False,
                capture_output=True,
            )
            if not path.exists():
                return
        # Fallback: overwrite with zeros then unlink.
        try:
            size = path.stat().st_size
            with open(path, "r+b") as f:
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            pass
        path.unlink(missing_ok=True)
    except OSError:
        pass


# ── Report types ─────────────────────────────────────────────────────────


@dataclass
class VectorResult:
    vector_index: int
    label: str
    password_repr: str
    plaintext_repr: str
    btt_to_pynacl: str = "FAIL"
    pynacl_to_btt: str = "FAIL"
    btt_blob_hex: Optional[str] = None
    pynacl_blob_hex: Optional[str] = None
    error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "vector_index": self.vector_index,
            "label": self.label,
            "password_repr": self.password_repr,
            "plaintext_repr": self.plaintext_repr,
            "btt_to_pynacl": self.btt_to_pynacl,
            "pynacl_to_btt": self.pynacl_to_btt,
            "btt_blob_hex": self.btt_blob_hex,
            "pynacl_blob_hex": self.pynacl_blob_hex,
            "error": self.error,
        }


def safe_repr(b: bytes, limit: int = 80) -> str:
    """Quoted, size-limited byte repr suitable for a JSON report."""
    r = repr(b)
    if len(r) > limit:
        r = r[: limit - 3] + "..."
    return r


# ── Known test mnemonic ──────────────────────────────────────────────────
#
# We use a fixed BIP39 mnemonic for the regen-coldkey path. This is a
# standard "all abandon" test vector. It has no funds and is not a secret.
KNOWN_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


# ── Main ─────────────────────────────────────────────────────────────────


def run_direction_a(
    vector: Vector,
    driver: BttDriver,
    scratch_dir: Path,
    result: VectorResult,
) -> None:
    """btt encrypts (wallet regen-coldkey), python decrypts.

    The KNOWN_MNEMONIC is the input plaintext path. After regen, we read
    the $NACL blob off disk and decrypt it ourselves. Success means our
    plaintext matches what btt wrote.
    """
    wallet_name = f"btt2py-{vector.index}"
    pw_file = write_password_file(vector.password, scratch_dir)
    try:
        driver.regen_coldkey(wallet_name, KNOWN_MNEMONIC, pw_file)
        blob_path = driver.coldkey_path(wallet_name)
        blob = blob_path.read_bytes()
        result.btt_blob_hex = blob.hex()
        if not blob.startswith(NACL_PREFIX):
            raise ValueError(f"btt wrote non-$NACL blob: {blob[:8]!r}")
        recovered = decrypt_btt_blob(blob, vector.password)
        # The plaintext is a JSON keyfile. We don't try to parse it; we
        # just require it contains the known mnemonic phrase. That's
        # sufficient proof that the envelope decrypted correctly — a
        # wrong key would have raised CryptoError at `.decrypt()` above.
        if b"abandon abandon abandon" not in recovered:
            raise ValueError(
                "decrypted plaintext does not contain the known mnemonic"
            )
        result.btt_to_pynacl = "PASS"
    finally:
        shred_and_remove(pw_file)


def run_direction_b(
    vector: Vector,
    driver: BttDriver,
    scratch_dir: Path,
    result: VectorResult,
) -> None:
    """python encrypts, btt decrypts.

    Strategy: generate a btt-compatible keyfile JSON by first asking btt
    to regen a coldkey with a disposable wallet name and a disposable
    password we control. Read the resulting coldkey, decrypt it with
    pynacl to get the canonical keyfile JSON, then re-encrypt it with
    pynacl under `vector.password`. Overwrite the coldkey blob on disk,
    then ask btt to sign. If signing succeeds, btt decrypted our blob.

    This "round-trip through btt" sidesteps the need to hand-construct
    the inner JSON. btt builds it; we just repack the envelope.
    """
    wallet_name = f"py2btt-{vector.index}"
    wallet_dir = driver.home / ".bittensor" / "wallets" / wallet_name

    # Step 1: let btt create the wallet with a known password.
    bootstrap_pw = b"bootstrap-password-not-secret"
    bootstrap_pw_file = write_password_file(bootstrap_pw, scratch_dir)
    try:
        driver.regen_coldkey(wallet_name, KNOWN_MNEMONIC, bootstrap_pw_file)
    finally:
        shred_and_remove(bootstrap_pw_file)

    coldkey_path = driver.coldkey_path(wallet_name)
    btt_blob = coldkey_path.read_bytes()
    inner_json = decrypt_btt_blob(btt_blob, bootstrap_pw)

    # Step 2: re-encrypt the same inner JSON with the vector password
    # using ONLY our pynacl encryptor. No btt involvement.
    py_blob = encrypt_btt_blob(inner_json, vector.password)
    result.pynacl_blob_hex = py_blob.hex()

    # Overwrite the coldkey on disk. Preserve 0600.
    coldkey_path.write_bytes(py_blob)
    os.chmod(coldkey_path, 0o600)

    # Step 3: ask btt to sign with the vector password. If btt can't
    # decrypt our blob, sign fails.
    vector_pw_file = write_password_file(vector.password, scratch_dir)
    try:
        sign_out = driver.sign(
            wallet_name,
            f"compat-test-msg-{vector.index}",
            vector_pw_file,
        )
    finally:
        shred_and_remove(vector_pw_file)

    if not sign_out.get("ok", False):
        raise ValueError(f"btt wallet sign failed: {sign_out}")
    sig = sign_out.get("data", {}).get("signature", "")
    if not sig.startswith("0x") or len(sig) < 20:
        raise ValueError(f"btt signature looks bogus: {sig}")
    result.pynacl_to_btt = "PASS"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify btt coldkey envelope against pynacl/argon2-cffi."
    )
    parser.add_argument(
        "--btt-binary",
        type=Path,
        default=Path("./target/release/btt"),
        help="path to the built btt binary",
    )
    parser.add_argument(
        "--vector-count",
        type=int,
        default=6,
        help="number of vectors to generate (max 6)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("./btcli-compat-out"),
        help="where to write report.json and raw vector blobs",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="echo each btt invocation to stderr",
    )
    parser.add_argument(
        "--seed",
        type=str,
        default=None,
        help="hex-encoded seed for deterministic vector generation "
        "(default: fresh 16-byte seed)",
    )
    args = parser.parse_args()

    if not args.btt_binary.exists():
        print(
            f"error: btt binary not found at {args.btt_binary}",
            file=sys.stderr,
        )
        return 2

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    vectors_out = out_dir / "vectors"
    vectors_out.mkdir(exist_ok=True)

    if args.seed:
        seed = bytes.fromhex(args.seed)
    else:
        seed = secrets.token_bytes(16)
    print(f"seed: {seed.hex()}", file=sys.stderr)

    vectors = build_vectors(args.vector_count, seed)

    # Every btt invocation gets its own HOME under the out dir so wallets
    # never pollute the real $HOME of the runner.
    runner_home = out_dir / "home"
    scratch_dir = out_dir / "scratch"
    scratch_dir.mkdir(exist_ok=True)
    driver = BttDriver(args.btt_binary, runner_home, args.verbose)

    results: List[VectorResult] = []
    overall_pass = True

    for vector in vectors:
        result = VectorResult(
            vector_index=vector.index,
            label=vector.label,
            password_repr=safe_repr(vector.password),
            plaintext_repr=safe_repr(vector.plaintext),
        )

        try:
            run_direction_a(vector, driver, scratch_dir, result)
        except Exception as e:
            result.error = f"direction A: {e}"
            if args.verbose:
                traceback.print_exc(file=sys.stderr)

        try:
            run_direction_b(vector, driver, scratch_dir, result)
        except Exception as e:
            prev = result.error + " | " if result.error else ""
            result.error = f"{prev}direction B: {e}"
            if args.verbose:
                traceback.print_exc(file=sys.stderr)

        if result.btt_to_pynacl != "PASS" or result.pynacl_to_btt != "PASS":
            overall_pass = False

        # Dump the raw blobs for this vector so an investigator can
        # replay them without re-running the whole script.
        if result.btt_blob_hex:
            (vectors_out / f"vector-{vector.index:02d}-btt.bin").write_bytes(
                bytes.fromhex(result.btt_blob_hex)
            )
        if result.pynacl_blob_hex:
            (vectors_out / f"vector-{vector.index:02d}-pynacl.bin").write_bytes(
                bytes.fromhex(result.pynacl_blob_hex)
            )

        results.append(result)

        status = (
            f"vector {vector.index:02d} [{vector.label:<20}] "
            f"A={result.btt_to_pynacl:4} B={result.pynacl_to_btt:4}"
        )
        if result.error:
            status += f"  error={result.error}"
        print(status, file=sys.stderr)

    report = {
        "seed": seed.hex(),
        "nacl_salt_hex": NACL_SALT_HEX,
        "argon2": {
            "type": "argon2i",
            "t_cost": ARGON2_T_COST,
            "m_cost_kib": ARGON2_M_COST_KIB,
            "parallelism": ARGON2_PARALLELISM,
            "hash_len": KEY_BYTES,
        },
        "vector_count": args.vector_count,
        "results": [r.as_dict() for r in results],
        "overall": "PASS" if overall_pass else "FAIL",
    }

    report_path = out_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"report: {report_path}", file=sys.stderr)

    # Shred the runner home as a best-effort cleanup. Blobs we wanted to
    # keep are already in out_dir/vectors and out_dir/report.json.
    try:
        shutil.rmtree(runner_home, ignore_errors=True)
        shutil.rmtree(scratch_dir, ignore_errors=True)
    except OSError:
        pass

    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())
