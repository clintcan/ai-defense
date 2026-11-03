"""Pure-Python PuTTY .ppk reader -> OpenSSH PEM (no external tools).

Parses an unencrypted PuTTY private key (.ppk v2 or v3) and rebuilds the key
with ``cryptography`` (paramiko's own dependency), serializing it to an OpenSSH
PEM string that paramiko can load. Encrypted .ppk files (PuTTY v3 uses Argon2)
are not handled here — the caller falls back to puttygen or asks the operator to
export an OpenSSH key from the PuTTYgen GUI.

Supported key types: ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp{256,384,521}.
"""

from __future__ import annotations

from base64 import b64decode

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

_PPK_HEADER = "PuTTY-User-Key-File"


class PpkEncryptedError(ValueError):
    """The .ppk is encrypted; native parsing is not supported."""


class PpkError(ValueError):
    """The .ppk could not be parsed or the key type is unsupported."""


# --- SSH wire format helpers --------------------------------------------

class _Reader:
    def __init__(self, data: bytes) -> None:
        self._d = data
        self._i = 0

    def string(self) -> bytes:
        n = int.from_bytes(self._d[self._i:self._i + 4], "big")
        self._i += 4
        s = self._d[self._i:self._i + n]
        self._i += n
        return s

    def mpint(self) -> int:
        return int.from_bytes(self.string(), "big")  # keys are positive


# --- .ppk parsing --------------------------------------------------------

def _parse(text: str) -> tuple[str, str, bytes, bytes]:
    lines = text.replace("\r\n", "\n").split("\n")
    algorithm = encryption = ""
    public = private = b""
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(_PPK_HEADER):
            algorithm = line.split(":", 1)[1].strip()
        elif line.startswith("Encryption:"):
            encryption = line.split(":", 1)[1].strip()
        elif line.startswith("Public-Lines:"):
            n = int(line.split(":", 1)[1])
            public = b64decode("".join(lines[i + 1:i + 1 + n]))
            i += n
        elif line.startswith("Private-Lines:"):
            n = int(line.split(":", 1)[1])
            private = b64decode("".join(lines[i + 1:i + 1 + n]))
            i += n
        i += 1
    if not algorithm:
        raise PpkError("not a PuTTY .ppk key")
    return algorithm, encryption, public, private


def ppk_to_openssh_pem(text: str) -> str:
    """Convert unencrypted .ppk text to an OpenSSH PEM private key string."""
    algorithm, encryption, public, private = _parse(text)
    if encryption and encryption != "none":
        raise PpkEncryptedError(f"encrypted .ppk ({encryption}) not supported natively")

    key = _build_key(algorithm, public, private)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("ascii")


def _build_key(algorithm: str, public: bytes, private: bytes):
    pub = _Reader(public)
    pub.string()                       # algorithm name (redundant with header)
    priv = _Reader(private)

    if algorithm == "ssh-ed25519":
        pub.string()                   # 32-byte public point (not needed)
        seed = priv.string()
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed)

    if algorithm == "ssh-rsa":
        e = pub.mpint()
        n = pub.mpint()
        d = priv.mpint()
        p = priv.mpint()
        q = priv.mpint()
        # iqmp from the file is ignored; recompute the CRT params for safety.
        pubnums = rsa.RSAPublicNumbers(e, n)
        privnums = rsa.RSAPrivateNumbers(
            p=p, q=q, d=d,
            dmp1=rsa.rsa_crt_dmp1(d, p), dmq1=rsa.rsa_crt_dmq1(d, q),
            iqmp=rsa.rsa_crt_iqmp(p, q), public_numbers=pubnums,
        )
        return privnums.private_key()

    if algorithm.startswith("ecdsa-sha2-"):
        pub.string()                   # curve name
        pub.string()                   # public point Q
        secret = priv.mpint()
        curve = {"ecdsa-sha2-nistp256": ec.SECP256R1,
                 "ecdsa-sha2-nistp384": ec.SECP384R1,
                 "ecdsa-sha2-nistp521": ec.SECP521R1}.get(algorithm)
        if curve is None:
            raise PpkError(f"unsupported ECDSA curve: {algorithm}")
        return ec.derive_private_key(secret, curve())

    raise PpkError(f"unsupported .ppk key type: {algorithm}")
