"""Pure-Python .ppk parsing: build real unencrypted .ppk files and load them.

puttygen can't run headless on all platforms, so we construct valid .ppk text
directly from cryptography keys and verify ppk_to_openssh_pem reconstructs a key
paramiko can load that matches the original public key.
"""

import io
from base64 import b64encode

import pytest

pytest.importorskip("cryptography")
paramiko = pytest.importorskip("paramiko")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa  # noqa: E402

from ai_defense.ssh.ppk import PpkEncryptedError, ppk_to_openssh_pem  # noqa: E402


def _ssh_string(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def _ssh_mpint(x: int) -> bytes:
    n = (x.bit_length() + 7) // 8
    b = x.to_bytes(n, "big") if n else b""
    if b and b[0] & 0x80:
        b = b"\x00" + b
    return _ssh_string(b)


def _ppk(algorithm: str, public: bytes, private: bytes) -> str:
    def block(blob):
        b64 = b64encode(blob).decode()
        return [b64[i:i + 64] for i in range(0, len(b64), 64)]
    pub_lines = block(public)
    priv_lines = block(private)
    lines = [f"PuTTY-User-Key-File-3: {algorithm}", "Encryption: none",
             "Comment: test-key", f"Public-Lines: {len(pub_lines)}", *pub_lines,
             f"Private-Lines: {len(priv_lines)}", *priv_lines, "Private-MAC: 00"]
    return "\n".join(lines) + "\n"


def _openssh_pub(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


def test_ed25519_ppk_roundtrip():
    key = ed25519.Ed25519PrivateKey.generate()
    raw_pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    raw_priv = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    public = _ssh_string(b"ssh-ed25519") + _ssh_string(raw_pub)
    private = _ssh_string(raw_priv)

    pem = ppk_to_openssh_pem(_ppk("ssh-ed25519", public, private))
    loaded = paramiko.Ed25519Key.from_private_key(io.StringIO(pem))
    # the reconstructed key must match the original public key
    reparsed = serialization.load_ssh_private_key(pem.encode(), password=None)
    assert _openssh_pub(reparsed) == _openssh_pub(key)
    assert loaded.get_name() == "ssh-ed25519"


def test_rsa_ppk_roundtrip():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pn = key.private_numbers()
    pub = key.public_key().public_numbers()
    public = _ssh_string(b"ssh-rsa") + _ssh_mpint(pub.e) + _ssh_mpint(pub.n)
    private = (_ssh_mpint(pn.d) + _ssh_mpint(pn.p) + _ssh_mpint(pn.q)
               + _ssh_mpint(pn.iqmp))

    pem = ppk_to_openssh_pem(_ppk("ssh-rsa", public, private))
    loaded = paramiko.RSAKey.from_private_key(io.StringIO(pem))
    reparsed = serialization.load_ssh_private_key(pem.encode(), password=None)
    assert _openssh_pub(reparsed) == _openssh_pub(key)
    assert loaded.get_name() == "ssh-rsa"


def test_encrypted_ppk_raises():
    text = ("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\n"
            "Public-Lines: 1\nAAAA\nPrivate-Lines: 1\nBBBB\n")
    with pytest.raises(PpkEncryptedError):
        ppk_to_openssh_pem(text)


def test_not_a_ppk_raises():
    from ai_defense.ssh.ppk import PpkError
    with pytest.raises(PpkError):
        ppk_to_openssh_pem("-----BEGIN OPENSSH PRIVATE KEY-----\n...\n")
