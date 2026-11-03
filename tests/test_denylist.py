"""The destructive-pattern denylist must block even approved commands."""

from ai_defense.ssh.denylist import is_denied


def test_blocks_rm_rf_root():
    assert is_denied("rm -rf /")


def test_blocks_fork_bomb():
    assert is_denied(":(){ :|:& };:")


def test_blocks_disabling_auditd():
    assert is_denied("systemctl stop auditd")


def test_allows_benign_patch_command():
    assert not is_denied("apt-get install --only-upgrade -y openssl")
