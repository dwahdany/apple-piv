"""Backup text, passphrase encryption and the printable page."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from apple_piv import backup

CREDENTIALS = [
    {"id": "QUJDREVGRw==", "rp_id": "apple.com", "user_id": "dXNlcg==", "user_name": "x"},
    {"id": "SElKS0xNTg==", "rp_id": "apple.com", "user_id": "dXNlcg=="},
]


@pytest.fixture
def key():
    return ec.generate_private_key(ec.SECP256R1())


def _same(a, b):
    return a.private_numbers().private_value == b.private_numbers().private_value


def test_round_trip_keeps_key_and_every_credential(key):
    text = backup.encode(key, "ab" * 16, CREDENTIALS)
    assert "\n" not in text and " " not in text
    restored, aaguid, credentials = backup.decode(text)
    assert _same(key, restored) and aaguid == "ab" * 16
    assert [(c["id"], c["rp_id"]) for c in credentials] == [
        ("QUJDREVGRw==", "apple.com"),
        ("SElKS0xNTg==", "apple.com"),
    ]


def test_text_typed_with_line_breaks_and_spaces_still_restores(key):
    text = backup.encode(key, "ab" * 16, CREDENTIALS)
    typed = "\n".join(text[i : i + 48] + "  " for i in range(0, len(text), 48))
    assert _same(key, backup.decode(typed)[0])


def test_version_1_backup_from_docker_icloudpd_is_accepted(key):
    old = json.dumps(
        {
            "softkey": 1,
            "rp": "apple.com",
            "id": "QUJDREVGRw==",
            "user": "dXNlcg==",
            "aaguid": "cd" * 16,
            "d": key.private_numbers().private_value.to_bytes(32, "big").hex(),
        }
    )
    restored, aaguid, credentials = backup.decode(old)
    assert _same(key, restored) and aaguid == "cd" * 16
    assert credentials == [{"id": "QUJDREVGRw==", "rp_id": "apple.com", "user_id": "dXNlcg=="}]


@pytest.mark.parametrize(
    "damage",
    [
        lambda t: t[:-20],
        lambda t: t.replace('"softkey":2', '"softkey":9'),
        lambda t: json.dumps({**json.loads(t), "d": "00" * 32}),
        lambda t: json.dumps({**json.loads(t), "d": "ff" * 32}),
        lambda t: "not a backup",
    ],
)
def test_damaged_backup_is_refused(key, damage):
    with pytest.raises(backup.BackupError):
        backup.decode(damage(backup.encode(key, "ab" * 16, CREDENTIALS)))


def test_passphrase_encryption_round_trip_and_wrong_passphrase(key):
    text = backup.encode(key, "ab" * 16, CREDENTIALS)
    armored = backup.encrypt(text, "correct horse battery")
    assert backup.is_encrypted(armored) and not backup.is_encrypted(text)
    assert armored.startswith(backup.ARMOR_BEGIN) and armored.rstrip().endswith(backup.ARMOR_END)
    assert all(len(line) <= 64 for line in armored.splitlines())
    assert key.private_numbers().private_value.to_bytes(32, "big").hex() not in armored
    assert backup.decrypt(armored, "correct horse battery") == text
    with pytest.raises(backup.BackupError):
        backup.decrypt(armored, "wrong")
    with pytest.raises(backup.BackupError):
        backup.encrypt(text, "")


def test_encrypted_backup_is_a_standard_age_file(key):
    """Recoverable without this program: the armor decodes to an age v1 scrypt file."""
    import base64

    armored = backup.encrypt(backup.encode(key, "ab" * 16, CREDENTIALS), "pass phrase")
    body = "".join(armored.splitlines()[1:-1])
    raw = base64.b64decode(body)
    assert raw.startswith(b"age-encryption.org/v1\n-> scrypt ")


def test_key_file_from_backup_signs_like_the_original(key):
    from cryptography.hazmat.primitives import serialization

    state = backup.to_key_file(backup.encode(key, "ab" * 16, CREDENTIALS))
    assert len(state["credentials"]) == 2
    restored = serialization.load_pem_private_key(
        state["credentials"][0]["private_key"].encode(), None
    )
    assert _same(key, restored)


def test_write_private_never_overwrites_and_is_owner_only(tmp_path):
    import stat

    path = tmp_path / "backup.txt"
    backup.write_private(path, "one")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        backup.write_private(path, "two")
    assert path.read_text() == "one"


@pytest.mark.parametrize("passphrase", [None, "pass phrase"])
def test_page_carries_the_whole_backup_as_text(key, passphrase):
    import html
    import re

    text = backup.encode(key, "ab" * 16, CREDENTIALS)
    content = backup.encrypt(text, passphrase) if passphrase else text
    page = backup.page(content, "My <key>")
    assert "<svg" in page and "My &lt;key&gt;" in page
    printed = html.unescape(re.search(r"<pre>(.*?)</pre>", page, re.S).group(1))
    recovered = backup.decrypt(printed, passphrase) if passphrase else printed
    assert _same(key, backup.decode(recovered)[0])
    assert ("PLAIN" in page.upper() or "working security key" in page) != bool(passphrase)
