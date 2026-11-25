"""Backup of the security key's private key: as text, optionally encrypted, and printable.

A key that was created inside the YubiKey has no backup. To have one, the key
is created in memory, written out here, and then moved into the YubiKey.

The backup is one line of JSON: the 32-byte private key and the credentials
registered with it. With a passphrase it is encrypted in the age format
(scrypt), ASCII-armored, so that plain ``age --decrypt`` opens it without this
program. Unencrypted, it is a working second factor in plain sight.
"""

from __future__ import annotations

import base64
import html
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
ARMOR_BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----"
ARMOR_END = "-----END AGE ENCRYPTED FILE-----"


class BackupError(Exception):
    """The backup text cannot be used (damaged, mistyped, wrong passphrase)."""


# ---- content ---------------------------------------------------------------------------------


def encode(private_key: Any, aaguid: str, credentials: list[dict[str, Any]]) -> str:
    """The backup text for a key and the credentials registered with it."""
    secret = private_key.private_numbers().private_value.to_bytes(32, "big")
    return json.dumps(
        {
            "softkey": 2,
            "aaguid": aaguid,
            "d": secret.hex(),
            "credentials": [
                {"rp": c["rp_id"], "id": c["id"], "user": c.get("user_id", "")}
                for c in credentials
            ],
        },
        separators=(",", ":"),
    )


def decode(text: str) -> tuple[Any, str, list[dict[str, Any]]]:
    """(private key, aaguid, credentials) from backup text; whitespace is ignored."""
    try:
        data = json.loads("".join(text.split()))
        version = data.get("softkey")
        scalar = int(data["d"], 16)
        if version == 1:  # one credential, written by docker-icloudpd's backup.py
            entries = [{"rp": data["rp"], "id": data["id"], "user": data.get("user", "")}]
        elif version == 2:
            entries = data["credentials"]
        else:
            raise BackupError("this is not a security key backup")
        if not 0 < scalar < P256_ORDER:
            raise BackupError("the private key in the backup is not valid (typing error?)")
        credentials = []
        for entry in entries:
            base64.b64decode(entry["id"], validate=True)
            credentials.append(
                {"id": entry["id"], "rp_id": entry["rp"], "user_id": entry.get("user", "")}
            )
        return ec.derive_private_key(scalar, ec.SECP256R1()), data["aaguid"], credentials
    except BackupError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise BackupError(f"the backup text is damaged or incomplete ({error})") from error


def to_key_file(text: str) -> dict[str, Any]:
    """A key file that holds the private key itself, from backup text."""
    private_key, aaguid, credentials = decode(text)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return {
        "version": 1,
        "aaguid": aaguid,
        "credentials": [
            {**credential, "user_name": "", "created": "restored from backup", "private_key": pem}
            for credential in credentials
        ],
    }


# ---- passphrase encryption (age) -------------------------------------------------------------


def encrypt(text: str, passphrase: str) -> str:
    from pyrage import passphrase as age_passphrase

    if not passphrase:
        raise BackupError("the passphrase is empty")
    body = base64.b64encode(age_passphrase.encrypt(text.encode(), passphrase)).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "\n".join([ARMOR_BEGIN, *lines, ARMOR_END]) + "\n"


def is_encrypted(text: str) -> bool:
    return ARMOR_BEGIN in text


def decrypt(armored: str, passphrase: str) -> str:
    import pyrage
    from pyrage import passphrase as age_passphrase

    try:
        start = armored.index(ARMOR_BEGIN) + len(ARMOR_BEGIN)
        body = "".join(armored[start : armored.index(ARMOR_END)].split())
        return age_passphrase.decrypt(base64.b64decode(body, validate=True), passphrase).decode()
    except (ValueError, pyrage.DecryptError) as error:
        raise BackupError("wrong passphrase, or the encrypted backup is damaged") from error


# ---- storage ---------------------------------------------------------------------------------


def write_private(path: Path, content: str) -> None:
    """Create ``path`` readable by its owner only; never overwrites."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)


def page(content: str, label: str) -> str:
    """A printable HTML page: the backup as a QR code and as text."""
    import segno

    encrypted = is_encrypted(content)
    qr = segno.make(content, error="m").svg_inline(scale=4, border=2)
    if encrypted:
        text = content.strip()
        warning = (
            "This sheet holds a security key for the Apple Account it was registered with, "
            "encrypted with a passphrase. Without the passphrase it is useless — to you as well."
        )
        how = (
            "save the text (from the QR code, or typed with its line breaks) to a file and run "
            "<code>apple-piv restore</code>. It is a standard age file: "
            "<code>age --decrypt</code> opens it too."
        )
    else:
        text = "\n".join(content[i : i + 48] for i in range(0, len(content), 48))
        warning = (
            "This sheet is a working security key for the Apple Account it was registered with. "
            "Anyone who has it and the account password can sign in. Keep it locked away."
        )
        how = (
            "save the text (from the QR code, or typed as one line without spaces) to a file "
            "and run <code>apple-piv restore</code>."
        )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Security key backup</title>
<style>
body {{ font: 12pt/1.5 system-ui, sans-serif; margin: 2cm; color: #000; }}
pre {{ font: 10pt/1.5 ui-monospace, Menlo, monospace; border: 1px solid #000; padding: .5cm; }}
p {{ max-width: 16cm; }}
</style></head><body>
<h1>Security key backup</h1>
<p><strong>{html.escape(label)}</strong></p>
<p>{warning}</p>
{qr}
<p>The same content as text:</p>
<pre>{html.escape(text)}</pre>
<p>To restore: {how} See github.com/dwahdany/apple-piv.</p>
</body></html>
"""
