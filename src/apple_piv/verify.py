"""Check with a real sign-in that Apple accepts the key.

Signs in to iCloud with icloudpd, into a temporary folder that is deleted
afterwards, with the security key answering Apple's challenge. icloudpd asks
for the account password at its own prompt; this program never sees it.

icloudpd pins its dependencies exactly, so it runs in an environment of its
own (made by uv) that gets only the three modules it needs from here.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

ICLOUDPD_VERSION = "1.33.0"
# The pure-Python wheel, by hash. The platform wheels wrap a prebuilt binary.
ICLOUDPD_WHEEL = (
    "https://files.pythonhosted.org/packages/d8/55/"
    "6ebee6620714b548befcf45c4873bafaa8b5a57d25c79d40ce947f1c4e04/"
    "icloudpd-1.33.0-py3-none-any.whl"
    "#sha256=3ff27038ebc17105a5c75a4202e938d4485d80880f8e88b1b4f299e9edc000b8"
)
_MODULES = ("__init__.py", "authenticator.py", "piv.py", "icloudpd_run.py")


class VerifyError(Exception):
    pass


def command(key_file: Path, apple_id: str, domain: str, cookies: Path, modules: Path) -> list[str]:
    return [
        "uv", "run", "--no-project", "--quiet",
        "--with", f"icloudpd @ {ICLOUDPD_WHEEL}",
        "--with", "yubikey-manager>=5.5,<6",
        "--with", "pyusb>=1.2",
        "env", f"PYTHONPATH={modules}",
        "python", "-m", "apple_piv.icloudpd_run", str(key_file),
        "--username", apple_id,
        "--cookie-directory", str(cookies),
        "--domain", domain,
        "--auth-only",
        "--password-provider", "console",
        "--mfa-provider", "console",
    ]  # fmt: skip


def run(key_file: Path, apple_id: str, domain: str = "com") -> bool:
    """True if Apple issued a trusted session for a sign-in confirmed by the key."""
    key_file = key_file.expanduser()
    if not key_file.is_file():
        raise VerifyError(f"no key file at {key_file}")
    if shutil.which("uv") is None:
        raise VerifyError("uv is needed to run icloudpd (https://docs.astral.sh/uv/)")
    with tempfile.TemporaryDirectory(prefix="apple-piv-verify-") as tmp:
        modules = Path(tmp) / "modules" / "apple_piv"
        modules.mkdir(parents=True)
        for name in _MODULES:
            shutil.copy(Path(__file__).with_name(name), modules / name)
        cookies = Path(tmp) / "cookies"
        cookies.mkdir(mode=0o700)
        subprocess.run(command(key_file, apple_id, domain, cookies, modules.parent), check=False)
        return any('"trust_token"' in f.read_text(errors="replace") for f in cookies.glob("*.session"))
