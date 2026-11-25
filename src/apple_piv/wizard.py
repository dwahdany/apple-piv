"""The guided setup: from a YubiKey and a Pico to a security key on the Apple Account.

Order of things, and why:

1. YubiKey: pick it, pick a free PIV slot.
2. Backup: decided before the key exists, because it decides where the key is
   made (inside the YubiKey = no backup possible; in memory = backup possible).
3. Key: created, in the YubiKey from here on, and a test signature made.
4. Pico: flashed and tested as a USB bridge.
5. Apple: the key is registered through the bridge. Only now are the
   credentials known that a backup has to contain.
6. Save: the key file (points to the YubiKey, no secret) and the backup.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import authenticator, backup, bridge, piv
from .console import Console

STEPS = 6
APPLE_RP = "apple.com"


class SetupAborted(Exception):
    """The setup cannot continue; the message says why and what state things are in."""


@dataclass
class BackupPlan:
    kind: str  # "none", "passphrase" or "plain"
    passphrase: str = ""
    path: Path | None = None
    page: Path | None = None


@dataclass
class Result:
    key_file: Path
    yubikey_serial: int
    slot: str
    backup: BackupPlan
    credentials: int


# ---- step 1: YubiKey -------------------------------------------------------------------------


def choose_yubikey(console: Console, serial: int | None) -> piv.YubiKey:
    while True:
        keys = piv.list_yubikeys()
        if serial is not None:
            keys = [k for k in keys if k.serial == serial]
        if len(keys) == 1:
            key = keys[0]
            console.ok(f"{key.name}, serial {key.serial}, firmware {key.version}")
            return key
        if len(keys) > 1:
            index = console.choose(
                "Which YubiKey should hold the key?",
                [f"{k.name}, serial {k.serial}, firmware {k.version}" for k in keys],
            )
            return keys[index]
        which = f"the YubiKey with serial {serial}" if serial else "the YubiKey that will hold the key"
        console.wait(f"Plug in {which}")


def unlock(console: Console, setup: piv.PivSetup) -> None:
    """Authenticate to PIV for writing a key, asking only for what this YubiKey needs."""
    from yubikit.core import InvalidPinError
    from yubikit.core.smartcard import ApduError

    kind = setup.management_key_kind()
    if kind == "default":
        setup.unlock()
        console.warn(
            "This YubiKey's PIV management key is the factory default. Nobody can read "
            "a key with it, but anyone with USB access could delete or replace one. "
            "Change PIN, PUK and management key afterwards (Yubico Authenticator, or "
            "`ykman piv access`)."
        )
        return
    if kind == "pin-protected":
        console.say("This YubiKey keeps its PIV management key protected by the PIV PIN.")
        while True:
            pin = console.secret("PIV PIN")
            try:
                setup.unlock(pin=pin)
                return
            except InvalidPinError as error:
                if error.attempts_remaining <= 1:
                    raise SetupAborted(
                        f"Wrong PIN, {error.attempts_remaining} attempt(s) left before the PIN is "
                        "blocked. Stopping here so it does not get blocked."
                    ) from error
                console.warn(f"Wrong PIN ({error.attempts_remaining} attempts left).")
    console.say("This YubiKey has its own PIV management key (not the default, not PIN-protected).")
    while True:
        text = console.secret("PIV management key (hex)")
        try:
            setup.unlock(management_key=bytes.fromhex(text.strip()))
            return
        except (ValueError, ApduError):
            console.warn("That is not this YubiKey's management key.")
            if not console.confirm("Try again?"):
                raise SetupAborted("No management key, so no key can be written to this YubiKey.")


# ---- step 2: backup --------------------------------------------------------------------------


def _free_path(console: Console, prompt: str, default: Path) -> Path:
    while True:
        path = Path(console.ask(prompt, str(default))).expanduser()
        if path.exists():
            console.warn(f"{path} exists already; choose another name.")
        elif not path.parent.is_dir():
            console.warn(f"The folder {path.parent} does not exist.")
        else:
            return path


def plan_backup(console: Console, backup_dir: Path) -> BackupPlan:
    console.say(
        "The private key will live in the YubiKey, which never gives it out again. "
        "The most secure choice is to let the YubiKey make the key itself: it then never "
        "exists anywhere else, and so cannot be backed up. A backup is only possible if "
        "the key is made on this Mac and exists in this program's memory for a moment "
        "before it is moved into the YubiKey."
    )
    choice = console.choose(
        "Where to make the key",
        [
            "In the YubiKey (most secure, no backup possible)\nThe key is generated inside "
            "the YubiKey and never exists anywhere else. If the YubiKey is lost or breaks, "
            "you register a new key.",
            "On this Mac, with a backup encrypted with a passphrase\nA file (and optionally "
            "a printable page) that is useless without the passphrase. Forget the passphrase "
            "and the backup is gone.",
            "On this Mac, with a backup in plain text\nA file (and optionally a printable "
            "page) that works as the security key for anyone who has it. Only for a safe or "
            "a locked drawer.",
        ],
    )
    if choice == 0:
        return BackupPlan("none")
    plan = BackupPlan("passphrase" if choice == 1 else "plain")
    if plan.kind == "passphrase":
        while True:
            first = console.secret("Passphrase for the backup")
            if len(first) < 8:
                console.warn("Use at least 8 characters; several random words are better.")
                continue
            if first == console.secret("Passphrase again"):
                plan.passphrase = first
                break
            console.warn("The two entries differ.")
    suffix = "age" if plan.kind == "passphrase" else "txt"
    plan.path = _free_path(console, "Backup file", backup_dir / f"apple-piv-backup.{suffix}")
    if console.confirm("Also write a page to print (QR code and text)?"):
        plan.page = _free_path(console, "Page to print", backup_dir / "apple-piv-backup.html")
    return plan


# ---- step 3: the key -------------------------------------------------------------------------


def create_key(
    console: Console, yubikey: piv.YubiKey, plan: BackupPlan, slot_hex: str | None
) -> tuple[dict[str, Any], Any]:
    """(the key file's ``piv`` entry, the private key if a backup was asked for else None)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from yubikit.piv import SLOT

    with piv.PivSetup(yubikey) as setup:
        if slot_hex:
            slot = SLOT(int(slot_hex, 16))
            if not setup.is_free(slot):
                raise SetupAborted(
                    f"PIV slot {slot_hex} on this YubiKey already holds a key. It was left untouched."
                )
        else:
            free = setup.free_slots()
            if not free:
                raise SetupAborted("This YubiKey has no free retired PIV slot (82-95).")
            slot = free[0]
        console.ok(f"PIV slot {slot.value:02x} is free and will be used")
        unlock(console, setup)
        if plan.kind == "none":
            private_key = None
            public_key = setup.generate(slot)
            console.ok("Key created inside the YubiKey")
        else:
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = setup.import_key(slot, private_key)
            console.ok("Key created and moved into the YubiKey")
        setup.test_signature(slot, public_key)
        console.ok("The YubiKey signs with it, without touch and without PIN")
        return piv.key_reference(yubikey, slot, public_key), private_key


# ---- step 4: the Pico ------------------------------------------------------------------------


def prepare_bridge(console: Console) -> str:
    port = bridge.find_port()
    if port:
        console.ok("The Pico already runs the bridge firmware")
    else:
        console.say(
            "The Pico becomes a USB bridge: it lets this program appear as a USB security "
            "key, once, for registering with Apple. Nothing secret is stored on it."
        )
        while True:
            found = bridge.find_bootloader()
            if found:
                break
            console.wait(
                "Hold the BOOTSEL (or BOOT) button while plugging the Pico into this Mac; "
                "a drive called RPI-RP2 or RP2350 appears"
            )
        volume, chip = found
        bridge.flash(volume, chip)
        console.ok(f"Firmware written ({chip.upper()})")
        port = bridge.wait_for_port()
    for attempt in (1, 2):
        try:
            bridge.self_test(port)
            break
        except Exception as error:  # noqa: BLE001 - USB just re-enumerated; one more try
            if attempt == 2:
                raise SetupAborted(f"The Pico did not pass its self-test: {error}") from error
            time.sleep(2)
    console.ok("Self-test passed: this Mac sees the Pico as a security key")
    return port


# ---- step 5: Apple ---------------------------------------------------------------------------


def register_with_apple(
    console: Console, port: str, state: dict[str, Any], touch_delay: float
) -> list[dict[str, Any]]:
    """Run the bridge until Apple has registered the key; return the accepted credentials."""
    soft = authenticator.SoftAuthenticator(None, state=state)
    console.say(
        "Now add the key to your Apple Account on this Mac:\n\n"
        "  System Settings → your name → Sign-In & Security → Security Keys →\n"
        "  Add Security Key (the + button)\n\n"
        "Follow the prompts. When the Mac asks you to insert and activate the key, do "
        "nothing: the Pico answers by itself after two seconds. Do not touch any other "
        "security key while the dialog is open, and give the key a name you will "
        "recognise.\n\n"
        "If security keys are not switched on for the account yet, Apple asks for two "
        "keys during that first setup; do that with two ordinary keys first, then add "
        "this one."
    )
    with bridge.Bridge(port, soft, touch_delay) as running:
        while True:
            console.say("\nWaiting for the Mac to ask the key … (Ctrl-C to give up)")
            known = len(soft.credentials)
            while len(soft.credentials) == known:
                if running.error is not None:
                    raise SetupAborted(f"Lost the connection to the Pico: {running.error}")
                time.sleep(0.3)
            credential = soft.credentials[-1]
            if credential["rp_id"] != APPLE_RP:
                console.warn(f"That request came from {credential['rp_id']}, not Apple; ignoring it.")
                state["credentials"].remove(credential)
                continue
            console.ok("The key answered Apple's request")
            time.sleep(1)
            if console.confirm("Does Security Keys in System Settings now list the new key?"):
                break
            console.say(
                "Then Apple did not accept it. 'Could not connect to iCloud' with no further "
                "detail is what Apple shows when its servers refuse a key. Try Add Security "
                "Key once more."
            )
            state["credentials"].remove(credential)
    return [c for c in state["credentials"] if c["rp_id"] == APPLE_RP]


# ---- step 6: saving --------------------------------------------------------------------------


def write_backup(console: Console, plan: BackupPlan, private_key: Any, state: dict[str, Any]) -> None:
    text = backup.encode(private_key, state["aaguid"], state["credentials"])
    content = backup.encrypt(text, plan.passphrase) if plan.kind == "passphrase" else text + "\n"
    # Read it back the way a restore would before relying on it.
    check = backup.decrypt(content, plan.passphrase) if plan.kind == "passphrase" else content
    restored, _aaguid, credentials = backup.decode(check)
    if (
        restored.public_key().public_numbers() != private_key.public_key().public_numbers()
        or len(credentials) != len(state["credentials"])
    ):
        raise SetupAborted("The backup did not read back correctly; nothing was written.")
    for attribute, body in (("path", content), ("page", None)):
        while True:
            path = getattr(plan, attribute)
            if path is None:
                break
            try:
                backup.write_private(
                    path, body if body is not None else backup.page(content, "Apple Account security key")
                )
                console.ok(f"Wrote {path}")
                break
            except OSError as error:
                console.warn(f"Could not write {path}: {error}")
                setattr(plan, attribute, _free_path(console, "Write it where instead", path))


def run(
    console: Console,
    key_file: Path,
    serial: int | None = None,
    slot: str | None = None,
    touch_delay: float = bridge.TOUCH_DELAY,
    backup_dir: Path | None = None,
) -> Result:
    key_file = key_file.expanduser()
    if key_file.exists():
        raise SetupAborted(
            f"{key_file} exists already. It may point to a registered key: move it away or "
            "pass --out with another name."
        )
    key_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    console.say(
        "This sets up a security key for your Apple Account that confirms sign-ins without "
        "being touched. Its private key is held by a YubiKey; whoever has that YubiKey "
        "plugged in can have sign-ins confirmed, and pulling it out stops that.\n\n"
        "You need: a YubiKey 5 (or 4), a Raspberry Pi Pico or other RP2040/RP2350 board, "
        "and this Mac signed in to the Apple Account."
    )

    console.step(1, STEPS, "YubiKey")
    yubikey = choose_yubikey(console, serial)

    console.step(2, STEPS, "Where the key is made")
    plan = plan_backup(console, backup_dir or Path.home() / "Desktop")

    console.step(3, STEPS, "Create the key")
    reference, private_key = create_key(console, yubikey, plan, slot)
    state: dict[str, Any] = {
        "version": 1,
        "aaguid": os.urandom(16).hex(),
        "piv": reference,
        "credentials": [],
    }
    where = f"PIV slot {reference['slot']} of YubiKey {yubikey.serial}"
    try:
        console.step(4, STEPS, "Pico USB bridge")
        port = prepare_bridge(console)

        console.step(5, STEPS, "Register with Apple")
        accepted = register_with_apple(console, port, state, touch_delay)
    except (SetupAborted, KeyboardInterrupt, bridge.BridgeError) as error:
        reason = "Interrupted." if isinstance(error, KeyboardInterrupt) else str(error)
        raise SetupAborted(
            f"{reason}\nThe key in {where} is not registered with Apple and no key file was "
            "written. Run the setup again; it will use the next free slot."
        ) from error

    console.step(6, STEPS, "Save")
    state["credentials"] = accepted
    authenticator.write_key_file(
        str(key_file), {k: v for k, v in state.items() if k != "attestation"}
    )
    console.ok(f"Wrote {key_file} (points to the YubiKey; holds no secret)")
    if private_key is not None:
        write_backup(console, plan, private_key, state)
    del private_key
    return Result(key_file, yubikey.serial, reference["slot"], plan, len(accepted))


def summary(console: Console, result: Result) -> None:
    console.say(
        f"\nDone. The security key is registered and its private key is in PIV slot "
        f"{result.slot} of YubiKey {result.yubikey_serial}."
    )
    if result.backup.kind == "none":
        console.say("The key was generated inside that YubiKey and has never existed anywhere else. "
            "There is no backup.")
    else:
        kind = "encrypted with your passphrase" if result.backup.kind == "passphrase" else "in PLAIN TEXT"
        console.say(f"Backup ({kind}): {result.backup.path}")
        if result.backup.page:
            console.say(
                f"Page to print: {result.backup.page}\n"
                "Print it, then delete the HTML file and empty the Trash."
            )
        if result.backup.kind == "plain":
            console.say(
                "Move the plain-text backup off this Mac (it is a working security key), "
                "and keep it out of cloud sync and unencrypted backups."
            )
    console.say(
        "\nNext:\n"
        f"  apple-piv verify <apple-id> --key {result.key_file}\n"
        "      a real sign-in confirmed by the YubiKey, into a temporary folder\n"
        "  Unplug the Pico; it is only needed again to restore from a backup.\n"
        f"  Where sign-ins should be confirmed unattended, plug the YubiKey in and "
        f"provide {result.key_file.name} (see the README, 'Using the key')."
    )
