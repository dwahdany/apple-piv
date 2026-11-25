"""Command line: apple-piv setup | verify | restore | bridge."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .console import Console

DEFAULT_KEY_FILE = Path("~/.config/apple-piv/softkey.json")


def _setup(args: argparse.Namespace, console: Console) -> int:
    from . import piv, wizard

    try:
        result = wizard.run(
            console,
            Path(args.out),
            serial=args.serial,
            slot=args.slot,
            touch_delay=args.touch_delay,
        )
    except wizard.SetupAborted as error:
        console.say(f"\nSetup stopped: {error}")
        return 1
    except KeyboardInterrupt:
        console.say("\nSetup interrupted.")
        return 130
    except piv.PivError as error:
        console.say(f"\nSetup stopped: {error}")
        return 1
    wizard.summary(console, result)
    return 0


def _verify(args: argparse.Namespace, console: Console) -> int:
    from . import verify

    console.say(
        "Signing in to iCloud with icloudpd, into a temporary folder. Type the account "
        "password at icloudpd's prompt; the security key answers on its own. If the key "
        "is held by a YubiKey, it must be plugged in."
    )
    try:
        accepted = verify.run(Path(args.key), args.apple_id, args.domain)
    except verify.VerifyError as error:
        console.say(f"error: {error}")
        return 2
    if accepted:
        console.say("\nOK: Apple accepted the security key and issued a trusted session.")
        return 0
    console.say("\nFAILED: the sign-in did not end with a trusted session.")
    return 1


def _restore(args: argparse.Namespace, console: Console) -> int:
    from . import authenticator, backup, piv, wizard

    out = Path(args.out).expanduser()
    if out.exists():
        console.say(f"error: {out} exists already")
        return 2
    source = sys.stdin.read() if args.backup == "-" else Path(args.backup).expanduser().read_text()
    try:
        if backup.is_encrypted(source):
            source = backup.decrypt(source, console.secret("Passphrase of the backup"))
        private_key, aaguid, credentials = backup.decode(source)
    except backup.BackupError as error:
        console.say(f"error: {error}")
        return 1
    out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.to_yubikey:
        from yubikit.piv import SLOT

        try:
            yubikey = wizard.choose_yubikey(console, args.serial)
            with piv.PivSetup(yubikey) as setup:
                if args.slot:
                    slot = SLOT(int(args.slot, 16))
                    if not setup.is_free(slot):
                        raise wizard.SetupAborted(f"slot {args.slot} already holds a key; left untouched")
                else:
                    free = setup.free_slots()
                    if not free:
                        raise wizard.SetupAborted("no free retired PIV slot (82-95) on this YubiKey")
                    slot = free[0]
                wizard.unlock(console, setup)
                public_key = setup.import_key(slot, private_key)
                setup.test_signature(slot, public_key)
        except wizard.SetupAborted as error:
            console.say(f"error: {error}")
            return 1
        state = {
            "version": 1,
            "aaguid": aaguid,
            "piv": piv.key_reference(yubikey, slot, public_key),
            "credentials": credentials,
        }
        authenticator.write_key_file(str(out), state)
        console.say(
            f"The key is in PIV slot {slot.value:02x} of YubiKey {yubikey.serial}; "
            f"wrote {out} (points to it, holds no secret)."
        )
    else:
        authenticator.write_key_file(str(out), backup.to_key_file(source))
        console.say(
            f"Wrote {out}. This file holds the private key itself: it is a working "
            "security key for anyone who can read it."
        )
    return 0


def _bridge(args: argparse.Namespace, console: Console) -> int:
    from . import authenticator, bridge

    key = Path(args.key).expanduser()
    if not key.is_file():
        console.say(f"error: no key file at {key}")
        return 2
    try:
        port = bridge.find_port()
        if not port:
            found = bridge.find_bootloader()
            if not found:
                console.say(
                    "error: no Pico found. Plug it in while holding BOOTSEL (to flash it), "
                    "or plug in one that already runs the bridge firmware."
                )
                return 2
            bridge.flash(*found)
            port = bridge.wait_for_port()
        soft = authenticator.SoftAuthenticator(str(key), lambda m: print(f"{time.strftime('%H:%M:%S')} {m}", flush=True))
        with bridge.Bridge(port, soft, args.touch_delay) as running:
            console.say(
                "This Mac now sees a USB security key that answers without a touch. "
                "Press Ctrl-C to stop."
            )
            while running.error is None:
                time.sleep(0.5)
            console.say(f"error: lost the connection to the Pico: {running.error}")
            return 1
    except bridge.BridgeError as error:
        console.say(f"error: {error}")
        return 1
    except KeyboardInterrupt:
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="apple-piv",
        description="A touch-free security key for an Apple Account, with its private key held by a YubiKey.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    setup = commands.add_parser("setup", help="guided setup: YubiKey, backup, Pico, registration with Apple")
    setup.add_argument("--out", default=str(DEFAULT_KEY_FILE), help=f"key file to write (default: {DEFAULT_KEY_FILE})")
    setup.add_argument("--serial", type=int, help="serial number of the YubiKey to use")
    setup.add_argument("--slot", help="PIV slot in hex (default: the first free retired slot, 82-95)")
    setup.add_argument("--touch-delay", type=float, default=2.0, help=argparse.SUPPRESS)
    setup.set_defaults(run=_setup)

    verify = commands.add_parser("verify", help="check the key with a real iCloud sign-in (temporary session)")
    verify.add_argument("apple_id")
    verify.add_argument("--key", default=str(DEFAULT_KEY_FILE))
    verify.add_argument("--domain", default="com", choices=["com", "cn"])
    verify.set_defaults(run=_verify)

    restore = commands.add_parser("restore", help="make a key file (or a YubiKey) from a backup")
    restore.add_argument("backup", help="backup file, or - to read the text from standard input")
    restore.add_argument("--out", default=str(DEFAULT_KEY_FILE), help="key file to write")
    restore.add_argument("--to-yubikey", action="store_true", help="move the key into a YubiKey instead of keeping it in the key file")
    restore.add_argument("--serial", type=int, help="serial number of the YubiKey to use")
    restore.add_argument("--slot", help="PIV slot in hex")
    restore.set_defaults(run=_restore)

    serve = commands.add_parser("bridge", help="present a key file as a USB security key through the Pico")
    serve.add_argument("--key", default=str(DEFAULT_KEY_FILE))
    serve.add_argument("--touch-delay", type=float, default=2.0, help=argparse.SUPPRESS)
    serve.set_defaults(run=_bridge)

    args = parser.parse_args(argv)
    return args.run(args, Console())


if __name__ == "__main__":
    sys.exit(main())
