"""The guided setup from start to finish, with stand-ins for terminal, YubiKey and Pico."""

import base64
import json
import threading
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor

from apple_piv import authenticator, backup, bridge, piv, wizard

PIN = "246810"


class FakeConsole:
    """Answers prompts from a script; fails the test on a prompt nobody expected."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.lines = []

    def _next(self, kind, prompt):
        assert self.answers, f"unexpected {kind} prompt: {prompt!r}"
        expected, value = self.answers.pop(0)
        assert expected == kind, f"expected a {expected} prompt, got {kind}: {prompt!r}"
        self.lines.append(f"{kind}: {prompt}")
        return value

    def say(self, text=""):
        self.lines.append(text)

    ok = warn = say

    def step(self, number, total, title):
        self.lines.append(f"[{number}/{total}] {title}")

    def ask(self, prompt, default=None):
        value = self._next("ask", prompt)
        return default if value is None else value

    def confirm(self, prompt, default=True):
        return self._next("confirm", prompt)

    def choose(self, prompt, options, default=0):
        return self._next("choose", prompt)

    def secret(self, prompt):
        return self._next("secret", prompt)

    def wait(self, prompt):
        self._next("wait", prompt)

    @property
    def text(self):
        return "\n".join(self.lines)


class FakeYubiKeys:
    """One YubiKey: its slots hold private keys that never leave this object."""

    def __init__(self, kind="default", occupied=(), version="5.7.4"):
        from yubikit.piv import SLOT

        self.kind = kind
        self.slots = {SLOT(int(s, 16)): "someone else's key" for s in occupied}
        self.plugged_in = True
        self.unlocked = False
        self.pin_attempts = 3
        self.key = piv.YubiKey(device=None, serial=1234567, version=version, name="YubiKey 5 NFC")
        outer = self

        class Setup:
            def __init__(self, yubikey):
                assert yubikey is outer.key
                self.yubikey = yubikey

            def __enter__(self):
                outer.unlocked = False
                return self

            def __exit__(self, *_exc):
                pass

            def supports_metadata(self):
                return tuple(int(part) for part in outer.key.version.split(".")) >= (5, 3, 0)

            def free_slots(self):
                return [s for s in SLOT if s.name.startswith("RETIRED") and s not in outer.slots]

            def is_free(self, slot):
                return slot not in outer.slots

            def management_key_kind(self):
                return outer.kind

            def unlock(self, pin=None, management_key=None):
                from yubikit.core import InvalidPinError
                from yubikit.core.smartcard import ApduError

                if outer.kind == "pin-protected":
                    if pin != PIN:
                        outer.pin_attempts -= 1
                        raise InvalidPinError(outer.pin_attempts)
                elif outer.kind == "custom" and management_key != b"k" * 24:
                    raise ApduError(b"", 0x6982)
                outer.unlocked = True

            def generate(self, slot):
                assert outer.unlocked and slot not in outer.slots
                outer.slots[slot] = ec.generate_private_key(ec.SECP256R1())
                outer.generated = True
                return outer.slots[slot].public_key()

            def import_key(self, slot, private_key):
                assert outer.unlocked and slot not in outer.slots
                outer.slots[slot] = private_key
                outer.generated = False
                return private_key.public_key()

            def test_signature(self, slot, public_key):
                message = b"test"
                public_key.verify(
                    outer.slots[slot].sign(message, ec.ECDSA(hashes.SHA256())),
                    message,
                    ec.ECDSA(hashes.SHA256()),
                )

        self.Setup = Setup

    def list(self):
        return [self.key] if self.plugged_in else []

    def sign(self, reference, message):
        from yubikit.piv import SLOT

        assert reference["serial"] == self.key.serial
        return self.slots[SLOT(int(reference["slot"], 16))].sign(message, ec.ECDSA(hashes.SHA256()))


class FakePico:
    """The Pico and, behind it, the Mac asking the key to register with Apple."""

    def __init__(self, flashed=False, bootloader=True, fail_link=False, first_rp="apple.com"):
        self.flashed, self.bootloader, self.fail_link = flashed, bootloader, fail_link
        self.flash_calls, self.self_tests, self.requests = [], 0, 0
        self.rps = [first_rp]
        outer = self

        class Bridge:
            def __init__(self, port, soft, touch_delay):
                assert port == "/dev/cu.fake"
                self.soft, self.error = soft, None
                self._stop = threading.Event()

            def __enter__(self):
                threading.Thread(target=self._apple, daemon=True).start()
                return self

            def __exit__(self, *_exc):
                self._stop.set()

            def _apple(self):
                """Ask for a credential whenever the key holds none (first time, and after a refusal)."""
                while not self._stop.is_set():
                    if not self.soft.credentials:
                        if outer.fail_link:
                            self.error = OSError("device disconnected")
                            return
                        rp = outer.rps.pop(0) if outer.rps else "apple.com"
                        outer.requests += 1
                        reply = self.soft.handle(
                            b"\x01"
                            + cbor.encode(
                                {
                                    1: b"h" * 32,
                                    2: {"id": rp},
                                    3: {"id": b"u" * 44, "name": " "},
                                    4: [{"alg": -7, "type": "public-key"}],
                                }
                            )
                        )
                        assert reply[0] == 0
                    time.sleep(0.02)

        self.Bridge = Bridge

    def find_port(self):
        return "/dev/cu.fake" if self.flashed else None

    def find_bootloader(self):
        return ("/Volumes/RPI-RP2", "rp2040") if self.bootloader else None

    def flash(self, volume, chip):
        self.flash_calls.append((volume, chip))
        self.flashed = True

    def wait_for_port(self):
        return "/dev/cu.fake"

    def self_test(self, port):
        self.self_tests += 1


@pytest.fixture
def world(monkeypatch, tmp_path):
    def build(yubikeys=None, pico=None):
        yubikeys = yubikeys or FakeYubiKeys()
        pico = pico or FakePico()
        monkeypatch.setattr(piv, "list_yubikeys", yubikeys.list)
        monkeypatch.setattr(piv, "PivSetup", yubikeys.Setup)
        for name in ("find_port", "find_bootloader", "flash", "wait_for_port", "self_test"):
            monkeypatch.setattr(bridge, name, getattr(pico, name))
        monkeypatch.setattr(bridge, "Bridge", pico.Bridge)
        return yubikeys, pico

    return build


def _sign_in(key_file, yubikeys):
    """A sign-in challenge answered from the key file, signed by the (fake) YubiKey."""
    state = json.loads(key_file.read_text())
    soft = authenticator.SoftAuthenticator(str(key_file), hardware_sign=yubikeys.sign)
    reply = soft.handle(
        b"\x02"
        + cbor.encode(
            {
                1: "apple.com",
                2: b"c" * 32,
                3: [{"id": base64.b64decode(c["id"]), "type": "public-key"} for c in state["credentials"]],
            }
        )
    )
    assert reply[0] == 0
    answer = cbor.decode(reply[1:])
    serialization.load_pem_public_key(state["piv"]["public_key"].encode()).verify(
        answer[3], answer[2] + b"c" * 32, ec.ECDSA(hashes.SHA256())
    )


def test_no_backup_key_is_made_in_the_yubikey_and_pico_gets_flashed(world, tmp_path):
    yubikeys, pico = world()
    console = FakeConsole([("choose", 0), ("confirm", True)])
    key_file = tmp_path / "config" / "softkey.json"

    result = wizard.run(console, key_file, backup_dir=tmp_path)

    assert yubikeys.generated is True
    assert pico.flash_calls == [("/Volumes/RPI-RP2", "rp2040")] and pico.self_tests == 1
    state = json.loads(key_file.read_text())
    assert state["piv"]["serial"] == 1234567 and state["piv"]["slot"] == "82"
    assert len(state["credentials"]) == 1 and state["credentials"][0]["rp_id"] == "apple.com"
    assert "PRIVATE" not in key_file.read_text() and "attestation" not in state
    assert result.backup.kind == "none" and [p.name for p in tmp_path.iterdir()] == ["config"]
    assert "factory default" in console.text  # told to change the default management key
    _sign_in(key_file, yubikeys)
    wizard.summary(console, result)
    assert "There is no backup" in console.text and "generated inside" in console.text


def test_passphrase_backup_pin_protected_yubikey_and_a_refusal_by_apple(world, tmp_path):
    yubikeys, pico = world(FakeYubiKeys(kind="pin-protected", occupied=["82"]), FakePico(flashed=True))
    console = FakeConsole(
        [
            ("choose", 1),
            ("secret", "short"),  # too short
            ("secret", "correct horse battery"),
            ("secret", "correct horse batteri"),  # mistyped
            ("secret", "correct horse battery"),
            ("secret", "correct horse battery"),
            ("ask", None),  # backup file: default
            ("confirm", True),  # printable page
            ("ask", None),
            ("secret", "000000"),  # wrong PIN once
            ("secret", PIN),
            ("confirm", False),  # Apple showed an error
            ("confirm", True),
        ]
    )
    key_file = tmp_path / "softkey.json"

    result = wizard.run(console, key_file, backup_dir=tmp_path)

    assert yubikeys.generated is False and pico.flash_calls == [] and pico.requests == 2
    state = json.loads(key_file.read_text())
    assert state["piv"]["slot"] == "83"  # 82 was taken and left alone
    assert yubikeys.slots[next(iter(yubikeys.slots))] == "someone else's key"
    assert len(state["credentials"]) == 1  # the refused one is not kept
    armored = (tmp_path / "apple-piv-backup.age").read_text()
    assert backup.is_encrypted(armored)
    restored, aaguid, credentials = backup.decode(backup.decrypt(armored, "correct horse battery"))
    from yubikit.piv import SLOT

    assert (
        restored.private_numbers().private_value
        == yubikeys.slots[SLOT.RETIRED2].private_numbers().private_value
    )
    assert aaguid == state["aaguid"] and [c["id"] for c in credentials] == [state["credentials"][0]["id"]]
    assert "<svg" in (tmp_path / "apple-piv-backup.html").read_text()
    assert "PRIVATE" not in key_file.read_text()
    _sign_in(key_file, yubikeys)
    # A key file restored from the backup signs in as well, with no YubiKey at all.
    restored_file = tmp_path / "restored.json"
    authenticator.write_key_file(
        str(restored_file), backup.to_key_file(backup.decrypt(armored, "correct horse battery"))
    )
    soft = authenticator.SoftAuthenticator(str(restored_file))
    reply = soft.handle(
        b"\x02"
        + cbor.encode(
            {1: "apple.com", 2: b"c" * 32, 3: [{"id": base64.b64decode(credentials[0]["id"]), "type": "public-key"}]}
        )
    )
    assert reply[0] == 0
    wizard.summary(console, result)
    assert "encrypted with your passphrase" in console.text


def test_plain_backup_asks_again_for_a_name_that_is_taken(world, tmp_path):
    yubikeys, _pico = world()
    (tmp_path / "apple-piv-backup.txt").write_text("already here")
    console = FakeConsole(
        [
            ("choose", 2),
            ("ask", None),  # default name: taken
            ("ask", str(tmp_path / "key-backup.txt")),
            ("confirm", False),  # no page
            ("confirm", True),
        ]
    )

    result = wizard.run(console, tmp_path / "softkey.json", backup_dir=tmp_path)

    assert (tmp_path / "apple-piv-backup.txt").read_text() == "already here"
    restored, _aaguid, credentials = backup.decode((tmp_path / "key-backup.txt").read_text())
    assert len(credentials) == 1 and restored is not None
    wizard.summary(console, result)
    assert "PLAIN TEXT" in console.text


def test_waits_for_yubikey_and_for_the_pico_in_bootloader_mode(world, tmp_path):
    yubikeys, pico = world(pico=FakePico(bootloader=False))
    yubikeys.plugged_in = False

    class Console(FakeConsole):
        def wait(self, prompt):
            super().wait(prompt)
            if "YubiKey" in prompt:
                yubikeys.plugged_in = True
            else:
                pico.bootloader = True

    console = Console([("wait", None), ("choose", 0), ("wait", None), ("confirm", True)])
    wizard.run(console, tmp_path / "softkey.json", backup_dir=tmp_path)
    assert "BOOTSEL" in console.text and pico.flash_calls


def test_request_from_another_site_is_ignored(world, tmp_path):
    yubikeys, pico = world(pico=FakePico(first_rp="example.org"))
    console = FakeConsole([("choose", 0), ("confirm", True)])
    wizard.run(console, tmp_path / "softkey.json", backup_dir=tmp_path)
    state = json.loads((tmp_path / "softkey.json").read_text())
    assert [c["rp_id"] for c in state["credentials"]] == ["apple.com"] and pico.requests == 2


def test_existing_key_file_stops_before_anything_is_touched(world, tmp_path):
    yubikeys, pico = world()
    key_file = tmp_path / "softkey.json"
    key_file.write_text("{}")
    with pytest.raises(wizard.SetupAborted, match="exists already"):
        wizard.run(FakeConsole([]), key_file, backup_dir=tmp_path)
    assert yubikeys.slots == {} and key_file.read_text() == "{}"


def test_occupied_slot_is_never_overwritten(world, tmp_path):
    yubikeys, _pico = world(FakeYubiKeys(occupied=["85"]))
    with pytest.raises(wizard.SetupAborted, match="left untouched"):
        wizard.run(FakeConsole([("choose", 0)]), tmp_path / "softkey.json", slot="85", backup_dir=tmp_path)
    assert list(yubikeys.slots.values()) == ["someone else's key"]
    assert not (tmp_path / "softkey.json").exists()


def test_wrong_pin_stops_before_the_pin_gets_blocked(world, tmp_path):
    yubikeys, _pico = world(FakeYubiKeys(kind="pin-protected"))
    console = FakeConsole([("choose", 0), ("secret", "111111"), ("secret", "222222")])
    with pytest.raises(wizard.SetupAborted, match="does not get blocked"):
        wizard.run(console, tmp_path / "softkey.json", backup_dir=tmp_path)
    assert yubikeys.pin_attempts == 1 and yubikeys.slots == {}


def test_losing_the_pico_says_which_slot_holds_an_unregistered_key(world, tmp_path):
    yubikeys, _pico = world(pico=FakePico(fail_link=True))
    console = FakeConsole([("choose", 0)])
    with pytest.raises(wizard.SetupAborted) as error:
        wizard.run(console, tmp_path / "softkey.json", backup_dir=tmp_path)
    assert "PIV slot 82 of YubiKey 1234567" in str(error.value)
    assert "not registered" in str(error.value)
    assert not (tmp_path / "softkey.json").exists()


def test_firmware_below_5_3_asks_before_writing_and_aborts_if_declined(world, tmp_path):
    yubikeys, _pico = world(FakeYubiKeys(version="4.3.7"))
    console = FakeConsole([("choose", 0), ("confirm", False)])
    with pytest.raises(wizard.SetupAborted, match="left untouched"):
        wizard.run(console, tmp_path / "softkey.json", backup_dir=tmp_path)
    assert "4.3.7" in console.text and "cannot detect imported PIV keys" in console.text
    assert yubikeys.slots == {}
    assert not (tmp_path / "softkey.json").exists()


def test_firmware_below_5_3_proceeds_when_confirmed(world, tmp_path):
    yubikeys, _pico = world(FakeYubiKeys(version="4.3.7"))
    console = FakeConsole([("choose", 0), ("confirm", True), ("confirm", True)])
    wizard.run(console, tmp_path / "softkey.json", backup_dir=tmp_path)
    assert "4.3.7" in console.text
    assert (tmp_path / "softkey.json").is_file()


def test_restore_to_yubikey_refuses_occupied_slot_and_confirms_below_5_3(world, tmp_path):
    from apple_piv import cli

    key = ec.generate_private_key(ec.SECP256R1())
    backup_file = tmp_path / "backup.txt"
    backup_file.write_text(
        backup.encode(key, "ab" * 16, [{"id": "QUJD", "rp_id": "apple.com", "user_id": ""}])
    )

    yubikeys, _pico = world(FakeYubiKeys(occupied=["85"], version="4.3.7"))
    args = type(
        "Args",
        (),
        {
            "backup": str(backup_file),
            "out": str(tmp_path / "out.json"),
            "to_yubikey": True,
            "serial": None,
            "slot": "85",
        },
    )()
    assert cli._restore(args, FakeConsole([])) == 1
    assert list(yubikeys.slots.values()) == ["someone else's key"]

    args.slot = None
    assert cli._restore(args, FakeConsole([("confirm", False)])) == 1
    assert not (tmp_path / "out.json").exists()


