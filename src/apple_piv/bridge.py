"""The USB bridge: a Pico that lets the software key appear as a USB security key.

Apple only adds security keys through Settings on an Apple device, which
expects a USB (or NFC) key. A Raspberry Pi Pico with the firmware from this
repository enumerates as a FIDO HID key plus a serial port and relays the raw
64-byte packets between the two; the authenticator is this program at the
other end of the serial port. Nothing secret is on the board.
"""

from __future__ import annotations

import shutil
import threading
import time
from importlib import resources
from pathlib import Path
from typing import Any, Callable

from . import authenticator

VENDOR_ID, PRODUCT_ID = 0x1209, 0x0001  # pid.codes test id, as set in the firmware
BOOT_VOLUMES = {"RPI-RP2": "rp2040", "RP2350": "rp2350"}
# Seconds the key pretends a touch takes. Apple's dialog hangs when the key
# answers before the dialog has finished appearing.
TOUCH_DELAY = 2.0


class BridgeError(Exception):
    pass


# ---- finding and flashing the board ----------------------------------------------------------


def find_port() -> str | None:
    """Serial port of a board that runs the bridge firmware."""
    from serial.tools import list_ports

    ports = [p.device for p in list_ports.comports() if (p.vid, p.pid) == (VENDOR_ID, PRODUCT_ID)]
    if len(ports) > 1:
        raise BridgeError(f"several bridge boards are plugged in ({', '.join(ports)}); leave one")
    return ports[0] if ports else None


def find_bootloader(volumes: Path = Path("/Volumes")) -> tuple[Path, str] | None:
    """(mount point, chip) of a Pico waiting in its USB bootloader (BOOTSEL mode)."""
    for name, chip in BOOT_VOLUMES.items():
        volume = volumes / name
        info = volume / "INFO_UF2.TXT"
        if info.is_file():
            # RP2350 boards say so in INFO_UF2.TXT whatever the volume is called.
            if "RP2350" in info.read_text(errors="replace").upper():
                chip = "rp2350"
            return volume, chip
    return None


def firmware_path(chip: str) -> Any:
    return resources.files("apple_piv").joinpath("firmware", f"softkey_bridge-{chip}.uf2")


def flash(volume: Path, chip: str) -> None:
    """Copy the firmware onto the bootloader volume; the board then restarts into it."""
    with resources.as_file(firmware_path(chip)) as image:
        try:
            shutil.copyfile(image, volume / "softkey_bridge.uf2")
        except OSError:
            # The board reboots the moment the last block arrives, which can
            # pull the volume away before the copy call returns.
            if volume.exists() and (volume / "INFO_UF2.TXT").exists():
                raise


def wait_for_port(timeout: float = 30.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        port = find_port()
        if port:
            return port
        time.sleep(0.5)
    raise BridgeError("the board did not come up as a security key bridge after flashing")


# ---- serving ---------------------------------------------------------------------------------


class Bridge:
    """Answers the computer's requests to the board from an authenticator, in a thread."""

    def __init__(
        self,
        port: str,
        soft_authenticator: authenticator.SoftAuthenticator,
        touch_delay: float = TOUCH_DELAY,
    ) -> None:
        self._port = port
        self._session = authenticator.CtapHidSession(soft_authenticator, touch_delay)
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, name="softkey-bridge", daemon=True)
        self.error: Exception | None = None

    def __enter__(self) -> "Bridge":
        self._thread.start()
        if not self._ready.wait(10) and self.error is None:
            self.error = BridgeError("the bridge's serial port did not open")
        if self.error is not None:
            raise BridgeError(f"cannot talk to the board on {self._port}: {self.error}")
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(5)

    def _run(self) -> None:
        import serial

        try:
            # Opening raises DTR, at which the firmware drops half-sent packets.
            with serial.Serial(self._port, timeout=0.2) as link:
                link.reset_input_buffer()
                self._ready.set()
                buffer = b""
                while not self._stop.is_set():
                    buffer += link.read(authenticator.HID_PACKET - len(buffer))
                    if len(buffer) < authenticator.HID_PACKET:
                        continue
                    packet, buffer = buffer, b""
                    for reply in self._session.feed(packet):
                        link.write(reply)
                        link.flush()
        except Exception as error:  # noqa: BLE001 - reported to whoever waits on the bridge
            self.error = error
            self._ready.set()


def self_test(port: str, log: Callable[[str], None] | None = None) -> None:
    """Register and sign in against a local test server through real USB, with a throwaway key."""
    from fido2.client import DefaultClientDataCollector, Fido2Client
    from fido2.hid import CtapHidDevice
    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

    throwaway = authenticator.SoftAuthenticator(None, log)
    with Bridge(port, throwaway, touch_delay=0.3):
        time.sleep(0.5)
        devices = [
            d
            for d in CtapHidDevice.list_devices()
            if (d.descriptor.vid, d.descriptor.pid) == (VENDOR_ID, PRODUCT_ID)
        ]
        if not devices:
            raise BridgeError("this computer does not list the board as a security key")
        client = Fido2Client(
            devices[0], client_data_collector=DefaultClientDataCollector("https://bridge.test")
        )
        server = Fido2Server(PublicKeyCredentialRpEntity(id="bridge.test", name="self-test"))
        options, state = server.register_begin(
            PublicKeyCredentialUserEntity(id=b"self-test", name="self-test"),
            user_verification="discouraged",
        )
        credential = server.register_complete(
            state, client.make_credential(options.public_key)
        ).credential_data
        options, state = server.authenticate_begin([credential], user_verification="discouraged")
        assertion = client.get_assertion(options.public_key).get_response(0)
        server.authenticate_complete(state, [credential], assertion)
