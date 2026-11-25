"""Keep the software security key's private key inside a YubiKey.

The YubiKey's FIDO function insists on a touch for every sign-in, so it cannot
confirm an unattended one. Its PIV (smart card) function is different: a key
in a PIV slot can never be read out, and can be set to sign without touch or
PIN. The software security key (authenticator.py) then holds no secret at all:
it asks the YubiKey for each signature. Pull the YubiKey and no further
sign-in can be confirmed.

The YubiKey is reached through PC/SC where that exists (macOS, desktops, via
ykman) and otherwise directly over USB (pyusb), which suits a container that
has no smart-card daemon, only access to the USB device.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes

YUBICO_VENDOR_ID = 0x1050
_CCID_INTERFACE_CLASS = 0x0B


class PivError(Exception):
    """The YubiKey could not be asked (not plugged in, wrong one, no access)."""


def _usb_connection_class() -> Any:
    from yubikit.core import TRANSPORT
    from yubikit.core.smartcard import SmartCardConnection

    class UsbCcidConnection(SmartCardConnection):
        """APDUs to the YubiKey's smart-card interface, straight over USB (CCID)."""

        _POWER_ON, _POWER_OFF, _XFR_BLOCK = 0x62, 0x63, 0x6F
        _DATA_BLOCK, _SLOT_STATUS = 0x80, 0x81

        def __init__(self, device: Any) -> None:
            import usb.util

            self._device = device
            self._sequence = 0
            interface = None
            for candidate in device.get_active_configuration():
                if candidate.bInterfaceClass == _CCID_INTERFACE_CLASS:
                    interface = candidate
                    break
            if interface is None:
                raise PivError("this YubiKey has its smart-card (CCID) interface disabled")
            self._interface = interface.bInterfaceNumber
            try:
                if device.is_kernel_driver_active(self._interface):
                    device.detach_kernel_driver(self._interface)
            except (NotImplementedError, usb.core.USBError):
                pass
            usb.util.claim_interface(device, self._interface)

            def endpoint(direction: int) -> Any:
                return usb.util.find_descriptor(
                    interface,
                    custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress)
                    == direction
                    and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK,
                )

            self._out = endpoint(usb.util.ENDPOINT_OUT)
            self._in = endpoint(usb.util.ENDPOINT_IN)
            self._exchange(self._POWER_ON, b"")

        @property
        def transport(self) -> Any:
            return TRANSPORT.USB

        def _exchange(self, message_type: int, data: bytes) -> bytes:
            sequence = self._sequence
            self._sequence = (self._sequence + 1) % 256
            header = struct.pack("<BIBB3x", message_type, len(data), 0, sequence)
            self._out.write(header + data, timeout=5000)
            while True:
                reply = bytes(self._in.read(65556, timeout=30000))
                while len(reply) < 10 or len(reply) < 10 + struct.unpack_from("<I", reply, 1)[0]:
                    reply += bytes(self._in.read(65556, timeout=30000))
                kind, length, _slot, reply_sequence, status, error = struct.unpack_from(
                    "<BIBBBB", reply
                )
                if reply_sequence != sequence:
                    continue  # stale answer to an earlier message
                if status & 0xC0 == 0x80:
                    continue  # time extension: the card is still working
                if status & 0xC0 or kind not in (self._DATA_BLOCK, self._SLOT_STATUS):
                    raise PivError(f"the YubiKey refused a CCID message (status {status:#x}, error {error:#x})")
                return reply[10 : 10 + length]

        def send_and_receive(self, apdu: bytes) -> tuple[bytes, int]:
            reply = self._exchange(self._XFR_BLOCK, apdu)
            if len(reply) < 2:
                raise PivError("short answer from the YubiKey")
            return reply[:-2], int.from_bytes(reply[-2:], "big")

        def close(self) -> None:
            import usb.util

            try:
                self._exchange(self._POWER_OFF, b"")
            except Exception:  # noqa: BLE001 - closing a device that may be gone
                pass
            usb.util.release_interface(self._device, self._interface)
            usb.util.dispose_resources(self._device)

    return UsbCcidConnection


def _serial_of(connection: Any) -> int | None:
    from yubikit.management import ManagementSession

    return ManagementSession(connection).read_device_info().serial


def _open_pcsc(serial: int | None) -> Any | None:
    """A PC/SC connection, or None when this machine has no PC/SC to ask."""
    try:
        from ykman.device import list_all_devices
        from yubikit.core.smartcard import SmartCardConnection
    except ImportError:
        return None
    try:
        devices = list_all_devices()
    except Exception:  # noqa: BLE001 - no PC/SC service running
        return None
    for device, info in devices:
        if serial in (None, info.serial) and device.supports_connection(SmartCardConnection):
            return device.open_connection(SmartCardConnection)
    return None


def usb_backend() -> Any | None:
    """libusb for pyusb, or None when it cannot start.

    libusb refuses to initialise when there is no USB bus to look at, which is
    the case in a container that /dev/bus/usb was not passed to.
    """
    import usb.backend.libusb1

    return usb.backend.libusb1.get_backend()


def _open_usb(serial: int | None) -> Any | None:
    try:
        import usb.core
    except ImportError:
        return None
    backend = usb_backend()
    if backend is None:
        raise PivError(
            "no USB access: pass /dev/bus/usb through to the container "
            "(or libusb is not installed)"
        )
    connection_class = _usb_connection_class()
    last_error: Exception | None = None
    for device in usb.core.find(find_all=True, idVendor=YUBICO_VENDOR_ID, backend=backend):
        try:
            connection = connection_class(device)
        except (PivError, usb.core.USBError) as error:
            last_error = error
            continue
        if serial is None or _serial_of(connection) == serial:
            return connection
        connection.close()
    if last_error is not None:
        raise PivError(f"a YubiKey is plugged in but cannot be used: {last_error}")
    return None


def open_connection(serial: int | None = None) -> Any:
    connection = _open_pcsc(serial) or _open_usb(serial)
    if connection is None:
        which = f"YubiKey {serial}" if serial else "a YubiKey"
        raise PivError(f"{which} is not plugged in (or not passed through to this container)")
    return connection


def slot_of(piv: dict[str, Any]) -> Any:
    from yubikit.piv import SLOT

    return SLOT(int(str(piv["slot"]), 16))


def sign(
    piv: dict[str, Any], message: bytes, attempts: int = 10, pause: float = 1.0
) -> bytes:
    """ECDSA P-256 / SHA-256 signature (DER) by the key in the configured slot.

    Retried for a few seconds: two containers may share one YubiKey, and only
    one of them can hold its USB interface at a time.
    """
    import time

    from yubikit.piv import KEY_TYPE, PivSession

    last_error: Exception | None = None
    for attempt in range(attempts):
        if attempt:
            time.sleep(pause)
        try:
            with open_connection(piv.get("serial")) as connection:
                return PivSession(connection).sign(
                    slot_of(piv), KEY_TYPE.ECCP256, message, hashes.SHA256()
                )
        except Exception as error:  # noqa: BLE001 - USB busy, YubiKey just replugged, ...
            last_error = error
    raise PivError(f"the YubiKey did not sign after {attempts} attempts: {last_error}")


def usb_device_nodes() -> list[str]:
    """Device nodes of the YubiKeys that are plugged in (Linux)."""
    from pathlib import Path

    nodes = []
    for device in Path("/sys/bus/usb/devices").glob("*"):
        try:
            if int((device / "idVendor").read_text(), 16) != YUBICO_VENDOR_ID:
                continue
            bus = int((device / "busnum").read_text())
            number = int((device / "devnum").read_text())
        except (OSError, ValueError):
            continue
        nodes.append(f"/dev/bus/usb/{bus:03d}/{number:03d}")
    return nodes


# ---- setting a YubiKey up (interactive use, PC/SC) -------------------------------------------


@dataclass
class YubiKey:
    device: Any
    serial: int
    version: str
    name: str


def list_yubikeys() -> list[YubiKey]:
    """YubiKeys with a usable smart-card interface, via PC/SC."""
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.support import get_name

    found = []
    for device, info in list_all_devices():
        if info.serial is None or not device.supports_connection(SmartCardConnection):
            continue
        try:
            name = get_name(info, None)
        except Exception:  # noqa: BLE001 - a model ykman does not know by name
            name = "YubiKey"
        found.append(YubiKey(device, info.serial, str(info.version), name))
    return found


class PivSetup:
    """One YubiKey's PIV application, for creating the key. Use as a context manager."""

    def __init__(self, yubikey: YubiKey) -> None:
        self.yubikey = yubikey
        self._connection: Any = None
        self._session: Any = None
        self._key_type: Any = None

    def __enter__(self) -> "PivSetup":
        from yubikit.core.smartcard import SmartCardConnection
        from yubikit.piv import PivSession

        self._connection = self.yubikey.device.open_connection(SmartCardConnection)
        self._session = PivSession(self._connection)
        return self

    def __exit__(self, *_exc: object) -> None:
        self._connection.close()

    def supports_metadata(self) -> bool:
        """Whether this YubiKey's firmware (>= 5.3) can report bare keys without certificates."""
        return self._session.version >= (5, 3, 0)

    def _has_key(self, slot: Any) -> bool:
        from yubikit.core import NotSupportedError
        from yubikit.core.smartcard import SW, ApduError

        try:
            self._session.get_slot_metadata(slot)
            return True
        except ApduError as error:
            if error.sw == SW.REFERENCE_DATA_NOT_FOUND:
                return False
            raise PivError(f"cannot inspect PIV slot {slot.value:02x}: {error}") from error
        except NotSupportedError:
            # Firmware before 5.3 has no slot metadata. Attestation (4.3+) still detects
            # keys generated on the YubiKey even when no certificate is stored.
            try:
                self._session.attest_key(slot)
                return True
            except NotSupportedError:
                return False
            except ApduError as error:
                if error.sw in (
                    SW.INCORRECT_PARAMETERS,
                    SW.CONDITIONS_NOT_SATISFIED,
                    SW.FILE_NOT_FOUND,
                    SW.REFERENCE_DATA_NOT_FOUND,
                ):
                    return False
                raise PivError(f"cannot inspect PIV slot {slot.value:02x}: {error}") from error

    def _has_certificate(self, slot: Any) -> bool:
        from yubikit.core import BadResponseError
        from yubikit.core.smartcard import SW, ApduError
        from yubikit.piv import OBJECT_ID

        try:
            return bool(self._session.get_object(OBJECT_ID.from_slot(slot)))
        except BadResponseError:
            # Malformed data is still data in the slot; never overwrite it.
            return True
        except ApduError as error:
            if error.sw == SW.FILE_NOT_FOUND:
                return False
            raise PivError(f"cannot inspect PIV slot {slot.value:02x}: {error}") from error

    def _occupied(self, slot: Any) -> bool:
        return self._has_key(slot) or self._has_certificate(slot)

    def free_slots(self) -> list[Any]:
        """Retired slots (82-95) that hold nothing. Other slots are never offered."""
        from yubikit.piv import SLOT

        return [s for s in SLOT if s.name.startswith("RETIRED") and not self._occupied(s)]

    def is_free(self, slot: Any) -> bool:
        return not self._occupied(slot)

    def management_key_kind(self) -> str:
        """'default', 'pin-protected' (stored on the YubiKey, released by the PIN) or 'custom'."""
        from ykman.piv import get_pivman_data
        from yubikit.core import NotSupportedError
        from yubikit.piv import MANAGEMENT_KEY_TYPE

        try:
            metadata = self._session.get_management_key_metadata()
            self._key_type = metadata.key_type
            if metadata.default_value:
                return "default"
        except NotSupportedError:
            self._key_type = MANAGEMENT_KEY_TYPE.TDES
        if get_pivman_data(self._session).has_protected_key:
            return "pin-protected"
        return "custom"

    def unlock(self, pin: str | None = None, management_key: bytes | None = None) -> None:
        """Authenticate for writing a key: default key, the PIN-protected one, or a given key."""
        from ykman.piv import get_pivman_protected_data
        from yubikit.piv import DEFAULT_MANAGEMENT_KEY

        if self._key_type is None:
            self.management_key_kind()
        if management_key is None and pin is not None:
            self._session.verify_pin(pin)
            management_key = get_pivman_protected_data(self._session).key
            if management_key is None:
                raise PivError("this YubiKey holds no PIN-protected management key")
        if management_key is None:
            management_key = DEFAULT_MANAGEMENT_KEY
        self._session.authenticate(self._key_type, management_key)

    def _write_certificate(self, slot: Any, public_key: Any) -> None:
        """Store a self-signed certificate so the slot is visibly occupied on all firmware."""
        import datetime

        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from ykman.piv import sign_certificate_builder
        from yubikit.piv import KEY_TYPE

        now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        until = now + datetime.timedelta(days=365 * 30)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "apple-piv")])
        builder = (
            x509.CertificateBuilder()
            .public_key(public_key)
            .subject_name(subject)
            .issuer_name(subject)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(until)
        )
        certificate = sign_certificate_builder(
            self._session, slot, KEY_TYPE.ECCP256, builder, hashes.SHA256
        )
        self._session.put_certificate(slot, certificate)

    def generate(self, slot: Any) -> Any:
        """Create the key inside the YubiKey. It never exists anywhere else."""
        from yubikit.piv import KEY_TYPE, PIN_POLICY, TOUCH_POLICY

        if self._occupied(slot):
            raise PivError(f"PIV slot {slot.value:02x} already holds a key or certificate")
        public_key = self._session.generate_key(
            slot, KEY_TYPE.ECCP256, PIN_POLICY.NEVER, TOUCH_POLICY.NEVER
        )
        self._write_certificate(slot, public_key)
        return public_key

    def import_key(self, slot: Any, private_key: Any) -> Any:
        """Put an existing P-256 key into the YubiKey (so that a backup of it can exist)."""
        from yubikit.piv import PIN_POLICY, TOUCH_POLICY

        if self._occupied(slot):
            raise PivError(f"PIV slot {slot.value:02x} already holds a key or certificate")
        self._session.put_key(slot, private_key, PIN_POLICY.NEVER, TOUCH_POLICY.NEVER)
        public_key = private_key.public_key()
        self._write_certificate(slot, public_key)
        return public_key

    def test_signature(self, slot: Any, public_key: Any) -> None:
        """Sign once without touch or PIN, exactly as an unattended sign-in will."""
        import os

        from cryptography.hazmat.primitives.asymmetric import ec
        from yubikit.piv import KEY_TYPE

        message = os.urandom(32)
        signature = self._session.sign(slot, KEY_TYPE.ECCP256, message, hashes.SHA256())
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))


def key_reference(yubikey: YubiKey, slot: Any, public_key: Any) -> dict[str, Any]:
    """The ``piv`` entry of a key file: where the private key is, and its public half."""
    from cryptography.hazmat.primitives import serialization

    return {
        "serial": yubikey.serial,
        "slot": f"{slot.value:02x}",
        "public_key": public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(),
    }
