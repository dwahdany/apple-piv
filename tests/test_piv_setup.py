"""PIV slot occupancy checks and marker certificates on all YubiKey firmware versions."""

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

pytest.importorskip("yubikit")

from yubikit.core import BadResponseError, NotSupportedError  # noqa: E402
from yubikit.core.smartcard import SW, ApduError  # noqa: E402
from yubikit.piv import KEY_TYPE, OBJECT_ID, SLOT  # noqa: E402

from apple_piv import piv  # noqa: E402


class _FakePivSession:
    """In-memory stand-in for yubikit.piv.PivSession across firmware generations."""

    def __init__(self, version=(5, 7, 4)):
        self.version = version
        self.keys = {}  # slot -> (private_key, generated: bool)
        self.objects = {}  # object_id -> bytes | Exception
        self.certs = {}  # slot -> x509.Certificate
        self.metadata_errors = {}  # slot -> int (SW)
        self.attest_errors = {}  # slot -> int (SW)

    def get_slot_metadata(self, slot):
        if self.version < (5, 3, 0):
            raise NotSupportedError()
        if slot in self.metadata_errors:
            raise ApduError(b"", self.metadata_errors[slot])
        if slot not in self.keys:
            raise ApduError(b"", SW.REFERENCE_DATA_NOT_FOUND)
        return object()

    def attest_key(self, slot):
        if self.version < (4, 3, 0):
            raise NotSupportedError()
        if slot in self.attest_errors:
            raise ApduError(b"", self.attest_errors[slot])
        entry = self.keys.get(slot)
        if entry is None or not entry[1]:  # absent or imported
            raise ApduError(b"", SW.INCORRECT_PARAMETERS)
        return object()

    def get_object(self, object_id):
        if object_id not in self.objects:
            raise ApduError(b"", SW.FILE_NOT_FOUND)
        value = self.objects[object_id]
        if isinstance(value, Exception):
            raise value
        return value

    def generate_key(self, slot, key_type, pin_policy, touch_policy):
        assert key_type == KEY_TYPE.ECCP256
        key = ec.generate_private_key(ec.SECP256R1())
        self.keys[slot] = (key, True)
        return key.public_key()

    def put_key(self, slot, private_key, pin_policy, touch_policy):
        self.keys[slot] = (private_key, False)
        return KEY_TYPE.ECCP256

    def sign(self, slot, key_type, message, hash_algorithm, padding=None):
        key, _generated = self.keys[slot]
        return key.sign(message, ec.ECDSA(hash_algorithm))

    def put_certificate(self, slot, certificate):
        self.certs[slot] = certificate
        self.objects[OBJECT_ID.from_slot(slot)] = b"cert-tlv"


def _setup(session):
    version = ".".join(str(v) for v in session.version)
    yubikey = piv.YubiKey(device=None, serial=1234, version=version, name="YubiKey")
    setup = piv.PivSetup(yubikey)
    setup._session = session
    return setup


def test_certificate_only_slot_is_treated_as_occupied_even_on_firmware_5_3_plus():
    session = _FakePivSession(version=(5, 7, 4))
    session.objects[OBJECT_ID.from_slot(SLOT.RETIRED1)] = b"existing-cert-bytes"
    setup = _setup(session)

    assert setup.supports_metadata() is True
    assert setup.is_free(SLOT.RETIRED1) is False
    assert SLOT.RETIRED1 not in setup.free_slots()
    assert setup.free_slots()[0] == SLOT.RETIRED2


def test_malformed_certificate_object_is_treated_as_occupied():
    session = _FakePivSession(version=(5, 7, 4))
    session.objects[OBJECT_ID.from_slot(SLOT.RETIRED1)] = BadResponseError("malformed")
    setup = _setup(session)

    assert setup.is_free(SLOT.RETIRED1) is False


def test_empty_object_bytes_with_no_key_is_free():
    session = _FakePivSession(version=(5, 7, 4))
    session.objects[OBJECT_ID.from_slot(SLOT.RETIRED1)] = b""
    setup = _setup(session)

    assert setup.is_free(SLOT.RETIRED1) is True


def test_unexpected_apdu_error_fails_closed_instead_of_treating_slot_as_free():
    session = _FakePivSession(version=(5, 7, 4))
    session.metadata_errors[SLOT.RETIRED1] = SW.MEMORY_FAILURE
    setup = _setup(session)

    with pytest.raises(piv.PivError, match="cannot inspect PIV slot 82"):
        setup.is_free(SLOT.RETIRED1)

    session2 = _FakePivSession(version=(5, 7, 4))
    session2.objects[OBJECT_ID.from_slot(SLOT.RETIRED1)] = ApduError(b"", SW.MEMORY_FAILURE)
    with pytest.raises(piv.PivError, match="cannot inspect PIV slot 82"):
        _setup(session2).is_free(SLOT.RETIRED1)


def test_firmware_4_3_detects_generated_key_without_cert_via_attestation():
    session = _FakePivSession(version=(4, 3, 7))
    session.keys[SLOT.RETIRED1] = (ec.generate_private_key(ec.SECP256R1()), True)
    setup = _setup(session)

    assert setup.supports_metadata() is False
    assert setup.is_free(SLOT.RETIRED1) is False
    assert setup.is_free(SLOT.RETIRED2) is True


def test_firmware_below_4_3_still_detects_certificates():
    session = _FakePivSession(version=(4, 2, 0))
    session.objects[OBJECT_ID.from_slot(SLOT.RETIRED1)] = b"cert"
    setup = _setup(session)

    assert setup.supports_metadata() is False
    assert setup.is_free(SLOT.RETIRED1) is False
    assert setup.is_free(SLOT.RETIRED2) is True


@pytest.mark.parametrize("version", [(5, 7, 4), (4, 3, 7)])
def test_generate_and_import_write_marker_certificate_and_refuse_overwrite(version):
    session = _FakePivSession(version=version)
    setup = _setup(session)

    pub_gen = setup.generate(SLOT.RETIRED1)
    cert_gen = session.certs[SLOT.RETIRED1]
    assert cert_gen.subject.rfc4514_string() == "CN=apple-piv"
    pub_gen.verify(cert_gen.signature, cert_gen.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    assert setup.is_free(SLOT.RETIRED1) is False

    imported_key = ec.generate_private_key(ec.SECP256R1())
    pub_imp = setup.import_key(SLOT.RETIRED2, imported_key)
    cert_imp = session.certs[SLOT.RETIRED2]
    assert cert_imp.subject.rfc4514_string() == "CN=apple-piv"
    pub_imp.verify(cert_imp.signature, cert_imp.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    # Even on firmware < 5.3, an imported key now shows as occupied because of the marker cert.
    assert setup.is_free(SLOT.RETIRED2) is False

    # Direct calls to generate/import_key refuse to overwrite an occupied slot.
    with pytest.raises(piv.PivError, match="already holds a key or certificate"):
        setup.generate(SLOT.RETIRED1)
    with pytest.raises(piv.PivError, match="already holds a key or certificate"):
        setup.import_key(SLOT.RETIRED2, imported_key)
