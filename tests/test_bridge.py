"""Finding and flashing the Pico (no hardware: a folder stands in for the boot volume)."""

import pytest

from apple_piv import bridge


def _volume(tmp_path, name, info):
    volume = tmp_path / name
    volume.mkdir()
    (volume / "INFO_UF2.TXT").write_text(info)
    return volume


def test_no_bootloader_volume(tmp_path):
    assert bridge.find_bootloader(tmp_path) is None
    (tmp_path / "RPI-RP2").mkdir()  # a folder by that name without the marker file
    assert bridge.find_bootloader(tmp_path) is None


@pytest.mark.parametrize(
    "name, info, chip",
    [
        ("RPI-RP2", "UF2 Bootloader v3.0\nModel: Raspberry Pi RP2\nBoard-ID: RPI-RP2\n", "rp2040"),
        ("RP2350", "UF2 Bootloader v1.0\nModel: Raspberry Pi RP2350\nBoard-ID: RP2350\n", "rp2350"),
        ("RPI-RP2", "UF2 Bootloader v1.0\nModel: Raspberry Pi RP2350\nBoard-ID: RP2350\n", "rp2350"),
    ],
)
def test_bootloader_volume_and_chip(tmp_path, name, info, chip):
    volume = _volume(tmp_path, name, info)
    assert bridge.find_bootloader(tmp_path) == (volume, chip)


@pytest.mark.parametrize("chip", ["rp2040", "rp2350"])
def test_firmware_images_ship_with_the_package_and_are_uf2(tmp_path, chip):
    volume = _volume(tmp_path, "RPI-RP2", "x")
    bridge.flash(volume, chip)
    image = (volume / "softkey_bridge.uf2").read_bytes()
    assert len(image) % 512 == 0 and len(image) > 10_000
    assert image[:4] == b"UF2\n" and image[508:512] == bytes.fromhex("30 6f b1 0a")
    families = {int.from_bytes(image[i + 28 : i + 32], "little") for i in range(0, len(image), 512)}
    # (RP2350 images start with one "absolute" block that works around a boot ROM erratum.)
    assert {"rp2040": 0xE48BFF56, "rp2350": 0xE48BFF59}[chip] in families
    assert {"rp2040": 0xE48BFF59, "rp2350": 0xE48BFF56}[chip] not in families


def test_volume_vanishing_at_the_end_of_the_copy_is_not_an_error(tmp_path, monkeypatch):
    volume = _volume(tmp_path, "RPI-RP2", "x")

    def copy_then_reboot(_src, _dst):
        (volume / "INFO_UF2.TXT").unlink()
        volume.rmdir()
        raise OSError("device not configured")

    monkeypatch.setattr(bridge.shutil, "copyfile", copy_then_reboot)
    bridge.flash(volume, "rp2040")  # no exception


def test_copy_failure_with_the_volume_still_there_is_an_error(tmp_path, monkeypatch):
    volume = _volume(tmp_path, "RPI-RP2", "x")

    def fail(_src, _dst):
        raise OSError("disk full")

    monkeypatch.setattr(bridge.shutil, "copyfile", fail)
    with pytest.raises(OSError):
        bridge.flash(volume, "rp2040")
