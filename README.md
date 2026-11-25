# apple-piv

A security key for an Apple Account that confirms sign-ins **without being
touched**, with its private key held by a YubiKey.

An Apple Account protected by security keys gets no six-digit codes: every new
sign-in has to be confirmed by a registered key, and a hardware key wants a
finger on it each time. That rules out anything unattended, such as a server
that backs up iCloud Photos. `apple-piv` registers one more key with the
account that is a piece of software, so nothing has to be touched, and keeps
that key's private half inside a YubiKey, so it cannot be copied:

- whoever has the YubiKey plugged in can have sign-ins confirmed;
- pull the YubiKey out and no further sign-in can be confirmed.

```
uvx --from git+https://github.com/dwahdany/apple-piv apple-piv setup
```

## What you need

- A Mac that is signed in to the Apple Account (keys can only be added in
  System Settings on an Apple device), with [uv](https://docs.astral.sh/uv/).
- A **YubiKey 5** (any form factor; a YubiKey 4 works too). FIDO-only keys such
  as the blue Security Key have no PIV function and cannot be used.
- A **Raspberry Pi Pico**, or any other RP2040/RP2350 board, and a USB *data*
  cable for it. It is needed once, for the registration.
- Security keys already switched on for the account, with your ordinary keys.

## The setup

`apple-piv setup` walks through six steps and asks before it does anything
that matters.

1. **YubiKey.** Plug it in. A free PIV slot (82–95) is chosen; occupied slots
   are never written to. If the YubiKey's management key is PIN-protected, you
   are asked for the PIV PIN.
2. **Where the key is made.** This also decides whether a backup is possible:
   - *In the YubiKey* (most secure): the YubiKey generates the key itself, so
     the key never exists anywhere else, not even in this Mac's memory. No
     backup is possible. If the YubiKey breaks, you register a new key.
   - *On this Mac, with a passphrase-encrypted backup*: the key is made in
     memory, written to a file in the [age](https://age-encryption.org) format
     (`age --decrypt` opens it without this program) and moved into the YubiKey.
   - *On this Mac, with a plain-text backup*: the same, but the file works as
     the security key for whoever has it.

   Either kind of backup can also be written as a page to print, with a QR
   code and the same content as text.
3. **Key.** Created (in the YubiKey, or in memory and then moved there), set to
   sign without touch and without PIN, and tried once.
4. **Pico.** Plug it in while holding BOOTSEL. It is flashed with a small
   firmware that makes it a USB bridge, and tested.
5. **Apple.** You open *System Settings → your name → Sign-In & Security →
   Security Keys → Add Security Key*. When the Mac asks for the key, the Pico
   answers by itself.
6. **Save.** A key file is written (default `~/.config/apple-piv/softkey.json`)
   and, if you asked for one, the backup.

Then check it with a real sign-in, into a temporary folder:

```
apple-piv verify you@example.com
```

Afterwards the Pico is not needed any more. It holds nothing secret.

## Using the key

The key file says which YubiKey and slot hold the key and which credentials
Apple registered. It contains no secret. Wherever a sign-in should be confirmed,
that YubiKey has to be plugged in and the program needs the key file.

- **[docker-icloudpd](https://github.com/dwahdany/docker-icloudpd)** reads this
  key file as `/config/softkey.json` and needs the USB bus passed in:

  ```yaml
      volumes:
        - /dev/bus/usb:/dev/bus/usb
      device_cgroup_rules:
        - 'c 189:* rwm'
  ```

- **icloudpd** (1.33.0 or later, installed from its pure-Python wheel):
  `python -m apple_piv.icloudpd_run softkey.json --mfa-provider console …`
- **Anything built on python-fido2**:
  `apple_piv.authenticator.make_ctap_device("softkey.json")` is a `CtapDevice`.
- **As a USB key again**, for example to sign in on a new device:
  `apple-piv bridge` with the Pico and the YubiKey plugged in.

## What this does and does not protect

The software key answers Apple's challenge; the signature inside the answer is
made by the YubiKey, in its PIV application, which never gives a private key
out. The slot is set to sign without touch and without PIN, because that is the
point.

| | |
|---|---|
| Key file copied, leaked in a backup | Nothing to steal: it holds no secret. |
| Someone controls the machine the YubiKey is in | They can have sign-ins confirmed for as long as it stays plugged in. They cannot take the key with them. |
| You pull the YubiKey | No new sign-in can be confirmed. Sessions issued before stay valid until they expire: sign other sessions out from one of your Apple devices. |
| The YubiKey is stolen | It signs for whoever holds it (they still need the account password). Remove the key under Security Keys. |
| A plain-text backup is found | It is the key. Use the passphrase option, or a safe. |

Two things to know:

- **Apple asks for FIDO Certified keys; this is not one.** Apple accepted it
  when this was written (November 2026, macOS 27) and may stop. Its servers
  required an attestation certificate but did not check who issued it.
- **Change the YubiKey's PIV PIN, PUK and management key** from the factory
  defaults (Yubico Authenticator, or `ykman piv access`). The defaults do not
  let anyone read the key, but they let anyone with USB access overwrite it.
- **Whoever has USB access can still destroy the key**, whatever the PIN is:
  three wrong PINs and three wrong PUKs block both, after which the PIV
  application can be reset, which erases every slot. Nothing is stolen that
  way, but sign-ins stop until you restore from a backup or register a new key.
  Firmware before 5.7 is also open to a laboratory side-channel attack on its
  ECDSA keys (EUCLEAK), which needs the YubiKey in hand and special equipment.

## Restoring from a backup

```
apple-piv restore backup.age --to-yubikey     # into a (new) YubiKey
apple-piv restore backup.txt --out softkey.json   # as a key file that holds the key itself
```

The first asks for the passphrase if the backup is encrypted, moves the key
into a free PIV slot and writes a key file that points to it. No new
registration with Apple is needed: it is the same key.

## The Pico firmware

`firmware/` is the source: a FIDO HID interface plus a serial port, relaying
raw 64-byte packets between them (TinyUSB, Pico SDK). The images that
`apple-piv` flashes are in `src/apple_piv/firmware/`, built from that source
with `firmware/shell.nix`:

```
cd firmware
nix-shell --run 'cmake -S . -B build -DPICO_BOARD=pico && cmake --build build'    # RP2040
nix-shell --run 'cmake -S . -B build2 -DPICO_BOARD=pico2 && cmake --build build2'  # RP2350
```

The board identifies itself with the pid.codes test id (`1209:0001`).

## Development

```
uv run --extra dev pytest
```

The tests need no hardware: python-fido2's own client and server stand in for
Apple, and scripted stand-ins for the YubiKey, the Pico and the terminal.
