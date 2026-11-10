# OSX-Wifi

A driver for **Realtek RTL8187L** USB Wi-Fi adapters on **Mac OS X 10.3.9
"Panther", 10.4 "Tiger" and 10.5 "Leopard"** on PowerPC Macs (G3, G4, G5).

> **Status: untested on real hardware.** This driver was written and
> checked on a Linux machine. The portable core (crypto, 802.11 logic,
> chip register code) is unit-tested, including on an emulated big-endian
> PowerPC, and the kernel extension source was type-checked against
> Apple's 10.3 kernel, USB and networking headers. It has **not** yet
> been compiled with Apple's compiler, loaded into a Mac kernel, or run
> against a real adapter. Expect to have to fix things on first contact;
> a bug in a kernel extension can panic the machine. See
> [What has and has not been verified](#what-has-and-has-not-been-verified).

## What it does

- Makes the adapter appear as an Ethernet-style network interface
  (`en1`, `en2`, ...) that Network preferences, DHCP and everything else
  use normally.
- Scans for networks and joins **open**, **WEP** (40/104-bit) and
  **WPA2-Personal (AES/CCMP)** networks. All encryption is done in
  software in the driver.
- 802.11b and 802.11g rates, channels 1-13.
- Rejoins automatically if the connection drops, and after the adapter
  is unplugged and replugged (or the Mac sleeps) while the driver stays
  loaded.
- Controlled from Terminal with the bundled `rtlwifi` tool. There is no
  AirPort menu integration: Apple's AirPort interfaces are private and
  differ between 10.3, 10.4 and 10.5.

Not supported: WPA (TKIP), mixed WPA/WPA2 networks that use TKIP for
broadcast traffic, WPA3, 802.1X/Enterprise, ad-hoc networks, 802.11n,
power saving, and Intel Macs.

## Supported adapters

Adapters built on the RTL8187**L** chip with an RTL8225 or RTL8225z2
radio, including:

| Adapter | USB ID |
|---|---|
| Alfa AWUS036H and other Realtek reference designs | 0bda:8187 |
| Netgear WG111v2 | 0846:6100, 0846:6a00 |
| Linksys WUSB54GC v2 | 1737:0073 |
| ASUS P5B WiFi | 0b05:171d |
| Sitecom WL-168 v1 | 0df6:000d |
| Logitec LAN-W54G/U2 | 0789:010c |
| Surecom EP-9001-g | 0769:11f2 |
| Others (HP, Sphairon, AirLive/Dick Smith, AboCom, Qcom) | 03f0:ca02, 114b:0150, 1b75:8187, 13d1:abe6, 18e8:6232 |

To check yours, open System Profiler, select USB, and compare the Vendor
ID and Product ID. The **RTL8187B** (for example Netgear WG111v3) is a
different chip and is not supported; the driver detects it and declines.

## Building (on the Mac)

You need Apple's developer tools: Xcode 1.5 on 10.3, Xcode 2.x on 10.4,
or Xcode 3.x on 10.5, with the **Mac OS X 10.3.9 SDK** installed (an
optional package in the Xcode 2/3 installers).

```sh
make                # builds build/RTL8187.kext and build/rtlwifi
sudo make install   # copies them into place
```

On 10.3 itself there is no separate SDK; build against the system
headers:

```sh
make SDK= KCC=gcc-3.3 KCXX=g++-3.3
```

Then restart and plug in the adapter. A driver built this way against
the 10.3.9 SDK is meant to load on 10.3.9, 10.4 and 10.5. To try it
without restarting:

```sh
sudo kextload /System/Library/Extensions/RTL8187.kext
```

Messages from the driver go to the system log (`/var/log/system.log`,
lines starting with `RTL8187:`). On a successful attach you should see
the chip revision, radio type and MAC address; this takes a few seconds
after plugging in.

## Using it

1. Plug in the adapter. Open System Preferences > Network; a new
   Ethernet port should be announced. Leave it on DHCP (or configure it
   as you would a wired port) and apply.
2. In Terminal:

```sh
rtlwifi scan                                   # list networks in range
sudo rtlwifi join "My Network" -P              # WPA2, asks for the passphrase
sudo rtlwifi join "My Network" -p "passphrase" # WPA2, passphrase on the command line
sudo rtlwifi join "Cafe"                       # open network
sudo rtlwifi join "Old Net" -w 0123456789      # WEP (10 or 26 hex digits, or 5/13 characters)
rtlwifi status
sudo rtlwifi leave
sudo rtlwifi rate 11                           # fix the transmit rate; "auto" to undo
```

Once joined, the port shows as connected in Network preferences and
gets its address by DHCP.

The driver remembers the network only while it stays loaded. To join
automatically at startup, run the join command from a StartupItem or
login script; use `-k` with the 64-digit key printed by any WPA key
calculator to avoid storing the passphrase itself.

`sudo make uninstall` removes the driver and the tool.

## How it is put together

```
src/core/   Portable C, no OS dependencies
  rtl8187.c     chip registers, EEPROM, RTL8225 radio, bulk transfer framing
  rtw_sta.c     802.11 station: scan, authenticate, associate, WPA2 handshake,
                Ethernet <-> 802.11 conversion, rejoin
  rtw_aes.c     AES-128, CCM, RFC 3394 key unwrap
  rtw_sha1.c    SHA-1, HMAC, PBKDF2, the 802.11i PRF
  rtw_wep.c     RC4, CRC-32
src/kext/   The kernel extension: IOKit glue between Apple's USB family,
            Apple's networking family, and the core
src/tool/   rtlwifi command line tool
tests/      Unit tests for the core, and the Python model that generates
            their expected values
```

The chip initialisation sequences and radio tables come from the
OpenBSD `urtw(4)` driver by Weongyo Jeong and Martynas Venckus.

## What has and has not been verified

Verified, on Linux:

- `make test`: 417 checks on the core, with compiler sanitizers. The
  expected bytes for every frame in a full WPA2 exchange (probe,
  authenticate, associate, 4-way handshake, encrypted data in both
  directions, group key update) come from an independent Python model
  built on `hashlib` and the `cryptography` package, and the core must
  match them exactly. WEP and open networks, error paths, replay and
  forgery rejection are covered the same way.
- `make test-ppc`: the same tests pass on an emulated 32-bit big-endian
  PowerPC.
- The chip layer runs against a small software model of the register
  interface and EEPROM (which checks the logic, not the real chip).
- `src/kext/RTL8187.cpp` passes a compiler syntax and type check against
  Apple's published headers for the 10.3 kernel (xnu-517), IOUSBFamily
  and IONetworkingFamily.

Not verified:

- Building with Apple's GCC 3.3/4.0 and linking the kext. The compiler
  flags in the `Makefile` are written from the conventions of the period
  and may need adjusting.
- Loading in any Mac OS X kernel, and all behaviour on a real adapter:
  USB transfers, radio bring-up, actual association and throughput.
- The claim that one binary built against the 10.3.9 SDK loads on 10.4
  and 10.5; and the alternative `KPI=1` build against the 10.4 SDK.
- Unplug, sleep and wake behaviour.

If you try it, the system log lines and the output of `rtlwifi status`
are the most useful things to report.

## Licence

ISC; see [LICENSE](LICENSE).
