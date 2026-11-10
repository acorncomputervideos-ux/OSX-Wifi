#!/usr/bin/env python3
"""Generate tests/vectors.h.

This is an independent model of the access point side of the exchanges
the driver core takes part in, written against standard library and
`cryptography` primitives.  The C tests replay the frames produced here
into the core and require its output to match byte for byte, so the two
implementations check each other.

Run:  python3 tests/gen_vectors.py > tests/vectors.h
"""
import hashlib, hmac, struct, sys, zlib
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

STA = bytes.fromhex("001122334455")
AP = bytes.fromhex("02aabbccddee")
PEER = bytes.fromhex("0a0b0c0d0e0f")       # a wired host behind the AP
BCAST = b"\xff" * 6
SSID = b"TestNet"
PASSPHRASE = b"correct horse battery"
CHAN = 6

out = []
def emit(name, data):
    data = bytes(data)
    body = ",".join("0x%02x" % b for b in data)
    out.append("static const unsigned char %s[%d] = {%s};" %
               (name, max(len(data), 1), body or "0"))
    out.append("#define %s_len %d" % (name, len(data)))

# --- the deterministic "random" source the C tests install -------------
class Rng:
    def __init__(self): self.i = 0
    def take(self, n):
        r = bytes(((self.i + k) * 7 + 13) & 0xff for k in range(n))
        self.i += n
        return r

# --- 802.11 framing -----------------------------------------------------
RATES = bytes([1, 8, 0x82, 0x84, 0x8b, 0x96, 12, 18, 24, 36])
XRATES = bytes([50, 4, 48, 72, 96, 108])
RSN = bytes.fromhex("30140100000fac040100000fac040100000fac020000")

def mgmt(subtype, da, sa, bssid, body, seq=0):
    return bytes([subtype, 0]) + b"\x00\x00" + da + sa + bssid + \
        struct.pack("<H", seq << 4) + body

def beacon(subtype, da, cap, ies, bssid=AP):
    return mgmt(subtype, da, bssid, bssid,
                b"\x00" * 8 + struct.pack("<HH", 100, cap) + ies)

def ie(i, d): return bytes([i, len(d)]) + d

def llc(ethertype, payload):
    oui = b"\x00\x00\xf8" if ethertype in (0x80f3, 0x8137) else b"\x00\x00\x00"
    return b"\xaa\xaa\x03" + oui + struct.pack(">H", ethertype) + payload

def data_hdr(fc1, a1, a2, a3, seq, fc0=0x08):
    return bytes([fc0, fc1]) + b"\x00\x00" + a1 + a2 + a3 + \
        struct.pack("<H", seq << 4)

def ccmp(tk, hdr, pn, keyid, plaintext):
    """CCMP-encrypt one MPDU (IEEE 802.11-2007 8.3.3)."""
    qos = bool(hdr[0] & 0x80)
    fc0 = hdr[0] & 0x8f
    fc1 = (hdr[1] & 0xc7) | 0x40
    if qos: fc1 &= 0x7f
    aad = bytes([fc0, fc1]) + hdr[4:22] + bytes([hdr[22] & 0x0f, 0])
    prio = 0
    if qos:
        prio = hdr[24] & 0x0f
        aad += bytes([prio, 0])
    pnb = pn.to_bytes(6, "big")
    nonce = bytes([prio]) + hdr[10:16] + pnb
    chdr = bytes([pnb[5], pnb[4], 0, 0x20 | (keyid << 6),
                  pnb[3], pnb[2], pnb[1], pnb[0]])
    ct = AESCCM(tk, tag_length=8).encrypt(nonce, plaintext, aad)
    h = bytearray(hdr); h[1] |= 0x40
    return bytes(h) + chdr + ct

def rc4(key, data):
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    i = j = 0; o = bytearray()
    for b in data:
        i = (i + 1) & 0xff; j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        o.append(b ^ s[(s[i] + s[j]) & 0xff])
    return bytes(o)

def wep(key, hdr, iv, keyid, plaintext):
    icv = struct.pack("<I", zlib.crc32(plaintext) & 0xffffffff)
    h = bytearray(hdr); h[1] |= 0x40
    return bytes(h) + iv + bytes([keyid << 6]) + rc4(iv + key, plaintext + icv)

# --- WPA2 key hierarchy -------------------------------------------------
def prf(key, label, data, n):
    r = b""; i = 0
    while len(r) < n:
        r += hmac.new(key, label + b"\x00" + data + bytes([i]),
                      hashlib.sha1).digest()
        i += 1
    return r[:n]

def eapol_key(info, replay, nonce=b"", rsc=b"", kd=b"", kck=None, ver=2):
    body = bytes([2]) + struct.pack(">HH", info, 16 if info & 8 else 0) + \
        struct.pack(">Q", replay) + nonce.ljust(32, b"\x00") + b"\x00" * 16 + \
        rsc.ljust(8, b"\x00") + b"\x00" * 8 + b"\x00" * 16 + \
        struct.pack(">H", len(kd)) + kd
    f = bytes([ver, 3]) + struct.pack(">H", len(body)) + body
    if kck is not None:
        mic = hmac.new(kck, f, hashlib.sha1).digest()[:16]
        f = f[:81] + mic + f[97:]
    return f

def sta_eapol_key(info, replay, nonce, kd, kck, ver=2):
    """What the station is expected to send (key length field zero)."""
    body = bytes([2]) + struct.pack(">HH", info, 0) + \
        struct.pack(">Q", replay) + nonce.ljust(32, b"\x00") + b"\x00" * 16 + \
        b"\x00" * 8 + b"\x00" * 8 + b"\x00" * 16 + \
        struct.pack(">H", len(kd)) + kd
    f = bytes([ver, 3]) + struct.pack(">H", len(body)) + body
    mic = hmac.new(kck, f, hashlib.sha1).digest()[:16]
    return f[:81] + mic + f[97:]

def gtk_kd(keyid, gtk, with_rsn=True):
    kd = (RSN if with_rsn else b"") + \
        ie(0xdd, bytes.fromhex("000fac01") + bytes([keyid, 0]) + gtk)
    if len(kd) % 8:                      # pad as the standard requires
        kd += b"\xdd"
        kd += b"\x00" * (-len(kd) % 8)
    if len(kd) < 16:
        kd += b"\x00" * (16 - len(kd))
    return kd

# ======================================================================
# Primitive vectors
# ======================================================================
emit("v_pbkdf2_psk",
     hashlib.pbkdf2_hmac("sha1", b"password", b"IEEE", 4096, 32))
k = bytes(range(16)); m = b"The quick brown fox jumps over the lazy dog" * 3
emit("v_hmac_key", bytes(range(80)))
emit("v_hmac_msg", m)
emit("v_hmac_out", hmac.new(bytes(range(80)), m, hashlib.sha1).digest())
emit("v_sha1_out", hashlib.sha1(m).digest())
emit("v_prf_out", prf(k, b"Pairwise key expansion", m[:76], 48))
emit("v_prf_data", m[:76])
enc = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
emit("v_aes_pt", bytes.fromhex("00112233445566778899aabbccddeeff"))
emit("v_aes_ct", enc.update(bytes.fromhex("00112233445566778899aabbccddeeff")))
for n in (16, 24, 40):
    emit("v_wrap%d_pt" % n, bytes(range(100, 100 + n)))
    emit("v_wrap%d_ct" % n, aes_key_wrap(k, bytes(range(100, 100 + n))))
nonce = bytes(range(50, 63))
for i, (alen, plen) in enumerate([(22, 0), (22, 1), (22, 15), (22, 16),
                                  (24, 17), (22, 100), (30, 1500), (0, 33)]):
    aad = bytes((7 * j + 1) & 0xff for j in range(alen))
    pt = bytes((5 * j + 3) & 0xff for j in range(plen))
    ct = AESCCM(k, tag_length=8).encrypt(nonce, pt, aad if alen else None)
    emit("v_ccm%d_aad" % i, aad); emit("v_ccm%d_pt" % i, pt)
    emit("v_ccm%d_ct" % i, ct)
out.append("#define V_CCM_CASES 8")
emit("v_ccm_nonce", nonce)
emit("v_rc4_out", rc4(b"Key", b"Plaintext"))

# ======================================================================
# WPA2 scenario
# ======================================================================
rng = Rng()
rng.take(6)                               # consumed by rtw_sta_up()
snonce = rng.take(32)
anonce = bytes((0x80 + 3 * i) & 0xff for i in range(32))
pmk = hashlib.pbkdf2_hmac("sha1", PASSPHRASE, SSID, 4096, 32)
ptk = prf(pmk, b"Pairwise key expansion",
          min(AP, STA) + max(AP, STA) + min(anonce, snonce) +
          max(anonce, snonce), 48)
kck, kek, tk = ptk[:16], ptk[16:32], ptk[32:48]
gtk1 = bytes(range(0xa0, 0xb0)); gtk2 = bytes(range(0xc0, 0xd0))

emit("w_sta", STA); emit("w_ap", AP); emit("w_peer", PEER)
emit("w_ssid", SSID); emit("w_pmk", pmk)
out.append('#define W_PASSPHRASE "%s"' % PASSPHRASE.decode())
out.append("#define W_CHAN %d" % CHAN)

ies = ie(0, SSID) + RATES + ie(3, bytes([CHAN])) + RSN + XRATES
emit("w_beacon", beacon(0x80, BCAST, 0x0411, ies))
# A hidden twin of the same network, a WPA(1)-only and an open network.
emit("w_beacon_hidden", beacon(0x80, BCAST, 0x0411,
     ie(0, b"") + RATES + ie(3, bytes([CHAN])) + RSN,
     bssid=bytes.fromhex("02aabbccdd01")))
emit("w_beacon_wpa1", beacon(0x80, BCAST, 0x0411,
     ie(0, b"OldNet") + RATES + ie(3, bytes([1])) +
     ie(0xdd, bytes.fromhex("0050f20101000050f20201000050f20201000050f202")),
     bssid=bytes.fromhex("02aabbccdd02")))
emit("w_beacon_open", beacon(0x50, STA, 0x0401,
     ie(0, b"Cafe") + RATES + ie(3, bytes([11])),
     bssid=bytes.fromhex("02aabbccdd03")))
emit("w_beacon_wep", beacon(0x80, BCAST, 0x0011,
     ie(0, b"Vintage") + ie(1, bytes([0x82, 0x84, 0x8b, 0x96])) +
     ie(3, bytes([3])), bssid=bytes.fromhex("02aabbccdd04")))
# WPA3-only: AKM is SAE (8) and management frame protection is required.
emit("w_beacon_wpa3", beacon(0x80, BCAST, 0x0411,
     ie(0, b"Modern") + RATES + ie(3, bytes([1])) +
     bytes.fromhex("30140100000fac040100000fac040100000fac08c000"),
     bssid=bytes.fromhex("02aabbccdd05")))

emit("w_auth_resp", mgmt(0xb0, STA, AP, AP, struct.pack("<HHH", 0, 2, 0)))
emit("w_assoc_resp", mgmt(0x10, STA, AP, AP,
     struct.pack("<HHH", 0x0411, 0, 0xc001) + RATES + XRATES))
emit("w_deauth", mgmt(0xc0, STA, AP, AP, struct.pack("<H", 2)))

# Frames the station must produce (sequence numbers are not compared).
emit("x_probe_bcast", mgmt(0x40, BCAST, STA, BCAST, ie(0, b"") + RATES + XRATES))
emit("x_probe_ssid", mgmt(0x40, BCAST, STA, BCAST, ie(0, SSID) + RATES + XRATES))
def with_dur(f, dur): return f[:2] + struct.pack("<H", dur) + f[4:]
emit("x_auth", with_dur(mgmt(0xb0, AP, STA, AP, struct.pack("<HHH", 0, 1, 0)), 314))
emit("x_assoc", with_dur(mgmt(0x00, AP, STA, AP,
     struct.pack("<HH", 0x0411, 10) + ie(0, SSID) + RATES + XRATES + RSN), 314))
emit("x_deauth", with_dur(mgmt(0xc0, AP, STA, AP, struct.pack("<H", 3)), 314))

def from_ap(payload, seq, da=STA, sa=AP):
    return data_hdr(0x02, da, AP, sa, seq) + payload
def to_ap(payload, da=AP, dur=314):
    return with_dur(data_hdr(0x01, AP, STA, da, 0) + payload, dur)

# 4-way handshake
m1 = eapol_key(0x008a, 1, anonce)
emit("w_m1", from_ap(llc(0x888e, m1), 10))
m2 = sta_eapol_key(0x010a, 1, snonce, RSN, kck)
emit("x_m2", to_ap(llc(0x888e, m2)))
rsc = (0x10).to_bytes(6, "little")
m3 = eapol_key(0x13ca, 2, anonce, rsc, aes_key_wrap(kek, gtk_kd(1, gtk1)), kck)
emit("w_m3", from_ap(llc(0x888e, m3), 11))
m4 = sta_eapol_key(0x030a, 2, b"", b"", kck)
emit("x_m4", to_ap(llc(0x888e, m4)))
# A message 3 with a bad MIC, and one for a wrong PMK.
bad = bytearray(m3); bad[85] ^= 1
emit("w_m3_badmic", from_ap(llc(0x888e, bytes(bad)), 11))

# Data: station -> AP.  First frame uses PN 1.
ip = bytes([0x45, 0, 0, 0x54]) + bytes(range(80))
emit("w_tx_eth", PEER + STA + b"\x08\x00" + ip)
emit("x_tx_data", ccmp(tk, to_ap(b"", da=PEER), 1, 0,
                       llc(0x0800, ip)))
emit("x_tx_data2", ccmp(tk, to_ap(b"", da=PEER), 2, 0,
                        llc(0x0800, ip)))
# Data: AP -> station (unicast, PTK) and broadcast (GTK key id 1).
arp = bytes(range(28))
emit("w_rx_data", ccmp(tk, from_ap(b"", 20, sa=PEER), 1, 0, llc(0x0800, ip)))
emit("x_rx_eth", STA + PEER + b"\x08\x00" + ip)
emit("w_rx_qos", ccmp(tk, data_hdr(0x02, STA, AP, PEER, 21, fc0=0x88) +
     b"\x05\x00", 2, 0, llc(0x0800, ip)))
emit("w_rx_bcast", ccmp(gtk1, from_ap(b"", 30, da=BCAST, sa=PEER), 0x11, 1,
                        llc(0x0806, arp)))
emit("x_rx_bcast_eth", BCAST + PEER + b"\x08\x06" + arp)
emit("w_rx_bcast_old", ccmp(gtk1, from_ap(b"", 31, da=BCAST, sa=PEER), 0x10, 1,
                            llc(0x0806, arp)))
emit("w_rx_own_bcast", ccmp(gtk1, from_ap(b"", 32, da=BCAST, sa=STA), 0x12, 1,
                            llc(0x0806, arp)))
emit("w_rx_plain", from_ap(llc(0x0800, ip), 22, sa=PEER))
# Group rekey, sent encrypted under the pairwise key (PN 3).
g1 = eapol_key(0x1382, 3, b"", b"", aes_key_wrap(kek, gtk_kd(2, gtk2, False)), kck)
emit("w_g1", ccmp(tk, from_ap(b"", 23), 3, 0, llc(0x888e, g1)))
g2 = sta_eapol_key(0x0302, 3, b"", b"", kck)
# The station's reply is its third encrypted frame (PN 3).
emit("x_g2", ccmp(tk, to_ap(b""), 3, 0, llc(0x888e, g2)))
emit("w_rx_bcast_new", ccmp(gtk2, from_ap(b"", 33, da=BCAST, sa=PEER), 1, 2,
                            llc(0x0806, arp)))
# Retransmitted message 3 after the keys are installed: the station
# answers again (now encrypted, PN 4) but must not reset its counters.
m3r = eapol_key(0x13ca, 4, anonce, rsc, aes_key_wrap(kek, gtk_kd(1, gtk1)), kck)
emit("w_m3_retx", ccmp(tk, from_ap(b"", 24), 4, 0, llc(0x888e, m3r)))
m4r = sta_eapol_key(0x030a, 4, b"", b"", kck)
emit("x_m4_retx", ccmp(tk, to_ap(b""), 4, 0, llc(0x888e, m4r)))
emit("x_tx_data5", ccmp(tk, to_ap(b"", da=PEER), 5, 0,
                        llc(0x0800, ip)))

# ======================================================================
# WEP and open scenarios
# ======================================================================
rng = Rng(); r = rng.take(6)
iv0 = ((r[2] << 16) | (r[3] << 8) | r[4]) + 1
wepkey = b"\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89"
WAP = bytes.fromhex("02aabbccdd04")
emit("e_key", wepkey); emit("e_ap", WAP)
emit("e_auth_resp", mgmt(0xb0, STA, WAP, WAP, struct.pack("<HHH", 0, 2, 0)))
emit("e_assoc_resp", mgmt(0x10, STA, WAP, WAP, struct.pack("<HHH", 0x11, 0, 0xc002)))
h = with_dur(data_hdr(0x01, WAP, STA, PEER, 0), 314)
emit("x_wep_tx", wep(wepkey, h, iv0.to_bytes(3, "big"), 2, llc(0x0800, ip)))
emit("e_rx", wep(wepkey, data_hdr(0x02, STA, WAP, PEER, 5),
                 b"\x09\x08\x07", 2, llc(0x0800, ip)))
badwep = bytearray(wep(wepkey, data_hdr(0x02, STA, WAP, PEER, 6),
                       b"\x09\x08\x08", 2, llc(0x0800, ip)))
badwep[-6] ^= 0x40
emit("e_rx_bad", badwep)

OAP = bytes.fromhex("02aabbccdd03")
emit("o_ap", OAP)
emit("o_auth_resp", mgmt(0xb0, STA, OAP, OAP, struct.pack("<HHH", 0, 2, 0)))
emit("o_auth_reject", mgmt(0xb0, STA, OAP, OAP, struct.pack("<HHH", 0, 2, 13)))
emit("o_assoc_resp", mgmt(0x10, STA, OAP, OAP, struct.pack("<HHH", 0x0401, 0, 0xc003)))
emit("o_assoc_reject", mgmt(0x10, STA, OAP, OAP, struct.pack("<HHH", 0x0401, 17, 0)))
aarp = bytes(range(28))
emit("o_tx_aarp_eth", BCAST + STA + b"\x80\xf3" + aarp)
emit("x_o_tx_aarp", with_dur(data_hdr(0x01, OAP, STA, BCAST, 0), 314) + llc(0x80f3, aarp))
# 802.3 length-encapsulated (raw LLC) frame, e.g. spanning tree / AppleTalk
raw = b"\x42\x42\x03" + bytes(range(35))
emit("o_tx_raw_eth", BCAST + STA + struct.pack(">H", len(raw)) + raw)
emit("x_o_tx_raw", with_dur(data_hdr(0x01, OAP, STA, BCAST, 0), 314) + raw)
emit("o_rx_raw", data_hdr(0x02, STA, OAP, PEER, 7) + raw)
emit("x_o_rx_raw_eth", STA + PEER + struct.pack(">H", len(raw)) + raw)
emit("o_rx_ip", data_hdr(0x02, STA, OAP, PEER, 8) + llc(0x0800, ip))
emit("o_rx_ip_retry", data_hdr(0x0a, STA, OAP, PEER, 8) + llc(0x0800, ip))
emit("o_rx_frag", data_hdr(0x06, STA, OAP, PEER, 9) + llc(0x0800, ip))
emit("o_rx_other_bss", data_hdr(0x02, STA, AP, PEER, 9) + llc(0x0800, ip))
emit("o_rx_enc", ccmp(tk, data_hdr(0x02, STA, OAP, PEER, 10), 1, 0, llc(0x0800, ip)))

print("/* Generated by tests/gen_vectors.py -- do not edit. */")
print("\n".join(out))
