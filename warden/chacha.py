"""
Pure-Python ChaCha20-Poly1305 AEAD (RFC 8439) -- authenticated encryption,
zero dependencies. Used to encrypt private agent memory at rest (memory.py).

Like ed25519.py, this is a real, standard construction (not a toy): its output
is byte-identical to mainstream implementations, which the self-test confirms
against both the RFC 8439 test vector and the `cryptography` library when
present.

Public API
----------
    seal(key32, plaintext, aad=b"")  -> nonce(12) || ciphertext || tag(16)
    open_(key32, blob, aad=b"")      -> plaintext   (raises on auth failure)
    aead_encrypt(key, nonce12, pt, aad) -> ct || tag
    aead_decrypt(key, nonce12, ct_tag, aad) -> pt
    new_key() -> 32 random bytes
"""

from __future__ import annotations

import os
import struct

_MASK = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    x &= _MASK
    return ((x << n) | (x >> (32 - n))) & _MASK


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & _MASK; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK; s[b] = _rotl(s[b] ^ s[c], 7)


_CONST = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"


def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    k = struct.unpack("<8I", key)
    n = struct.unpack("<3I", nonce)
    state = [_CONST[0], _CONST[1], _CONST[2], _CONST[3],
             k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
             counter & _MASK, n[0], n[1], n[2]]
    work = list(state)
    for _ in range(10):  # 20 rounds = 10 double rounds
        _quarter(work, 0, 4, 8, 12); _quarter(work, 1, 5, 9, 13)
        _quarter(work, 2, 6, 10, 14); _quarter(work, 3, 7, 11, 15)
        _quarter(work, 0, 5, 10, 15); _quarter(work, 1, 6, 11, 12)
        _quarter(work, 2, 7, 8, 13); _quarter(work, 3, 4, 9, 14)
    out = [(work[i] + state[i]) & _MASK for i in range(16)]
    return struct.pack("<16I", *out)


def _chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    for i in range(0, len(data), 64):
        ks = _chacha_block(key, counter + (i // 64), nonce)
        chunk = data[i:i + 64]
        for j in range(len(chunk)):
            out[i + j] = chunk[j] ^ ks[j]
    return bytes(out)


# --- Poly1305 (RFC 8439) -----------------------------------------------------
_P1305 = (1 << 130) - 5


def _poly1305_mac(msg: bytes, key: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little")
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF  # clamp
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")  # add the 1 bit past the block
        acc = (acc + n) % _P1305
        acc = (acc * r) % _P1305
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    if len(data) % 16 == 0:
        return b""
    return b"\x00" * (16 - (len(data) % 16))


def _poly_key_gen(key: bytes, nonce: bytes) -> bytes:
    return _chacha_block(key, 0, nonce)[:32]


# --- AEAD --------------------------------------------------------------------

def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("key must be 32 bytes, nonce 12 bytes")
    otk = _poly_key_gen(key, nonce)
    ciphertext = _chacha20(key, 1, nonce, plaintext)
    mac_data = (aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
                + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext)))
    tag = _poly1305_mac(mac_data, otk)
    return ciphertext + tag


def aead_decrypt(key: bytes, nonce: bytes, ct_and_tag: bytes, aad: bytes = b"") -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("key must be 32 bytes, nonce 12 bytes")
    if len(ct_and_tag) < 16:
        raise ValueError("ciphertext too short")
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    otk = _poly_key_gen(key, nonce)
    mac_data = (aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
                + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext)))
    expected = _poly1305_mac(mac_data, otk)
    if not _ct_equal(expected, tag):
        raise ValueError("authentication failed (tampered ciphertext or wrong key)")
    return _chacha20(key, 1, nonce, ciphertext)


def _ct_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


# --- convenience: self-framing seal/open with a random nonce -----------------

def new_key() -> bytes:
    return os.urandom(32)


def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    return nonce + aead_encrypt(key, nonce, plaintext, aad)


def open_(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < 12 + 16:
        raise ValueError("blob too short")
    nonce, ct = blob[:12], blob[12:]
    return aead_decrypt(key, nonce, ct, aad)
