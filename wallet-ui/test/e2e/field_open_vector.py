"""SDN Unified ECIES field cipher outside the wallet (Python `cryptography`).

Independent of the wallet's code: SLIP-10 from the test seed to the
contact-encryption X25519 key (m/44'/0'/<account>'/1'/0'), the SDS $ENC header
parsed by hand, then X25519, HKDF-SHA256 and AES-256-CTR from `cryptography`.

stdin: JSON, one of
  {"op": "open", "seedHex", "account", "fields": [{"encHex", "ciphertextHex", "fieldId"}]}
      -> {"publicKeyHex", "fields": [{"plaintextHex", "context"} | {"refused"}]}
  {"op": "seal", "seedHex", "account", "context", "fieldId", "plaintextHex"}
      -> {"publicKeyHex", "ephemeralPublicHex", "recipientKeyIdHex", "ciphertextHex"}
"""

import hashlib
import hmac
import json
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HARDENED = 0x80000000


def contact_key(seed: bytes, account: int) -> X25519PrivateKey:
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for index in (44, 0, account, 1, 0):
        digest = hmac.new(chain, b"\x00" + key + struct.pack(">I", index | HARDENED), hashlib.sha512).digest()
        key, chain = digest[:32], digest[32:]
    return X25519PrivateKey.from_private_bytes(key)


def raw_public(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def parse_enc(buf: bytes) -> dict:
    if buf[4:8] != b"$ENC":
        raise ValueError("not an $ENC record")
    table = struct.unpack_from("<I", buf, 0)[0]
    vtable = table - struct.unpack_from("<i", buf, table)[0]
    vt_len = struct.unpack_from("<H", buf, vtable)[0]

    def slot(i):
        at = vtable + 4 + 2 * i
        return struct.unpack_from("<H", buf, at)[0] if at < vtable + vt_len else 0

    def vector(i):
        off = slot(i)
        if not off:
            return b""
        pos = table + off
        pos += struct.unpack_from("<I", buf, pos)[0]
        n = struct.unpack_from("<I", buf, pos)[0]
        return bytes(buf[pos + 4:pos + 4 + n])

    return {"ephemeral": vector(4), "recipientKeyId": vector(6), "context": vector(7).decode("utf-8")}


def hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def field_cipher(shared: bytes, context: str, field_id: int, data: bytes) -> bytes:
    master = hkdf(shared, context.encode("utf-8"), 32)
    suffix = struct.pack(">HI", field_id, 0)
    key = hkdf(master, b"flatbuffers-field" + suffix, 32)
    iv = hkdf(master, b"flatbuffers-iv" + suffix, 16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return cipher.update(data) + cipher.finalize()


def main() -> int:
    request = json.load(sys.stdin)
    private = contact_key(bytes.fromhex(request["seedHex"]), request["account"])
    public = raw_public(private)
    if request["op"] == "open":
        out = []
        for field in request["fields"]:
            enc = parse_enc(bytes.fromhex(field["encHex"]))
            if enc["recipientKeyId"] != hashlib.sha256(public).digest()[:8]:
                out.append({"refused": "sealed for another key"})
                continue
            shared = private.exchange(X25519PublicKey.from_public_bytes(enc["ephemeral"]))
            plain = field_cipher(shared, enc["context"], field["fieldId"], bytes.fromhex(field["ciphertextHex"]))
            out.append({"plaintextHex": plain.hex(), "context": enc["context"]})
        json.dump({"publicKeyHex": public.hex(), "fields": out}, sys.stdout)
    elif request["op"] == "seal":
        ephemeral = X25519PrivateKey.generate()
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(public))
        ciphertext = field_cipher(shared, request["context"], request["fieldId"], bytes.fromhex(request["plaintextHex"]))
        json.dump({
            "publicKeyHex": public.hex(),
            "ephemeralPublicHex": raw_public(ephemeral).hex(),
            "recipientKeyIdHex": hashlib.sha256(public).digest()[:8].hex(),
            "ciphertextHex": ciphertext.hex(),
        }, sys.stdout)
    else:
        raise ValueError("unknown op")
    return 0


if __name__ == "__main__":
    sys.exit(main())
