import base64
import binascii
import re
import requests

from itertools import cycle

req_root = "http://ciphersprint.pulley.com"

nonhex_regex = "[^0-9a-fA-F]"

def rotate_string(input: str, d: int) -> str:
    left = input[0:len(input) - d]
    right = input[len(input) - d:]
    return right + left

def xor(data: bytes, key: bytes) -> bytes:
    return bytearray(d^k for d, k in zip(data, cycle(key)))

def unscramble(data: bytes, key: bytes) -> str:
    print(data)
    print(key)
    dec = [0] * 32
    for d, k in zip(data, key[3:]):
        dec[k] = d
    return ''.join(dec)

def find_encryption_method(method: str) -> str:
    match method:
        case "nothing": return lambda enc: enc
        case "encoded as base64": return lambda enc: base64.b64decode(enc).decode()
        case "inserted some non-hex characters": return lambda enc: re.sub(nonhex_regex, "", enc)

    circular_rotation_regex = r"circularly rotated (\w+) by (\d+)"
    if m := re.match(circular_rotation_regex, method):
        offset = m[2]
        return lambda enc: rotate_string(enc, int(offset))

    xor_encryption_regex = r"hex decoded, encrypted with XOR, hex encoded again. key: (\w+)"
    if m := re.match(xor_encryption_regex, method):
        key = m[1].encode()
        print(key)
        def decoder(enc):
            hex = binascii.unhexlify(enc)
            dec = xor(hex, key)
            hex = binascii.hexlify(dec)
            return hex.decode()

        return decoder

    scrambled_regex = r"scrambled! original positions as base64 encoded messagepack: (.*+)"
    if m := re.match(scrambled_regex, method):
        pos = m[1]
        key = base64.b64decode(pos)
        return lambda enc: unscramble(enc, key)

    raise Exception(f"Method ({method}) not found")

def main():
    req_path = "ian.ryan@gmail.com"

    while True:
        r = requests.get(f"{req_root}/{req_path}")
        assert r.status_code == 200
            
        json_obj = r.json()
        print (r.json())
        enc_task = json_obj["encrypted_path"]
        enc_task_id = enc_task.split("task_")[1]
        encryption_method = find_encryption_method(json_obj["encryption_method"])
        task_id = encryption_method(enc_task_id)
        
        req_path = f"task_{task_id}"

if __name__ == "__main__":
    main()

