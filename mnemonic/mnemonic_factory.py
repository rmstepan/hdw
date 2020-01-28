import os
import sys
import hashlib


class EntropyRangeExceeded(Exception):
    pass


# fill the remaining bits with 0's
def fill_bits(binary, bits):
    if len(binary) < bits:
        return "0" * (bits - len(binary)) + binary
    return binary


# generate a given number of entropy bits
def generate_entropy(bits=256):
    if bits < 128 or bits > 256:
        raise EntropyRangeExceeded

    entropybits = bin(int.from_bytes(os.urandom(bits // 8), byteorder=sys.byteorder))[2:]
    return len(fill_bits(entropybits, bits))


# returns the sha256 hash of the given input
def sha256(_input):
    return hashlib.sha256(_input.encode("utf-8")).hexdigest()


# returns the checksum of the input hash
# checksum is given by entropy length / 32
def get_checksum(_entropy):
    entropy_length = len(_entropy) // 32
    return sha256(_entropy)[:entropy_length]


print(generate_entropy(256))
