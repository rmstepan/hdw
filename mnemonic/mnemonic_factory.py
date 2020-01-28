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


# generate a given number of entropy bits using CSPRNG from /dev/urandom
def generate_entropy(bits=256):
    if bits < 128 or bits > 256:
        raise EntropyRangeExceeded

    entropybits = bin(int.from_bytes(os.urandom(bits // 8), byteorder=sys.byteorder))[2:]
    return fill_bits(entropybits, bits)


# returns the sha256 hash of the given input
def sha256(_input):
    return hashlib.sha256(_input.encode("utf-8")).hexdigest()


# returns the checksum of the input hash
# checksum is given by the first (entropy length / 32)
# bits of the sha256 hash applied on entropy bits
def get_checksum(_entropy):
    entropy_length = len(_entropy) // 32
    return bin(int(sha256(_entropy), 16))[2:][:entropy_length]


# separate the entropy+checksum bits in chunks of 11 bits
# and map them to the word list to get english words
# prints and returns the mnemonic phrase
def get_mnemonics(entropy):
    checksum = get_checksum(entropy)
    entcs = entropy + checksum[:len(entropy) // 32]
    bitlist = [entcs[i:i+11] for i in range(0, len(entcs), 11)]
    wordlist = []
    with open("wordlist", 'r') as wl:
        wlines = wl.readlines()
        for i in bitlist:
            wordlist.append(wlines[int(i, 2)].split("\n")[0])

    wordlist = " ".join(wordlist)
    print(wordlist)
    return wordlist
