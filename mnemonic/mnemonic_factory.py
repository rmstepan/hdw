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
    # append the checksum bits to the initial entropy
    entcs = entropy + checksum[:len(entropy) // 32]
    # separate the entropy+checksum into chunks of 11 bits
    bitchunks = [entcs[i:i+11] for i in range(0, len(entcs), 11)]
    wordlist = []
    with open("mnemonic/wordlist", 'r') as wl:
        wlines = wl.readlines()
        for chunk in bitchunks:
            # map each 11 bits to a word
            wordlist.append(wlines[int(chunk, 2)].split("\n")[0])

    return wordlist


# map the mnemonic phrase to the word list
# and retrieve the genesis key
def revert_mnemonic(words):
    indexes = []
    with open("mnemonic/wordlist", 'r') as wl:
        lines = wl.readlines()
        for w in words:
            for iline in range(0, len(lines)):
                if w == lines[iline].replace("\n", ""):
                    indexes.append(iline)
                    break
    bits = []
    for i in indexes:
        bits.append(fill_bits(bin(i)[2:], 11))

    return "".join(bits)


# stretch the mnemonic to a 512 bit seed through PBKDF2 function
def get_seed(mnemonic, passphrase=None, binary=False):
    if type(mnemonic) is list:
        mnemonic = " ".join(mnemonic)
    passphrase = "mnemonic" + passphrase if passphrase else ""
    _seed = hashlib.pbkdf2_hmac("sha512", bytes(mnemonic, 'utf-8'),
                                bytes(passphrase, 'utf-8'), 2048)

    return fill_bits(bin(int.from_bytes(_seed, byteorder=sys.byteorder))[2:], 512) if binary else \
        hex(int.from_bytes(_seed, byteorder=sys.byteorder))[2:]
