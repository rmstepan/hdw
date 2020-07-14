import os
import sys
import hmac
import hashlib
import ecdsa
from ecdsa.ecdsa import generator_secp256k1


class EntropyRangeExceeded(Exception):
    pass


MAINNET_XPRV = b"\x04\x88\xad\xe4"  # mainnet private key serialization
MAINNET_XPUB = b"\x04\x88\xb2\x1e"  # mainnet public key serialization
TESTNET_XPRV = b"\x04\x35\x83\x94"  # testnet private key serialization
TESTNET_XPUB = b"\x04\x35\x87\xcf"  # testnet public key serialization


##
# check if input string is binary or not
# return true or false
def is_binary(string):
    p = set(string)
    s = {'0', '1'}

    if s == p or p == {'0'} or p == {'1'}:
        return True
    else:
        return False


##
# convert given string to base 58 encoding
# base 58 - I and l discarded to avoid confusion
# return b58 encoded string
def b58encode(v):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    p, acc = 1, 0
    for c in reversed(v):
        if sys.version < "3":
            c = ord(c)
        acc += p * c
        p = p << 8

    string = ""
    while acc:
        acc, idx = divmod(acc, 58)
        string = alphabet[idx: idx + 1] + string
    return string


##
# fill the remaining bits with 0's
def fill_bits(binary, bits):
    if len(binary) < bits:
        return "0" * (bits - len(binary)) + binary
    return binary


##
# generate a given number of entropy bits using CSPRNG from /dev/urandom
def generate_entropy(bits=256):
    if bits % 32 != 0:
        raise ValueError("Strength must be a multiple of 32")
    if bits < 128 or bits > 256:
        raise EntropyRangeExceeded

    entropy_bits = bin(int.from_bytes(os.urandom(bits // 8), byteorder="big"))[2:]
    return fill_bits(entropy_bits, bits)


##
# returns the sha256 hash of the given input
def sha256(_input):
    ent_bytes = int(_input, 2).to_bytes(len(_input) // 8, byteorder='big')
    return hashlib.sha256(ent_bytes).hexdigest()


##
# returns the checksum of the input hash
# checksum is given by the first (entropy length / 32)
# bits of the sha256 hash applied on entropy bits
def get_checksum(_entropy):
    entropy_length = len(_entropy) // 32
    return bin(int(sha256(_entropy), 16))[2:].zfill(256)[:entropy_length]


##
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


##
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


##
# stretch the mnemonic to a 512 bit seed through PBKDF2 function
def get_seed(mnemonic, passphrase=None, binary=False):
    if type(mnemonic) is list:
        mnemonic = " ".join(mnemonic)
    passphrase = "mnemonic" + passphrase if passphrase else "mnemonic"
    _seed = hashlib.pbkdf2_hmac("sha512", bytes(mnemonic, 'utf-8'),
                                bytes(passphrase, 'utf-8'), 2048)

    return fill_bits(bin(int.from_bytes(_seed, byteorder="big"))[2:], 512) if binary else \
        hex(int.from_bytes(_seed, byteorder="big"))[2:]


##
# get the master private key, public key and master chain code from the master seed
# _seed -> master seed generated from mnemonic (64 bytes); hex or bin
# return: (xpriv, xpub), (priv, pub, chain_code)
def get_master_code(_seed):
    if is_binary(_seed):
        _seed = int(_seed, 2).to_bytes(len(_seed) // 8, byteorder='big')
    else:
        _seed = bytes.fromhex(_seed)

    seed = hmac.new(b"Bitcoin seed", _seed, digestmod=hashlib.sha512).digest()

    # add formatting bytes
    xprv = MAINNET_XPRV  # version for mainnet private key
    xprv += b"\x00" * 9  # Depth(1b), child number(4b), parent fingerprint(4b)

    il = seed[:32]  # master private key
    ir = seed[32:]  # master chain code

    xprv += ir
    xprv += b"\x00" + il

    # Double hash using SHA256
    hashed_xprv = hashlib.sha256(xprv).digest()
    hashed_xprv = hashlib.sha256(hashed_xprv).digest()

    # Append 4 bytes of checksum
    xprv += hashed_xprv[:4]

    ##
    # create master public key
    privkey_obj = ecdsa.SigningKey.from_string(il, curve=ecdsa.SECP256k1)
    pubkey_obj = privkey_obj.get_verifying_key().to_string("compressed")

    xpub = MAINNET_XPUB  # version for mainnet public key
    xpub += b"\x00" * 9
    xpub += ir
    xpub += pubkey_obj

    # Double hash using SHA256
    hashed_xpub = hashlib.sha256(xpub).digest()
    hashed_xpub = hashlib.sha256(hashed_xpub).digest()

    # add 4 checksum bytes
    xpub += hashed_xpub[:4]

    # return base 58 tuple (master code, (master private key, master chain code))

    return (b58encode(xprv), b58encode(xpub)), (il, pubkey_obj, ir)


##
# derive a new child from the given parent
# parent_priv -> Parent private key (32 bytes)
# parent_pub  -> Parent public key (33 bytes - compressed)
# hardened    -> 1 for hardened derivation or 0 for normal derivation
# depth       -> the child depth in the tree
# index       -> the child index to be derived
def derive_child(parent_priv, parent_pub, parent_chain_code, hardened=False, depth=0, index=0):
    if index < 0:
        raise ValueError("Child index should be greater than or equal to 0.")
    if depth < 0:
        raise ValueError("Depth should be greater than or equal to 0.")

    if not hardened:
        # concatenate parent public key || child index -> normal derivation
        parent_index = parent_pub + int.to_bytes(index, length=4, byteorder="big")
    else:
        # concatenate parent private key || child index -> hardened derivation
        parent_index = b"\x00" + parent_priv + int.to_bytes(index, length=4, byteorder="big")

    # HMAC that shit
    data = hmac.new(parent_chain_code, parent_index, digestmod=hashlib.sha512).digest()

    # set child chain code to IR
    child_chain_code = data[32:]
    il = data[:32]

    # build child private key -> parent private key + IL (scalar addition) (mod n)
    child_private_key = int.from_bytes(parent_priv, byteorder="big") + int.from_bytes(il, byteorder="big")
    child_private_key = child_private_key % generator_secp256k1.order()
    child_private_key = int.to_bytes(child_private_key, length=32, byteorder="big")

    # build child public key from SECP256k1 curve
    # compress the pubkey to 33 bytes
    # y point is discarded and replaced with 0x02 for evenness or 0x03 for oddness -> the header byte
    privkey_obj = ecdsa.SigningKey.from_string(child_private_key, curve=ecdsa.SECP256k1)
    pubkey_obj = privkey_obj.get_verifying_key().to_string("compressed")
    child_public_key = pubkey_obj

    #####################################################################################
    # Extend child private key
    extended_priv = MAINNET_XPRV                             # add version - 4 bytes
    extended_priv += int.to_bytes(depth, length=1, byteorder="big")  # add depth - 1 byte
    extended_priv += int.to_bytes(index, length=4, byteorder="big")  # add index - 4 bytes

    # add first 4 bytes (parent fingerprint) from hash160 hash (ripemd160(sha256(xpriv)))
    sha = hashlib.sha256(b"\x00" + parent_priv).digest()
    hash160 = hashlib.new("ripemd160")
    hash160.update(sha)
    hash160 = hash160.digest()

    extended_priv += hash160[:4]
    extended_priv += child_chain_code
    extended_priv += b"\x00" + child_private_key

    hashed_xpriv = hashlib.sha256(extended_priv).digest()
    hashed_xpriv = hashlib.sha256(hashed_xpriv).digest()

    extended_priv += hashed_xpriv[:4]

    #######################################################################################
    # Extend child public key
    extended_pub = MAINNET_XPUB     # add version - 4 bytes
    extended_pub += int.to_bytes(depth, length=1, byteorder="big")  # add depth - 1 byte
    extended_pub += int.to_bytes(index, length=4, byteorder="big")  # add index - 4 bytes

    # add first 4 bytes (parent fingerprint) from hash160 hash (ripemd160(sha256(xpub)))
    sha = hashlib.sha256(parent_pub).digest()
    hash160 = hashlib.new("ripemd160")
    hash160.update(sha)
    hash160 = hash160.digest()

    extended_pub += hash160[:4]
    extended_pub += child_chain_code
    extended_pub += child_public_key

    hashed_xpub = hashlib.sha256(extended_pub).digest()
    hashed_xpub = hashlib.sha256(hashed_xpub).digest()

    extended_pub += hashed_xpub[:4]

    return (b58encode(extended_priv), b58encode(extended_pub)), (child_private_key, child_public_key, child_chain_code)
