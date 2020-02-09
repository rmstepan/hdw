import pytest
import string
from mnemonic import mnemonic_factory

def get_string(s):
    return string.printable + s + string.printable


def test_n1():
    x = 5
    y = 6
    assert x+y == 11  # test passed


def test_entropy_generator():
    assert len(mnemonic_factory.generate_entropy(256)) == 256


def test_sha256_length():
    assert len(mnemonic_factory.sha256("test")) == 64


def test_mnemonic_checksum():
    assert len(mnemonic_factory.get_checksum(mnemonic_factory.generate_entropy(128))) == 4
    assert len(mnemonic_factory.get_checksum(mnemonic_factory.generate_entropy(160))) == 5
    assert len(mnemonic_factory.get_checksum(mnemonic_factory.generate_entropy(192))) == 6
    assert len(mnemonic_factory.get_checksum(mnemonic_factory.generate_entropy(224))) == 7
    assert len(mnemonic_factory.get_checksum(mnemonic_factory.generate_entropy(256))) == 8


def test_mnemonic_sentence():
    assert len(mnemonic_factory.get_mnemonics(mnemonic_factory.generate_entropy(128))) == 12
    assert len(mnemonic_factory.get_mnemonics(mnemonic_factory.generate_entropy(160))) == 15
    assert len(mnemonic_factory.get_mnemonics(mnemonic_factory.generate_entropy(192))) == 18
    assert len(mnemonic_factory.get_mnemonics(mnemonic_factory.generate_entropy(224))) == 21
    assert len(mnemonic_factory.get_mnemonics(mnemonic_factory.generate_entropy(256))) == 24


def test_mnemonic_reversal():
    ENT = mnemonic_factory.generate_entropy(128)
    CS = mnemonic_factory.get_checksum(ENT)
    MN = mnemonic_factory.get_mnemonics(ENT)
    CMN = mnemonic_factory.revert_mnemonic(MN)
    assert CMN == ENT+CS


def test_seed_length():
    entropy = mnemonic_factory.generate_entropy()
    mnemonic = mnemonic_factory.get_mnemonics(entropy)
    bin_seed = mnemonic_factory.get_seed(mnemonic, binary=True)
    assert len(bin_seed) == 512
