import pytest
from ..mnemonic import mnemonic_factory


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
    pass
    # assert len(mnemonic_factory.get_mnemonics(entropy_bits=128)) == 12
    # assert len(mnemonic_factory.get_mnemonics(entropy_bits=160)) == 15
    # assert len(mnemonic_factory.get_mnemonics(entropy_bits=192)) == 18
    # assert len(mnemonic_factory.get_mnemonics(entropy_bits=224)) == 21
    # assert len(mnemonic_factory.get_mnemonics(entropy_bits=256)) == 24
