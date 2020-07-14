from mnemonic import mnemonic_factory

entropy = mnemonic_factory.generate_entropy(256)
mnemonic = mnemonic_factory.get_mnemonics(entropy)
seed = mnemonic_factory.get_seed(mnemonic, "test", binary=False)
master_code = mnemonic_factory.get_master_code(seed)

print("[+] Entropy:     {}".format(entropy))
print("[+] Mnemonic:    {}".format(" ".join(mnemonic)))

root = mnemonic_factory.derive_path(master_code, "m/0/0/1/3'/4")
