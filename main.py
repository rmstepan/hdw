from mnemonic import mnemonic_factory


entropy = mnemonic_factory.generate_entropy(128)
mnemonic = mnemonic_factory.get_mnemonics(entropy)
seed = mnemonic_factory.get_seed(mnemonic, "test", binary=True)

print("[+] Entropy: {}".format(entropy))
print("[+] Mnemonic: {}".format(mnemonic))
print("[+] Seed: {}".format(seed))
print("[!] Seed length: {}".format(len(seed)))
