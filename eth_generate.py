from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from eth_account import Account

# Generate a mnemonic phrase (12 words)
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(12)
print("MNEMONIC:", mnemonic)

# Generate the seed from the mnemonic phrase (optional passphrase is empty)
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# Derive the first Ethereum address using BIP44, path: m/44'/60'/0'/0/0
bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
acct0 = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

# Private key
priv_key_hex = acct0.PrivateKey().Raw().ToHex()

# Print eth-account address
acct = Account.from_key(bytes.fromhex(priv_key_hex))
print("ETH address:", acct.address)
print("Private key (hex):", priv_key_hex)
