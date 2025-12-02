from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from eth_account import Account
import secrets

def generate_wallet():
    """Generate new wallet address and private key."""
    try:
        priv_key_bytes = secrets.token_bytes(32)
        acct = Account.from_key(priv_key_bytes)

        print(f"Wallet generated successfully")
        print(f"Wallet Address: {acct.address}")
        print(f"Private Key (hex): {acct.key.hex()}")
    except Exception as e:
        print(f"Error generating wallet: {e}")

def generate_mnemonic_and_wallet():
    """Generate a new mnemonic phrase and wallet address."""
    try:
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
        print("Wallet generated successfully")
        print("Wallet address:", acct.address)
        print("Private key (hex):", priv_key_hex)
    except Exception as e:
        print(f"Error generating wallet: {e}")

if __name__ == "__main__":
    # generate_wallet()
    generate_mnemonic_and_wallet()
