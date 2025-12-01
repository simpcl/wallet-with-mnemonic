from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1, EthAddr
from bip_utils import Bip44, Bip44Coins, Bip44Changes
from eth_utils import to_checksum_address
import os
from dotenv import load_dotenv

load_dotenv()

def generate_address2(seed_bytes, coin, account, change, addr_index):
    from bip_utils import Bip44
    bip44_acc = Bip44.FromSeed(seed_bytes, coin).Purpose().Coin().Account(account).Change(change)
    addr = bip44_acc.AddressIndex(addr_index).PublicKey().ToAddress()
    private_key = bip44_acc.AddressIndex(addr_index).PrivateKey().Raw().ToHex()
    return addr, private_key

def show_addresses_from_mnemonic(mnemonic):
    coin = Bip44Coins.ETHEREUM
    change = Bip44Changes.CHAIN_EXT
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    for account in range(0, 1):
        for address_index in range(0, 8):
            address, private_key = generate_address2(seed_bytes, coin, account, change, address_index)
            path = f"m/44'/{coin}'/{account}'/{change}/{address_index}"
            print("\n===== Matched address found =====")
            print(f"Path: {path}")
            print(f"Address: {address}")
            print(f"PrivateKey: {private_key}")

if __name__ == "__main__":
    mnemonic = os.environ.get("MNEMONIC", "")
    if not mnemonic:
        print("Please set the environment variable MNEMONIC.")
        exit(1)

    show_addresses_from_mnemonic(mnemonic)