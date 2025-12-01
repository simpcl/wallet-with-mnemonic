from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1, EthAddr
from bip_utils import Bip44, Bip44Coins, Bip44Changes
from eth_utils import to_checksum_address
import os
from dotenv import load_dotenv

load_dotenv()


HARDENED_OFFSET = 0x80000000

def derive_address(root, path):
    node = root
    for level in path.split("/"):
        if level == "m":
            continue
        hardened = level.endswith("'")
        index = int(level.replace("'", ""))
        if hardened:
            node = node.ChildKey(index + HARDENED_OFFSET)
        else:
            node = node.ChildKey(index)
    return node

def generate_address(root, path):
    wallet_node = derive_address(root, path)
    pub = wallet_node.PublicKey().RawCompressed().ToBytes()
    return EthAddr.EncodeKey(pub), wallet_node.PrivateKey().Raw().ToHex()

def generate_address2(seed_bytes, coin, account, change, addr_index):
    from bip_utils import Bip44
    bip44_acc = Bip44.FromSeed(seed_bytes, coin).Purpose().Coin().Account(account).Change(change)
    addr = bip44_acc.AddressIndex(addr_index).PublicKey().ToAddress()
    private_key = bip44_acc.AddressIndex(addr_index).PrivateKey().Raw().ToHex()
    return addr, private_key

def search_address(mnemonic, target_address):
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    root = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

    max_account = os.environ.get("MAX_ACCOUNT", "11")
    max_account = int(max_account)
    max_change = os.environ.get("MAX_CHANGE", "2")
    max_change = int(max_change)
    max_address = os.environ.get("MAX_ADDRESS", "20")
    max_address = int(max_address)
                   
    print("Searching for path: m/44'/60'/account'/change/address_index")
    for account in range(0, max_account):
        for change in range(0, max_change):
            for address_index in range(0, max_address):
                path = f"m/44'/60'/{account}'/{change}/{address_index}"
                address, private_key = generate_address(root, path)
                if address.lower().startswith(target_address):
                    return path, address, private_key

    print("Searching for path: m/44'/60'/account'/address_index")
    for account in range(0, max_account):
        for address_index in range(0, max_address):
            path = f"m/44'/60'/{account}'/{address_index}"
            address, private_key = generate_address(root, path)
            if address.lower().startswith(target_address):
                return path, address, private_key

    print("Searching for path: m/44'/195'/0'/0/address_index")
    for address_index in range(0, max_address):
        path = f"m/44'/195'/0'/0/{address_index}"
        address, private_key = generate_address(root, path)
        if address.lower().startswith(target_address):
            return path, address, private_key

    print("Searching for path: m/44'/coin'/account'/change/address_index")
    for coin in [Bip44Coins.ETHEREUM, Bip44Coins.BITCOIN, Bip44Coins.SOLANA, Bip44Coins.BINANCE_SMART_CHAIN]:
        for account in range(0, max_account):
            for change in [Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT]:
                for address_index in range(0, max_address):
                    address, private_key = generate_address2(seed_bytes, coin, account, change, address_index)
                    if address.lower().startswith(target_address):
                        path = f"m/44'/{coin}'/{account}'/{change}/{address_index}"
                        return path, address, private_key
 
    return None


if __name__ == "__main__":
    mnemonic = os.environ.get("MNEMONIC", "")
    if not mnemonic:
        print("Please set the environment variable MNEMONIC.")
        exit(1)
    target_address = os.environ.get("TARGET_ADDRESS", "")
    if not target_address:
        print("Please set the environment variable TARGET_ADDRESS.")
        exit(1)
    target_address = target_address.lower()

    result = search_address(mnemonic, target_address)

    if result:
        path, address, privkey = result
        print("\n===== Matched address found =====")
        print(f"Path: {path}")
        print(f"Address: {address}")
        print(f"PrivateKey: 0x{privkey}")
    else:
        print("\nNot found.")

