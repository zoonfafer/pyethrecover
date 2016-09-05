import aes
import binascii
import bitcoin
import python_sha3
import pbkdf2 as PBKDF2
from utils import encode_hex, decode_hex

# Prefer openssl because it's more well-tested and reviewed; otherwise,
# use pybitcointools' internal ecdsa implementation
try:
    import openssl
except:
    openssl = None

def sha3(x):
    return python_sha3.sha3_256(x).digest()

def pbkdf2(x):
    return PBKDF2._pbkdf2(x, x, 2000)[:16]

def secure_privtopub(priv):
    if len(priv) == 64:
        return encode_hex(secure_privtopub(decode_hex(priv)))
    if openssl:
        k = openssl.CKey()
        k.generate(priv)
        return k.get_pubkey()
    else:
        return bitcoin.privtopub(priv)

def eth_privtoaddr(priv):
    pub = bitcoin.encode_pubkey(secure_privtopub(priv), 'bin_electrum')
    return encode_hex(sha3(pub)[12:])

def getseed(encseed, pw, ethaddr):
    pw = pbkdf2(pw)
    seed = aes.decryptData(pw, binascii.unhexlify(encseed))
    ethpriv = sha3(seed)
    if eth_privtoaddr(ethpriv) == ethaddr:
        return seed
