#!/usr/bin/python
from __future__ import print_function
import python_sha3
import aes
import os
import sys
import json
import getpass
import binascii
import pbkdf2 as PBKDF2
from bitcoin import *
from utils import decode_hex, encode_hex
try:
    from urllib2 import Request, urlopen
except ImportError:
    from urllib.request import Request, urlopen

from optparse import OptionParser

# Arguments

exodus = '36PrZ1KHYMpqSyAQXSG8VwbUiq2EogxLo2'
minimum = 1000000
maximum = 150000000000

# Option parsing

parser = OptionParser()
parser.add_option('-p', '--password',
                  default=None, dest='pw',
                  help="A single password to try against the wallet.")
parser.add_option('-f', '--passwords-file',
                  default="pwds.txt", dest='pwfile',
                  help="A file containing a newline-delimited list of passwords to try. (default: %default)")
parser.add_option('-w', '--wallet',
                  default='wallet.json', dest='wallet',
                  help="The wallet against which to try the passwords. (default: %default)")

(options, args) = parser.parse_args()

# Function wrappers


def sha3(x):
    return python_sha3.sha3_256(x).digest()


def pbkdf2(x):
    return PBKDF2._pbkdf2(x, x, 2000)[:16]


# Makes a request to a given URL (first arg) and optional params (second arg)
def make_request(url, data, headers):
    req = Request(url, data, headers)
    return urlopen(req).read().strip()


# Prefer openssl because it's more well-tested and reviewed; otherwise,
# use pybitcointools' internal ecdsa implementation
try:
    import openssl
except:
    openssl = None


def openssl_tx_sign(tx, priv):
    if len(priv) == 64:
        priv = priv.decode('hex')
    if openssl:
        k = openssl.CKey()
        k.generate(priv)
        u = k.sign(bitcoin.bin_txhash(tx))
        return u.encode('hex')
    else:
        return ecdsa_tx_sign(tx, priv)


def secure_sign(tx, i, priv):
    i = int(i)
    if not re.match('^[0-9a-fA-F]*$', tx):
        return sign(tx.encode('hex'), i, priv).decode('hex')
    if len(priv) <= 33:
        priv = priv.encode('hex')
    pub = privkey_to_pubkey(priv)
    address = pubkey_to_address(pub)
    signing_tx = signature_form(tx, i, mk_pubkey_script(address))
    sig = openssl_tx_sign(signing_tx, priv)
    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = serialize_script([sig, pub])
    return serialize(txobj)


def secure_privtopub(priv):
    if len(priv) == 64:
        return secure_privtopub(priv.decode('hex')).encode('hex')
    if openssl:
        k = openssl.CKey()
        k.generate(priv)
        return k.get_pubkey()
    else:
        return privtopub(priv)


def tryopen(f):
    try:
        assert f
        t = open(f).read()
        try:
            return json.loads(t)
        except:
            raise Exception("Corrupted file: "+f)
    except:
        return None


def eth_privtoaddr(priv):
    pub = encode_pubkey(secure_privtopub(priv), 'bin_electrum')
    return encode_hex(sha3(pub)[12:])


def getseed(encseed, pw, ethaddr):
    try:
        seed = aes.decryptData(pw, binascii.unhexlify(encseed))
        ethpriv = sha3(seed)
        eth_privtoaddr(ethpriv)
        assert eth_privtoaddr(ethpriv) == ethaddr
    except:
        raise Exception("Decryption failed. Bad password?")
    return seed


def list_passwords():
    if not options.pwfile:
        return []
    with open(options.pwfile) as f:
        return f.read().splitlines()


def ask_for_password():
    return getpass.getpass()


def __main__():
    w = tryopen(options.wallet)
    if not w:
        print("Wallet file not found! (-h for help)")
        exit(1)

    pwds = []

    if options.pw:
        pwds.append(options.pw)

    if options.pwfile:
        try:
            pwds.extend(list_passwords())
        except:
            print("Password file not found! (-h for help)")
            exit(1)

    if len(pwds) == 0:
        pwds.append(ask_for_password())

    for pw in pwds:
        try:
            print("\n\nYour seed is:\n%s" % getseed(w['encseed'], pbkdf2(pw), w['ethaddr']))
            print("\nYour password is:\n%s\n" % pw);
            exit(0)
        except Exception as e:
            if not options.pwfile:
                raise
            print("x", end="")

if __name__ == "__main__":
    __main__()
