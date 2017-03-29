#!/usr/bin/python
from __future__ import print_function
import python_sha3
import aes
import getpass
import pbkdf2 as PBKDF2
from bitcoin import *
from utils import encode_hex
import traceback
from joblib import Parallel, delayed
import itertools
import argparse
import time

# import of pycryptodome
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Random import get_random_bytes

# Arguments

exodus = '36PrZ1KHYMpqSyAQXSG8VwbUiq2EogxLo2'
minimum = 1000000
maximum = 150000000000

# Option parsing

parser = argparse.ArgumentParser(description="Pyeth recovery tool.")
parser.add_argument('-p', '--password',
                    default=None, dest='pw',
                    help="A single password to try against the wallet.")
parser.add_argument('-f', '--passwords-file',
                    default=None, dest='pwfile',
                    help="A file containing a newline-delimited list of passwords to try. (default: %default)")
parser.add_argument('-s', '--password-spec-file',
                    default=None, dest='pwsfile',
                    help="A file containing a password specification")
parser.add_argument('-q', '--password-perm-file',
                    default=None, dest='pwqfile',
                    help="A file containing a password permutations specification")
parser.add_argument('-k', '--permutation-max-elements',
                    default=2, dest='k', type=int,
                    help="The maximum elements of permutations set to use to create a password")
parser.add_argument('-w', '--wallet',
                    default='wallet.json', dest='wallet',
                    help="The wallet against which to try the passwords. (default: %default)")

parser.add_argument("-v", "--verbose", action="count", default=0,
                    help="Be more verbose.")

options = parser.parse_args(sys.argv[1:])

# Function wrappers


def sha3(x):
    return python_sha3.sha3_256(x).digest()


def pbkdf2(x):
    return PBKDF2._pbkdf2(x, x, 2000)[:16]

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


class DecryptionException(Exception):
    pass


def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    plaintext = aes.strip_PKCS7_padding(plaintext)  
    return plaintext.rstrip(b"\0")
    
def getseed(encseed, pw, ethaddr):
	# FROM pycrypto aes
    #try:
    #    seed = aes.decryptData(pw, binascii.unhexlify(encseed))
    #except Exception, e:
    #    raise DecryptionException("AES Decryption error. Bad password?")

    # FROM pycryptodome aes-ni
    try:
        seed = decrypt(binascii.unhexlify(encseed),pw)
        if seed is None:
            raise DecryptionException("AES Decryption error. Bad password?")
        if len(seed) == 0:
            raise DecryptionException("AES Decryption error. Bad password?")

    except Exception, e:
        raise DecryptionException("AES Decryption error. Bad password?")

    try:
        ethpriv = sha3(seed)
        eth_privtoaddr(ethpriv)
        #print ("ethaddr:%s"%ethaddr)
        #print ("eth_privtoaddr:%s"%eth_privtoaddr(ethpriv))
        assert eth_privtoaddr(ethpriv) == ethaddr
    except Exception, e:
        # print ("eth_priv = %s" % eth_privtoaddr(ethpriv))
        # print ("ethadd = %s" % ethaddr)
        # traceback.print_exc()
        raise DecryptionException("Decryption failed. Bad password?")
    return seed


def list_passwords():
    if not options.pwfile:
        return []
    with open(options.pwfile) as f:
        return f.read().splitlines()


def ask_for_password():
    return getpass.getpass()


class PasswordFoundException(Exception):
    pass

def generate_all(el, tr):
    if el:
        for j in xrange(len(el[0])):
            for w in generate_all(el[1:], tr + el[0][j]):
                yield w
    else:
        yield tr


def is_valid(pw):

    if len(pw) <= 10:
        return False

    has_lower = False
    has_upper = False
    has_symbol = False
    has_number = False
    for char in pw:
        if char.isdigit():
            has_number = True
        else:
            if char.isalpha():
                if char.isupper():
                    has_upper = True
                else:
                    has_lower = True
            else:
                has_symbol = True

    return has_lower and has_upper and has_symbol and has_number


def attempt(w, pw, verbose):
    if not isinstance(pw, basestring):
        pw = ''.join(str(i) for i in pw)
    if not is_valid(pw):
        return ""
    try:
        if verbose > 0:
            print (pw)
        raise PasswordFoundException(
            """\n\nYour seed is:\n%s\nYour password is:\n%s""" % (getseed(w['encseed'], pbkdf2(pw), w['ethaddr']), pw))

    except DecryptionException as e:
        # print(e)
        return ""


def __main__():
    w = tryopen(options.wallet)
    if not w:
        print("Wallet file not found! (-h for help)")
        exit(1)

    pwds = []

    if not(options.pw or options.pwfile or options.pwsfile or options.pwqfile):
        print("No passwords specified! (-h for help)")

    if options.pw:
        pwds.append(options.pw)

    if options.pwfile:
        try:
            pwds.extend(list_passwords())
        except:
            print("Password file not found! (-h for help)")
            exit(1)

    if options.pwsfile:
        grammar = eval(file(options.pwsfile, 'r').read())
        pwds = itertools.chain(pwds, generate_all(grammar, ''))

    if options.pwqfile:
        perms_tuple = eval(file(options.pwqfile, 'r').read())
        pwds = itertools.permutations(perms_tuple, options.k)
        total = 1
        for i in range(len(perms_tuple)-options.k, len(perms_tuple)):
            total *= i
        print("Total passwords to try: " + str(total))
        print("Expected days at 500/s: %.5f" % ((((total/500.0)/60)/60)/24))

    start = time.time()
    try:
        Parallel(n_jobs=-1)(delayed(attempt)(w, pw, options.verbose) for pw in pwds)
    except Exception, e:
        traceback.print_exc()
        while True:
            sys.stdout.write('\a')
            sys.stdout.flush()

    print("elapsed: " + str(time.time()-start))

if __name__ == "__main__":
    __main__()
