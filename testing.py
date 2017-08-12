import binascii
import aes
import pbkdf2 as PBKDF2
import python_sha3
from utils import encode_hex
from bitcoin import *

# import of pycryptodome
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Random import get_random_bytes

try:
    import openssl
except:
    openssl = None

def eth_privtoaddr(priv):
    pub = encode_pubkey(secure_privtopub(priv), 'bin_electrum')
    return encode_hex(sha3(pub)[12:])
def secure_privtopub(priv):
    if len(priv) == 64:
        return secure_privtopub(priv.decode('hex')).encode('hex')
    if openssl:
        k = openssl.CKey()
        k.generate(priv)
        return k.get_pubkey()
    else:
        return privtopub(priv)

def sha3(x):
    return python_sha3.sha3_256(x).digest()


def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=128):
    #message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    plaintext = aes.strip_PKCS7_padding(plaintext)
    return plaintext.rstrip(b"\x07")
  
  
def pbkdf2(x):
    return PBKDF2._pbkdf2(x, x, 2000)[:16]

# VALUES
password="Ibuy500ether!"
pw = pbkdf2(password) # 3e661b9345173538b11e0e7e954025d2
encseed = binascii.unhexlify("d93b5ca93c8db8706256c73457c2d45f741a051274ed685300faa975f8525cc33d020d4e6f5277d2d796008671fc218ef2fb7979699806ded8784591d0b1304c07251b9451dfd125b7f1f15f516b3f130dac1b9e031aba8dbf9000246dce0f285c344c934e194507f1f06b85efc6427150ab9c31c9d142cb41a9665452bdb82da55535257a79e0c96980882c2ae817524abb32ae750d38135b7026a32ede9d99d486342e060844822eb89017e2d59b4e7b448d00fc5499a3f19cd98a4bb6453f0b2a382facc80217e4d5104703aad7623f21fd844c5f8e280b02a5fc6e1a01601e6cb685e7ec4b61aed3ff25a963193a49b6441ae90acc0f24db7e942efdffa6a77f12bcebc0c2cfd4345087a719a77e39ffd7d4daaa62f90a98aeb139831e53f165b44b5796e74013cc570a280cfec7f21a35d26740897742a6fb3bcbbf487df27c8656327d2b37796f7627491a837ce8eb30160d17ceb26af9f547e1e3a8d2b4fc75d2fdb958d75b8ea99097c941624afa99acd46036c1c70dab33f3c6b866a7da4206cdb8246e7e0ebdb455387bdcc7221789fb49dff2f8a94916d1e1f1aadcfaac7815fdbc6e7d151ae214656f1b463feb1021c7f4e7644ad1a76cf807648c29cb3036f563f2da1818bb6ac229289e66461ca3cc1dd7a454f7fdff334888feef9573b9f7a2e3e90272da0274c3b0121d56957cc6d932aef5c43ec1b0b511f0a2922e7acc786672eaae75ee5b909a84e4faea1fa88b3c72ef1ba2aa67b1cbdda2bf1ea5ba67b0a5aa245ce3ab710f78f5ddc6172a15311e066a78209891f59b1204f7ddc3798d3d092307b3d4f91f6b1c6415079f51ff88ce17dfcc8d05a4eb6196917e84c5e684a9d317c1760db2")
seed = "oznszcw6irhg7reba2xauvwi3btr3qhztmkdljkmimbzw3dqwkq3daf2wlm3kj5f2cidsxelc253q4nalv4kgsoxb376knnlwny7llehqznk2ymjbqcna7yyitdx252j32ll52uemoctiiiginoodn42acyhs33fnbejd47k3jw77omxpgyshjii5ze2db4u52udbqu3anv6wwiebtz6s2xrusji4i6w5gwumah57rnpcip57bw3gixlkzjeq52aagwnn5nrf5tjslfo2pdjb6ylkrfh6x5qhpzxdpdsdfnx3oatx6nlzuh532ci5pcwwest4i5qlwbrwidizmxr3vcmbfwkdtkm37laocfmyqyjvbtza6scsojjmicqwhigijhiqaugsqzuyzixl3hdfkdx6bfiixtzeawr53nhh2zt2jystsjtn2wypae2o4rzvjkurzee4j3gf5k7ymmkc74dw2x6qc4zwsbf3opukeyog336sxmdh7qxulx7d6d632yxt6dslvsl4wq5s5j5sjevku5wynnikr6aomj7fpnrl6ucnkwkgwnphldp46elaowrhaaq7bti3xwehghq27l6c"

print ("pw = %s "% binascii.hexlify( pbkdf2(password)))
print ("encseed = %s "%binascii.hexlify(encseed))
print ("seed[%d] = %s "%(len(seed),seed))

print ("DECRYPTION aes.py")
try:
    decrypted = aes.decryptData( pw, encseed )
    print ("decrypted[%d] = %s" % (len(decrypted),decrypted))
except Exception, e:
    decrypted = ""
    print("AES Decryption error. Bad password?")

if seed == decrypted:
	print("OK")
else:
	print("KO")

print ("DECRYPTION pycryptodome")
decrypted = decrypt(encseed,pw)
print ("decrypted[%d] = %s" % (len(decrypted),binascii.hexlify(decrypted)) )
if seed == decrypted:
        print("OK")
else:
        print("KO")

print("ETH TEST")
seed = decrypted
ethaddr = "9dd46b1c6d3f05e29e9c6f037eed9a595af4a9aa" 

ethpriv = sha3(seed)
eth_privtoaddr(ethpriv)
print ("ethaddr = %s"%ethaddr)
print ("eth_privtoaddr = %s"%eth_privtoaddr(ethpriv))
if eth_privtoaddr(ethpriv) == ethaddr:
	print ("OK")
else:
	print ("KO")

'''
# FROM pycrypto aes
print ("FROM aes.py TO aes.py")
encrypted = aes.encryptData(pw,data)
print ("encrypted = %s"%encrypted)
decrypted = aes.decryptData(pw, encrypted)
print ("decrypted = %s"%decrypted)
print ("")

print ("FROM pycryptodome TO pycryptodome")
encrypted = encrypt(data,pw)
print ("encrypted = %s"%encrypted)
decrypted = decrypt(encrypted,pw)
print ("decrypted = %s"%decrypted)
print ("")

print ("FROM pycryptodome TO aes.py")
encrypted = encrypt(data,pw)
print ("encrypted = %s"%encrypted)
decrypted = aes.decryptData(pw, encrypted)
print ("decrypted = %s"%decrypted)
print ("")

print ("FROM aes.py TO pycryptodome")
encrypted = aes.encryptData(pw,data)
print ("encrypted = %s"%encrypted)
decrypted = decrypt(encrypted,pw)
print ("decrypted = %s"%decrypted)
print ("")
'''
