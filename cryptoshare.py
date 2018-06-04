import fcp
import base64
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as sig_pkcs
from Crypto import Random
import sys
import random
import string
import hashlib

#I straight up stole this off of stack overflow
class AESCipher(object):

    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

#This class is called RSAKeyManager. Guess what it does!
#Key storage is _not_ secure. 
#Other stuff is _not_ secure. This is a PoC. Don't use it for important things.
class RSAKeyManager:

    def __init__(self):
        self.key = None
        self.contactKeys = {}

    #Max pyCrypto keysize is 2048 bits
    def generate(self):
        random_generator = Random.new().read
        self.key = RSA.generate(2048, random_generator)
        return self.key

    def saveKeys(self, filepath):
	f = open(filepath, "wb")
        f.write(self.key.exportKey('PEM'))
        #pickle.dump([self.key, self.contactKeys], f)
        f.close()

    def loadKeys(self, filepath):
        f = open(filepath, "rb")
        self.key = RSA.importKey(f.read())
        #o = pickle.load(f)
        #self.key = o[0]
        #self.contactKeys = o[1]
        f.close()
        	
    def encrypt(self, cleartext, keydigest):
        h = SHA256.new(cleartext)
        cipher = PKCS1_v1_5.new(self.contactKeys[keydigest])
        ciphertext = cipher.encrypt(cleartext+h.digest())
        return base64.b64encode(ciphertext)

    def decrypt(self, ciphertext):
        dsize = SHA256.digest_size
        # A sentinel is a value that tells us if decryption was successful
        sentinel = Random.new().read(15+dsize)
        cipher = PKCS1_v1_5.new(self.key)
        message = cipher.decrypt(base64.b64decode(ciphertext), sentinel)
        digest = SHA256.new(message[:-dsize]).digest()
        if digest!=message[-dsize:]:
            print "Something's wrong: Digest does not match message"
        return message[:-dsize]

    def signature(self, cleartext):
        h = SHA256.new(cleartext)
        signer = sig_pkcs.new(self.key)
        signature = signer.sign(h)
        return base64.b64encode(signature)

    #Pass in a base64 encoded string representing a public key
    def add_pubkey(self, key):
        key = RSA.importKey(key)
        self.contactKeys[self.pubkey_digest(key)] = key

    #use the SHA256 digest of the keys to establish contact
    def pubkey_digest(self, key):
        pubkey = key.publickey().exportKey(format='DER', pkcs=1) #output the public key in binary format
        h = SHA256.new(pubkey)
        return h.hexdigest()
        
    def verify(self, message, signature, keydigest):
        h = SHA256.new(message)
        verifier = sig_pkcs.new(self.contactKeys[keydigest])
        if not verifier.verify(h, base64.b64decode(signature)):
            return False
        else:
            return True


class CryptoShare:
    def __init__(self, keyPath=None):
        self.node = fcp.node.FCPNode()
        self.manager = RSAKeyManager()
        if keyPath is None:
            self.manager.generate()
            self.manager.saveKeys("keyfile")
        else:
            self.manager.loadKeys(keyPath)

    #import a key straight from a freenet URI
    #definitely assuming things are properly formatted
    #again, this a POC
    def fetchKey(self, URI):
        key = self.node.get(uri=URI)[1]
        self.manager.add_pubkey(key)
        return key

    #Establish a beginning channel with key digest
    #Obviously we must already have the key
    def generateChannel(self, keydigest):
        k = self.manager.contactKeys[keydigest]
        #Do a string compare of the digests and make the intial channel lower+higher string val
        s = sorted([self.manager.pubkey_digest(self.manager.key),keydigest])
        contactChannel = "KSK@" + s[0] + s[1]
        randomChannel = "KSK@" + ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(50))
        ciphertext = self.manager.encrypt(randomChannel, keydigest)
        signature = self.manager.signature(ciphertext)
        print self.node.put(uri=contactChannel, data=ciphertext+":"+signature)
        return ciphertext

    #ripped from https://interactivepython.org/runestone/static/everyday/2013/01/3_password.html
    #NOT CRYPTOGRAPHICALLY SECURE
    #FFS THIS IS A POC
    def generatePassphrase(self):
        alphabet = "#@!abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        pw_length = 100
        mypw = ""

        for i in range(pw_length):
            next_index = random.randrange(len(alphabet))
            mypw = mypw + alphabet[next_index]

        return mypw


    #On first contact with our friend, get a signed and encrypted message about a new channel to publish on
    #This is mostly out of paranoia to make it harder to even capture ciphertext
    def discoverChannel(self, keydigest):
        k = self.manager.contactKeys[keydigest]
        s = sorted([self.manager.pubkey_digest(self.manager.key), keydigest])
        contactChannel = "KSK@" + s[0] + s[1]
        newChannelMessage = self.node.get(uri=contactChannel)[1]
        ciphertext = newChannelMessage.split(":")[0]
        signature = newChannelMessage.split(":")[1]
        if self.manager.verify(ciphertext, signature, keydigest):
            return self.manager.decrypt(ciphertext)
        else:
            print "Something's up - signature not valid"

    def getSecretCombo(self, secretChannel, keydigest):
        rawdata = self.node.get(uri=secretChannel)[1]
        secretCombo = self.manager.decrypt(rawdata.split(":")[0])
        encryptedData = rawdata.split(":")[0]
        dataSignature = rawdata.split(":")[1]
        print "Secret Combo: " + secretCombo
        if self.manager.verify(encryptedData, dataSignature, keydigest):
            return secretCombo.split(":")[0], secretCombo.split(":")[1]
        else:
            print "Message signature does not match"

    def publishSecretCombo(self, secretChannel, URI, AESKey, keydigest):
        ciphertext = self.manager.encrypt(URI + ":" + AESKey, keydigest)
        signature = self.manager.signature(ciphertext)
        return self.node.put(uri=secretChannel, data=ciphertext+":"+signature)
        

    def publishKey(self):
        return self.node.put(URI="CHK@", data=self.manager.key.publickey().exportKey(format='DER', pkcs=1))

if __name__ == "__main__":
    cs1 = CryptoShare()
    cs2 = CryptoShare()
    cs1.manager.add_pubkey(cs2.manager.key.publickey().exportKey(format='DER', pkcs=1))
    cs2.manager.add_pubkey(cs1.manager.key.publickey().exportKey(format='DER', pkcs=1))
    print "Nodes have exchanged keys either out of band or over freenet."
    print "Publishing encrypted and signed secret channel to deterministic KSK..."
    cs1.generateChannel(cs1.manager.contactKeys.keys()[0])
    print "Fetching signed and encrypted secret channel URI from deterministic KSK..."
    secretChannel = cs2.discoverChannel(cs2.manager.contactKeys.keys()[0])
    print "Secret Channel: " + secretChannel
    print "Now for a super secret message."
    secretKey = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(100))
    cipher = AESCipher(secretKey)
    ciphertext = cipher.encrypt("freenet rules")
    print "Publishing our very secret data..."
    secretURI = cs1.node.put(data=ciphertext)
    print "Encrypted payload has been published!"
    print "Now to share our secrets..."
    cs1.publishSecretCombo(secretChannel, secretURI, secretKey, cs1.manager.contactKeys.keys()[0])
    secretCombo = cs2.getSecretCombo(secretChannel, cs2.manager.contactKeys.keys()[0])
    print "Getting data from secret URI " + secretCombo[0]
    secretData = cs2.node.get(uri=secretCombo[0])[1]
    print "Secret is..."
    newCipher = AESCipher(secretCombo[1]) #Even though we already have the AES key locally, use the fetched one to show PoC
    print newCipher.decrypt(secretData)
    

