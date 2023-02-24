import logging
from os import urandom
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
import msgpack

logger = logging.getLogger('RSA_cipher')


class RSA_cipher:
    SK_PREFIX = b'-----BEGIN RSA PRIVATE KEY-----'
    SK_SUFFIX = b'-----END RSA PRIVATE KEY-----'
    PK_PREFIX = b'-----BEGIN PUBLIC KEY-----'
    PK_SUFFIX = b'-----END PUBLIC KEY-----'

    def __init__(self):
        self.cipher = None
        self.keys = None

    def _generateKeyPair(self, size=2048):
        random_generator = Random.new().read  # can also be urandom
        self.keys = RSA.generate(size, randfunc=random_generator)
        self.cipher = PKCS1_OAEP.new(self.keys)

    def loadKeyText(self, key):
        self.keys = RSA.importKey(key)
        self.cipher = PKCS1_OAEP.new(self.keys)

    def encrypt(self, data):
        if type(data) == dict:
            data = msgpack.dumps(data)
        encrypted = self.cipher.encrypt(data)
        # print('RSA_cipher:encrypted:\n' + str(encrypted))
        return encrypted

    def decrypt(self, bytestring):
        try:
            decrypted = self.cipher.decrypt(bytestring)
        except Exception as e:
            logger.error('error decrypting received data: ' + str(e))
            logger.debug('data:\n' + str(bytestring))
            return {}
        head = decrypted[0]
        if (head >= 128 and head <= 143) or head == 222:  # Check for packed dict
            try:
                decrypted = msgpack.loads(decrypted)
            except Exception as e:
                logger.error('error unpacking received data: ' + str(e))
                logger.debug('data:\n' + str(decrypted))
        return decrypted

    def getPrivateKeyBytes(self):
        if self.keys is None:
            self._generateKeyPair()
        sk = self.keys.export_key('PEM').lstrip(self.SK_PREFIX).rstrip(self.SK_SUFFIX)
        if b'PUBLIC' in sk:
            return b''
        return b64decode(b''.join(sk.split(b'\n')))

    def getPublicKeyBytes(self):
        if self.keys is None:
            self._generateKeyPair()
        pk = self.keys.publickey().export_key('PEM').lstrip(self.PK_PREFIX).rstrip(self.PK_SUFFIX)
        return b64decode(b''.join(pk.split(b'\n')))

    @classmethod
    def fromPrivateKeyBytes(cls, key_bytes):
        key = cls.SK_PREFIX + b'\n' + b64encode(key_bytes) + b'\n' + cls.SK_SUFFIX
        return cls.fromKey(key)

    @classmethod
    def fromPublicKeyBytes(cls, key_bytes):
        key = cls.PK_PREFIX + b'\n' + b64encode(key_bytes) + b'\n' + cls.PK_SUFFIX
        return cls.fromKey(key)

    @classmethod
    def fromKey(cls, key):
        rsa_cipher = cls()
        rsa_cipher.loadKeyText(key)
        return rsa_cipher
