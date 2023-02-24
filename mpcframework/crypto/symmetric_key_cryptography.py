import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

logger = logging.getLogger('AES_cipher')

class AES_cipher:
    def __init__(self, key, mode=AES.MODE_CBC, iv=None):
        self.key = key
        self.mode = mode
        self.iv = iv

    def encrypt(self, data):
        self.cipher = AES.new(self.key, self.mode, self.iv)
        return self.cipher.encrypt(pad(data, AES.block_size))

    def decrypt(self, bstring):
        self.cipher = AES.new(self.key, self.mode, self.iv)
        try:
            decrypted = self.cipher.decrypt(bstring)
            data = unpad(decrypted, AES.block_size)
        except ValueError as e:
            logger.error('could not retrieve encrypted message: {}'.format(e))
            logger.debug('data: {}'.format(bstring))
            return b''
        return data
