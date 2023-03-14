import sys
import logging
import msgpack
import socket

from ..crypto.symmetric_key_cryptography import AES_cipher

logger = logging.getLogger('NetworkProtocolBase')
MAX_PKT_LENGTH = 2048


class NetworkProtocolBase:
    serveraddr = ('localhost', 1250)

    def __init__(self):
        self.remotetype = ''
        self.srvrid = ''
        self.mysocket = None
        self.secureconn = False
        self.aes_cipher = None
        self.rxbuffer = b''

    def establishConnection(self):
        self.serv_addr_str = ':'.join([self.serveraddr[0], str(self.serveraddr[1])])
        self.mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug('sending connection request to {} server at {}'
                    .format(self.remotetype, self.serv_addr_str)
        )
        status = self.mysocket.connect_ex(self.serveraddr)
        if status:
            logger.error('could not connect to {} server at {}'.format(self.remotetype, self.serv_addr_str))
        else:
            logger.info('connected to {} server at {}'.format(self.remotetype, self.serv_addr_str))
        return status

    def sendData(self, data):
        if type(data) == dict:
            data = msgpack.dumps(data)
        if self.secureconn:
            data = self.aes_cipher.encrypt(data)
        bstring = b''.join([str(len(data)).encode('ascii'), b':', data, b','])
        self.mysocket.sendall(bstring)

    def receiveData(self, binary=False):
        if not self.rxbuffer:
            self.rxbuffer = self.mysocket.recv(MAX_PKT_LENGTH)
        if not self.rxbuffer:
            logger.warning('empty response from the {} server {}'.format(self.remotetype, self.srvrid))
        elif b':' in self.rxbuffer:
            head, self.rxbuffer = self.rxbuffer.split(b':', 1)
            try:
                length = int(head)
            except ValueError:
                logger.error(e)
            else:
                if len(self.rxbuffer) > length:
                    bstring, self.rxbuffer = self.rxbuffer[:length+1], self.rxbuffer[length+1:]
                    # logger.debug('remaining in rx buffer: {}'.format(self.rxbuffer))
                    if bstring.endswith(b','):
                        bstring = bstring.rstrip(b',')
                        if self.secureconn and not binary:
                            bstring = self.aes_cipher.decrypt(bstring)
                            if not bstring:
                                logger.warning('received message was not decrypted')
                                return {}
                        if not binary:  # For externally encrypted data
                            head = bstring[0]
                            if (head >= 128 and head <= 143) or head == 222:  # Check for packed dict
                                try:
                                    return msgpack.loads(bstring)
                                except Exception as e:
                                    logger.error('error unpacking received data: ' + str(e))
                                    logger.debug('data:\n' + str(bstring))
                        return bstring
                    else:
                        logger.warning('invalid string-end character: ' + '\n' + str(bstring))
                else:
                    logger.warning('insufficient data in rx buffer')
        else:
            logger.warning('invalid byte-string formatting: ' + '\n' + str(bstring))
        return {}

    def setupSymmCipher(self, smk, iv):  # This method only used during registration
        # setting up AES cipher with CBC mode by default
        self.aes_cipher = AES_cipher(smk, iv=iv)
        self.secureconn = True

    def verifyResponseMessageIntegrity(self, data):
        if 'response' not in data:
            logger.error('invalid response from the {} server {}'.format(self.remotetype, self.srvrid))
            self.closeAndExit(1)

    def close(self):
        if self.mysocket.fileno() != -1:
            self.mysocket.close()

    def closeAndExit(self, status):
        if self.mysocket.fileno() != -1:
            self.mysocket.close()
        sys.exit(status)
