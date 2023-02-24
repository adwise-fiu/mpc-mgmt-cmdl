import logging
import msgpack

from twisted.protocols import basic

from mpcframework.crypto.symmetric_key_cryptography import AES_cipher

logger = logging.getLogger('OutsourcingProtocolBase')
MAX_PKT_LENGTH = 2048


class OutsourcingProtocolBase(basic.NetstringReceiver):
    def __init__(self, **kwargs):
        super().__init__()
        self.factory = kwargs.pop('factory', None)
        self.srvr_identity = kwargs.pop('srvr_identity', {})
        self.secureconn = False
        self.authenticated = False
        self.aes_cipher = None
        self.remotename = ''
        if self.__class__.__name__ == 'InputProtocol':
            self.remoterole = 'CLIENT'
        elif self.__class__.__name__ == 'OutputProtocol':
            self.remoterole = 'VERIFIER'

    def connectionMade(self):
        self.remoteaddr = ':'.join([self.transport.client[0], str(self.transport.client[1])])
        logger.info('new connection from {}'.format(self.remoteaddr))

    def stringReceived(self, bstring):
        if self.authenticated:
            pass
        elif self.secureconn:
            if msg := self._decryptMessage(bstring):
                if self.remotename == msg['nodename']:
                    self.sendData({'result': 'ok'})
                    self.authenticated = True
                    logger.info('established secure communication channel with {}'.format(self.remotename))
        else:
            self._setupSecureChannel(bstring)  # the first message should be the service ticket

    def _decryptMessage(self, bstring):
        if not (bstring := self.aes_cipher.decrypt(bstring)):
            return b''
        return self._unpackMessage(bstring)

    def _unpackMessage(self, bstring):
        try:
            msg = msgpack.loads(bstring)
        except Exception as e:
            logger.error('error unpacking data received from: {}\n{}'.format(self.remoteaddr, e))
            logger.debug('data: {}'.format(bstring))
            return b''
        return msg

    def _setupSecureChannel(self, bstring):
        logger.debug('received service ticket from {}'.format(self.remoteaddr))
        cipher = AES_cipher(self.srvr_identity['symm_k'], iv=self.srvr_identity['nonce'])
        if not (payload := cipher.decrypt(bstring)):
            return
        # configure a secure communication channgel using the credentials in the ticket
        if not (ticket := self._unpackMessage(payload)):
            return
        if self.remoterole != ticket['role']:
            logger.warning('invalid node type for communicating using {}'.format(self.__class__.__name__))
            return
        self.remotename = ticket['nodename']
        logger.debug('opened session ticket from {}'.format(self.remotename))
        self.aes_cipher = AES_cipher(ticket['ssk'], iv=ticket['nonce'])
        self.secureconn = True

    def sendData(self, data):
        if type(data) == dict:
            data = msgpack.dumps(data)
        if self.secureconn:
            data = self.aes_cipher.encrypt(data)
        self.sendString(data)
