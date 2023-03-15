import logging

from .network_protocol_base import NetworkProtocolBase
from ..crypto.symmetric_key_cryptography import AES_cipher

logger = logging.getLogger('AuthenticationProtocol')


class AuthenticationProtocol(NetworkProtocolBase):

    def __init__(self, identity):
        super().__init__()
        self.nodeinfo = identity
        self.remotetype = 'management'
        self.serveraddr = ('localhost', identity['server_port'])
        # self.serv_addr_str = ':'.join([self.serveraddr[0], str(self.serveraddr[1])])
        self.aes_cipher = AES_cipher(identity['symm_k'], iv=identity['nonce'][:16])
        logger.debug('authentication protocol initialized')


    def execute(self):
        self.establishConnection()
        return self.runAuthenticationExchange()


    def runAuthenticationExchange(self):
        message = {
            'm-type': 'authenticate',
            'nodename': self.nodeinfo['nodename'],
            'role': self.nodeinfo['role'],
        }
        logger.debug('initiating authentication exchange')
        self.sendData(message)

        response = self.receiveData()
        status = response['response']
        if status == 'reject':
            logger.warning('server rejected authentication request. Reason: '
                            + str(response.get('reason', None)))
            self.closeAndExit(1)
        elif status != 'accept':
            logger.warning('received unknown response from the server')
            logger.debug('response: {}'.format(response))
            self.closeAndExit(1)

        logger.debug('server accepted the authentication request')
        # initiate encrypted communication
        self.secureconn = True

        response = self.receiveData()
        challenge = response.get('challenge', [])
        message = {
            'm-type': 'authexchange',
            'ch-response': sum(challenge),
        }
        logger.debug('sent authentication challenge response')
        self.sendData(message)

        response = self.receiveData()
        status = response.get('response', '')
        if status == 'complete':
            logger.info('authentication to the management server complete!')
            return True
        else:
            logger.warning('authentication to the management server failed')
            return False
