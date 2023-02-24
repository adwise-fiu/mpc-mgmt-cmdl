import logging

from .network_protocol_base import NetworkProtocolBase

logger = logging.getLogger('SecureSessionChannel')


class SecureSessionChannel(NetworkProtocolBase):
    def __init__(self, **kwargs):
        super().__init__()
        self.srvrid = kwargs.get('server-id', 0)
        self.serveraddr = (kwargs['ip-address'], kwargs['port'])
        self.symm_k = kwargs['ssk']
        self.nonce = kwargs['nonce']
        self.ssticket = kwargs['ssticket']
        self.remotetype = 'MPC'

    def initiateAuthentication(self, nodename):
        self.sendData(self.ssticket)
        self.setupSymmCipher(self.symm_k, self.nonce)
        authenticator = {
            'nodename': nodename,
        }
        self.sendData(authenticator)
