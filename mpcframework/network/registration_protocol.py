import logging
import types
from types import SimpleNamespace
from Crypto import Random
import ed25519

from .network_protocol_base import NetworkProtocolBase
from ..crypto.public_key_cryptography import RSA_cipher
from ..storage import sqlitedb as db

logger = logging.getLogger('ServerRegistrationProtocol')


class RegistrationProtocol(NetworkProtocolBase):

    def __init__(self):
        super().__init__()
        self.remotetype = 'coordination'
        random_generator = Random.new().read
        self.nodeinfo = SimpleNamespace(
            name=None,
            attrs={},
            symm_k=None,
            nonce=None,
            sig_k=None,
            ver_k=None,
            rsa_sk=None,
        )
        self.remoteserver = types.SimpleNamespace(
            port = None,
        )
        self.nodeinfo.sig_k, self.nodeinfo.ver_k = ed25519.create_keypair(entropy=random_generator)
        self.rsa_cipher = RSA_cipher()


    def execute(self):
        self.establishConnection()
        return self.runRegistrationExchange()


    def runRegistrationExchange(self):
        logger.debug('sending registration request including my public key')
        # Generate a public/private key pair
        self.nodeinfo.rsa_sk = self.rsa_cipher.getPrivateKeyBytes()
        request = {
            'm-type': 'register',
            'role': self.nodeinfo.role,
            'enc-pk': self.rsa_cipher.getPublicKeyBytes(),
        }
        self.sendData(request)

        # send this server's information after prompt by the coordination server
        bytestring = self.receiveData(binary=True)
        response = self.rsa_cipher.decrypt(bytestring)
        self.verifyResponseMessageIntegrity(response)
        status = response['response']
        if status == 'reject':
            logger.warning('server rejected registration request. Reason: '
                            + str(response.get('reason', None)))
            self.closeAndExit(1)
        elif status != 'accept':
            logger.warning('received unknown response from the server')
            logger.debug('response: ' + str(response))
            self.closeAndExit(1)

        self.nodeinfo.name = response['servername']
        self.nodeinfo.symm_k = response['smk']
        self.nodeinfo.nonce = response['nonce']
        self.remoteserver.port = response['auth_port']
        self.setupSymmCipher(self.nodeinfo.symm_k, iv=self.nodeinfo.nonce[:16])
        logger.info('established secure communication with the coordination server')
        requiredattrs = response['attributes']
        missing = set(requiredattrs.keys()) - set(self.nodeinfo.attrs.keys())
        if missing:
            logger.debug('attribute(s) requested not available. Continuing registration anyway')
        logger.debug('sending node attributes and signature verification key')
        message = {
            'm-type': 'attrexchange',
            'attributes': self.nodeinfo.attrs,
            'sig-vk': self.nodeinfo.ver_k.to_bytes(),
        }
        self.sendData(message)

        response = self.receiveData()
        self.verifyResponseMessageIntegrity(response)

        if response['response'] != 'complete':
            logger.warning('incomplete registration request. Reason: '
                            + str(response.get('reason', None)))
            logger.debug('response: ' + str(response))
            self.closeAndExit(1)
        logger.info('registered successfully as \'{}\''.format(self.nodeinfo.name))
        record = {  # TODO: find a better way to do this
            'nodename': self.nodeinfo.name,
            'attributes': self.nodeinfo.attrs,
            'symm_k': self.nodeinfo.symm_k,
            'nonce': self.nodeinfo.nonce,
            'sig_sk': self.nodeinfo.sig_k.to_bytes(),
            'sig_vk': self.nodeinfo.ver_k.to_bytes(),
            'enc_sk': self.nodeinfo.rsa_sk,
            'server_port': self.remoteserver.port,
        }
        folder = record['nodename'][-3:]
        db.save_identity(self.nodeinfo.role, folder, record)
        return record


if __name__ == "__main__":
    logger.info('performing MPC server registration...')
    regp = MPCSRegistrationProtocol()
    regp.execute()
