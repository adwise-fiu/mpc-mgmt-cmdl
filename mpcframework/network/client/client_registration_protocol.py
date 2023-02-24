import logging
import types
from pyDH import DiffieHellman
from hashlib import sha256
import scrypt

from ..network_protocol_base import NetworkProtocolBase
from mpcframework.storage import sqlitedb as db
from mpcframework.crypto.symmetric_key_cryptography import AES_cipher

logger = logging.getLogger('ClientRegistrationProtocol')


class ClientRegistrationProtocol(NetworkProtocolBase):

    appid = 'GASTURBINE'

    authcode = 'VFX34ML0RIBM48QS'
    nameprefix = 'Liberty'
    iotype = 'input'
    pwd = 'Lorem ipsum dolor sit'

    def __init__(self):
        super().__init__()
        self.nodeinfo = types.SimpleNamespace(
            name=None,
            attrs={
                'location': 'miami',
            },
            symm_k=None,
            nonce=None,
            hash_N=0,
        )
        self.remoteserver = types.SimpleNamespace(
            port = None,
        )
        logger.debug('registration protocol initialized')


    def execute(self):
        self.establishConnection()
        self.runDHkeyExchange()
        identity = self.runAuthorizationExchange()
        self.close()
        return identity


    def runDHkeyExchange(self):
        logger.debug('sending registration request')
        request = {
            'm-type': 'register',
            'role': 'CLIENT',
            'iotype': self.iotype,
            'appid': self.appid,
        }
        self.sendData(request)

        # send this client's information after prompt by the coordination server
        response = self.receiveData()
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

        server_pk = int.from_bytes(response['pk'], byteorder='big')
        logger.debug('DiffieHellman: received server\'s public key')
        dhkeygen = DiffieHellman()
        dh_pk = dhkeygen.gen_public_key()
        message = {
            'm-type': 'dhexchange',
            'pk': dh_pk.to_bytes(256, byteorder='big'),
        }
        self.sendData(message)
        logger.debug('DiffieHellman: sent this node\'s public key')

        dh_shk = bytes.fromhex(dhkeygen.gen_shared_key(server_pk))
        # generating a nonce value from the shared key
        nonce_gen = sha256(dh_shk)
        self.nodeinfo.nonce = nonce_gen.digest()

        # confirmation of successful DH key exchange
        response = self.receiveData()
        self.verifyResponseMessageIntegrity(response)
        if response['response'] != 'complete':
            logger.warning('incomplete DH key exchange. Reason: '
                          + str(response.get('reason', None))
            )
            self.closeAndExit(1)
        self.setupSymmCipher(dh_shk, iv=self.nodeinfo.nonce[:16])
        logger.info('generated DH shared key with coordination server')


    def runAuthorizationExchange(self):
        message = {
            'm-type': 'authorize',
            'authcode': self.authcode,
            'name-prefix': self.nameprefix,
            'pwd': self.pwd,
            'attributes': self.nodeinfo.attrs,
        }
        logger.debug('initiating authorization exchange')
        self.sendData(message)

        response = self.receiveData()
        self.verifyResponseMessageIntegrity(response)
        status = response['response']
        if status == 'ok':
            NotImplemented  # TODO: test for password not provided in the previous stage
        elif status != 'complete':
            logger.warning('incomplete registration request. Reason: '
                            + str(response.get('reason', None)))
            logger.debug('response: ' + str(response))
            self.closeAndExit(1)

        self.nodeinfo.name = response['clientname']
        self.nodeinfo.hash_N = response['N']
        self.nodeinfo.symm_k = scrypt.hash(
            self.pwd, self.nodeinfo.nonce, self.nodeinfo.hash_N, r=8, p=1, buflen=32
        )
        self.remoteserver.port = response['auth_port']
        logger.info('registered successfully as \'{}\''.format(self.nodeinfo.name))
        record = {  # TODO: find a better way to do this
            'nodename': self.nodeinfo.name,
            'datasource': self.iotype in ['input', 'in/output'],
            'dataconsumer': self.iotype in ['output', 'in/output'],
            'attributes': self.nodeinfo.attrs,
            'symm_k': self.nodeinfo.symm_k,
            'nonce': self.nodeinfo.nonce,
            'hash_N': self.nodeinfo.hash_N,
            'server_port': self.remoteserver.port,
        }
        folder = record['nodename'][-3:]
        db.save_identity('CLIENT', folder, record)
        return record


if __name__ == "__main__":
    logger.info('performing client registration...')
    regp = ClientRegistrationProtocol()
    regp.execute()
