import logging
import types
import msgpack
import cerberus
import scrypt

from pyDH import DiffieHellman
from Crypto import Random
from hashlib import sha256
from twisted.internet import protocol, reactor, endpoints
from twisted.protocols import basic

from ..crypto.symmetric_key_cryptography import AES_cipher
from ..crypto.public_key_cryptography import RSA_cipher
from ..storage import sqliteutils as sqt

logger = logging.getLogger('RegistrationProtocol')
REG_PORT = 1250


class RegistrationProtocol(basic.NetstringReceiver):

    MAX_LENGTH = 16384

    appid = 'GASTURBINE'
    authcode = 'VFX34ML0RIBM48QS'
    hash_N = 1024
    mpcsnameprefix = 'MPC_server_'
    auth_port = 1251
    clientattrs = {
        'location': '',
    }
    mpcsattrs = {
        'location': '',
        'cpus': 0,
        'ram': 0,
    }

    def __init__(self, factory, **kwargs):
        super().__init__(**kwargs)
        # TODO: convert these to a remote node struct
        self.factory = factory
        self.role = None
        self.remotenode = types.SimpleNamespace(
            name = '',
            ip = '',
            attrs = {},
            symm_k = b'',
            nonce = b'',
            numsuffix = 0,
        )

        self.aes_cipher = None
        self.dhkeyex = None
        self.rsa_cipher = None

        self.secureconn = False
        self.reg_stage = 0
        self.proto_schema = [INITIAL_SCHEMA]

        self.validated = cerberus.Validator(INITIAL_SCHEMA)
        self.process_registration_msg = self.receiveRegistrationRequest


    def connectionMade(self):
        self.remotenode.ip = self.transport.client[0]
        self.remoteaddr = ':'.join([self.transport.client[0], str(self.transport.client[1])])
        logger.info('new connection from {}'.format(self.remoteaddr))

    def connectionLost(self, reason):
        logger.info('closed connection with remote {}'.format(self.remoteaddr))
        logger.debug('Reason: {}'.format(reason.getErrorMessage()))

    def stringReceived(self, bstring):
        if self.secureconn:
            bstring = self.aes_cipher.decrypt(bstring)
        try:
            msg = msgpack.loads(bstring)
        except Exception as e:
            logger.error('error unpacking data received from: ' + self.remoteaddr + '\n' + str(e))
            logger.debug('data: ' + str(data))
            return
        response = self.process_registration_msg(msg)
        if response and type(response) == dict:
            logger.debug('sending response with status \'{}\' to \'{}\''
                         .format(response.get('response', None), self.remotenode.name)
            )
            self.sendData(response)


    def sendData(self, data):
        if type(data) == dict:
            data = msgpack.dumps(data)
        if self.secureconn:
            data = self.aes_cipher.encrypt(data)
        self.sendString(data)


    def receiveRegistrationRequest(self, msg):
        if not self.validated(msg):
            self.printSchemaValidationError()
            return
        logger.info('registration request from {} as {}'.format(self.remoteaddr, msg['role']))
        self.role = msg['role']

        if self.role == 'CLIENT':
            if 'iotype' in msg and 'appid' in msg:
                self.remotenode.datasource = msg['iotype'] in ['input', 'in/output']
                self.remotenode.dataconsumer = msg['iotype'] in ['output', 'in/output']
                if self.appid != msg['appid']:
                    logger.warning('invalid app Id \'' + msg[appid] + '\'')
                    response = {'response': 'reject', 'reason': 'invalid app Id'}
                    self.sendData(response)
                    return
            else:
                self.printSchemaValidationError()
                return
            logger.debug('initiating Diffie-Hellman key exchange')
            self.dhkeyex = DHKeyExchange(self)
            self.process_registration_msg = self.registerClient
            self.proto_schema.extend(CLIENT_REG_SCHEMA)
            self.updateNextStage()
            return self.registerClient(msg)

        elif self.role == 'MPCS':
            if 'enc-pk' in msg:
                self.rsa_cipher = RSA_cipher.fromPublicKeyBytes(msg['enc-pk'])
                printname = 'MPC'
                logger.debug('received this {} server\'s public key'.format(printname))
                self.remotenode.enc_pk = msg['enc-pk']
            else:
                self.printSchemaValidationError()
                return
            self.process_registration_msg = self.registerServer
            self.proto_schema.extend(MPCS_REG_SCHEMA)  ## TODO: check that it was not extended already
            self.updateNextStage()
            return self.registerServer(msg)


    def registerClient(self, msg):
        if not self.secureconn:
            self.dhkeyex.next_phase(msg)
            return {}

        if not self.validated(msg):
            self.printSchemaValidationError()
            return {}

        if self.reg_stage == 1:
            if msg['authcode'] != self.authcode:
                logger.warning('invalid authorization code \'{}\' received'.format(msg[authcode]))
                return {'response': 'fail', 'reason': 'invalid authorization code'}
            logger.debug('valid authorization code received')
            self.remotenode.numsuffix = self.factory.getClientSuffix()
            self.remotenode.name = msg['name-prefix'] + format(self.remotenode.numsuffix, '03d')
            self.remotenode.attrs = self.clientattrs
            self.remotenode.nonce = self.dhkeyex.nonce
            self.remotenode.hash_N = self.hash_N
            response = {
                'response': 'ok',
                'clientname': self.remotenode.name,
                'N': self.remotenode.hash_N,
                'auth_port': self.auth_port
            }
            self.requested = dict()
            if 'pwd' in msg:
                self.remotenode.symm_k = scrypt.hash(
                    msg['pwd'], self.remotenode.nonce, self.remotenode.hash_N, r=8, p=1, buflen=32
                )
                logger.debug('received password set by the remote client')
            else:
                self.requested['pwd'] = ''
                logger.debug('requesting password from the remote client')

            if 'attributes' in msg:
                logger.debug('verifying received attributes')
                missing_keys = set(self.remotenode.attrs.keys()) - set(msg['attributes'].keys())
                if missing_keys:
                    self.requested['attributes'] = {k: self.remotenode.attrs[k] for k in missing_keys}
                    logger.debug('requesting additional attributes from remote client')
                self.remotenode.attrs.update(msg['attributes'])
            else:
                self.requested['attributes'] = self.remotenode.attrs
                logger.debug('requesting attributes from remote client')
            if self.requested:
                response['requested'] = self.requested
                self.updateNextStage()
            else:
                response['response'] = 'complete'
                self.addNewClient(self.remotenode)
                logger.info('new client registered as \'' + self.remotenode.name + '\'')
                self.updateNextStage(restart=True)
            return response

        elif self.reg_stage == 2:
            if 'pwd' in self.requested and 'pwd' in msg['pwd']:
                self.remotenode.symm_k = scrypt.hash(
                    msg['pwd'], self.dhkeyex.nonce, self.remotenode.hash_N, r=8, p=1, buflen=32
                )
                self.requested.pop('pwd')
                logger.debug('password received')
            if self.requested.get('attributes', None) and msg.get('attributes', None):
                logger.debug('verifying received attributes')
                new_attributes = msg['attributes']
                for key in self.requested.attributes.keys():
                    if key in new_attributes:
                        self.remotenode.attrs['attributes'][key] = new_attributes[key]
                        self.requested['attributes'].pop(key)
                if not self.requested['attributes']:
                    self.requested.pop('attributes')
            response = dict()
            if self.requested:
                response['response'] = 'fail'
                response['reason'] = 'failed to provide all the information requested'
                logger.warning('registration failed because of missing information')
            else:
                response['response'] = 'complete'
                self.addNewClient(self.remotenode)
                logger.info('new client registered as \'' + self.remotenode.name + '\'')
            # TODO: Indeed the port should be closed and this instance deleted
            self.updateNextStage(restart=True)
            return response


    def registerServer(self, msg):
        if not self.secureconn:
            if self.role == 'MPCS':
                self.remotenode.numsuffix = self.factory.getMpcsSuffix()
                nameprefix = self.mpcsnameprefix
                self.remotenode.attrs = self.mpcsattrs
            self.remotenode.name = nameprefix + format(self.remotenode.numsuffix, '03d')
            random_generator = Random.new().read
            self.remotenode.symm_k = random_generator(32)
            self.remotenode.nonce = random_generator(16)
            self.aes_cipher = AES_cipher(self.remotenode.symm_k, iv=self.remotenode.nonce)
            response = {
                'response': 'accept',
                'servername': self.remotenode.name,
                'attributes': self.mpcsattrs,
                'smk': self.remotenode.symm_k,
                'nonce': self.remotenode.nonce,
                'auth_port': self.auth_port,
            }
            logger.debug('sending symmetric encryption key to this {}'.format(self.role))
            logger.debug('requestig attributes from this {}'.format(self.role))
            self.sendData(self.rsa_cipher.encrypt(response))
            self.secureconn = True
            logger.info('established secure communication with this {}'.format(self.role))
            return {}

        if not self.validated(msg):
            self.printSchemaValidationError()
            return {}

        if self.reg_stage == 1:
            self.remotenode.sig_vk = msg['sig-vk']
            logger.debug('received this {}\'s signature verification key'.format(self.role))
            response = dict()
            if 'attributes' in msg:
                logger.debug('verifying received attributes')
                missing_keys = set(self.remotenode.attrs.keys()) - set(msg['attributes'].keys())
                if missing_keys:
                    response['response'] = 'fail'
                    response['reason'] = 'failed to provide all the information requested'
                    logger.warning('registration failed because of missing information')
            self.remotenode.attrs.update(msg['attributes'])
            response['response'] = 'complete'
            self.addNewServer(self.role, self.remotenode)
            printname = 'MPC'
            logger.info('new {} server registered as \'{}\''.format(printname, self.remotenode.name))
            # TODO: Indeed the port should be closed and this instance deleted
            self.updateNextStage(restart=True)
            return response


    def addNewClient(self, nodeinfo):  #TODO: Pack all node attributes in a single object
        record = {
            'nodename': nodeinfo.name,
            'input': nodeinfo.datasource,
            'output': nodeinfo.dataconsumer,
            'ip_address': nodeinfo.ip,
            'attributes': nodeinfo.attrs,
            'symm_k': nodeinfo.symm_k,
            'nonce': nodeinfo.nonce,
            'hash_N': nodeinfo.hash_N,
            'n_suffix': nodeinfo.numsuffix,
        }
        sqt.addClientRecord(self.factory.dbcon, record)  # TODO: synchronize this?
        self.updateNodeList('CLIENT', nodeinfo.name)

    def addNewServer(self, srvrtype, nodeinfo):
        record = {
            'nodename': nodeinfo.name,
            'ip_address': nodeinfo.ip,
            'attributes': nodeinfo.attrs,
            'sig_vk': nodeinfo.sig_vk,
            'symm_k': nodeinfo.symm_k,
            'nonce': nodeinfo.nonce,
            'enc_pk': nodeinfo.enc_pk,
            'n_suffix': nodeinfo.numsuffix,
        }
        sqt.addServerRecord(self.factory.dbcon, srvrtype, record)  # TODO: synchronize this?
        self.updateNodeList(srvrtype, nodeinfo.name)

    def updateNodeList(self, role, nodename):
        group = role.lower()
        group += '' if group.endswith('s') else 's'
        self.factory.node_list[group].append(nodename)

    def updateNextStage(self, restart=False):
        if restart:
            self.reg_stage = 1
        else:
            self.reg_stage += 1
        self.validated.schema = self.proto_schema[self.reg_stage]

    def printSchemaValidationError(self):
        logger.warning('invalid/incomplete request from ' + self.remoteaddr)


class RegistrationProtocolFactory(protocol.ServerFactory):

    def __init__(self, dbcon, **kwargs):
        self.dbcon = dbcon
        self.node_list = kwargs['nodeList']
        node_count = sqt.getParticipantCount(dbcon)
        self.nclient = node_count.get('clients', 0)
        self.nmpcs = node_count.get('mpcs', 0)

    def buildProtocol(self, addr):
        p = RegistrationProtocol(self)
        return p

    def getClientSuffix(self):
        self.nclient += 1
        return self.nclient

    def getMpcsSuffix(self):
        self.nmpcs += 1
        return self.nmpcs


class RegistrationServer:

    def __init__(self, dbcon=None, **kwargs):
        # self.nodeCount = kwargs.pop('nodeCount', {})
        self.dbcon = dbcon
        self.kwargs = kwargs

    def start(self):
        self.endpoint = endpoints.TCP4ServerEndpoint(reactor, REG_PORT)
        factory = RegistrationProtocolFactory(self.dbcon, **self.kwargs)
        self.endpoint.listen(factory)
        logger.info('registration server started')


INITIAL_SCHEMA = {
    'm-type': {
        'type': 'string',
        'allowed': ['register'],
        'required': True,
    },
    'role': {
        'type': 'string',
        'allowed': ['MPCS', 'CLIENT'],
        'required': True,
    },
    'iotype': {
        'type': 'string',
        'allowed': ['input', 'output', 'in/output'],
    },
    'appid': {
        'type': 'string',
        'minlength': 3,
        'maxlength': 20,
    },
    'enc-pk': {
        'type': 'binary',
        'minlength': 162,  # RSA 1024
        'maxlength': 546,  # RSA 4096
    }
}

CLIENT_REG_SCHEMA = [
    {
        'm-type': {
            'type': 'string',
            'allowed': ['authorize'],
            'required': True,
        },
        'authcode': {
            'type': 'string',
            'minlength': 16,
            'maxlength': 16,
            'required': True,
        },
        'name-prefix': {
            'type': 'string',
            'minlength': 4,
            'maxlength': 12,
            'required': True,
        },
        'pwd': {
            'type': 'string',
            'minlength': 9,
            'maxlength': 24,
        },
        'attributes': {
            'type': 'dict',
            'allow_unknown': True,
        },
    },
    {
        'm-type': {
            'type': 'string',
            'allowed': ['authexchange'],
            'required': True,
        },
        'pwd': {
            'type': 'string',
            'minlength': 9,
            'maxlength': 24,
        },
        'attributes': {
            'type': 'dict',
            'allow_unknown': True,
        },
    },
    # This optional last communication stage is not implemented
    {
        'm-type': {
            'type': 'string',
            'allowed': ['keyconfirm'],
            'required': True,
        },
        'smk': {
            'type': 'binary',
            'minlength': 32,
            'maxlength': 64,
            'required': True,
        },
    },
]

MPCS_REG_SCHEMA = [
    {
        'm-type': {
            'type': 'string',
            'allowed': ['attrexchange'],
            'required': True,
        },
        'attributes': {
            'type': 'dict',
            'required': True,
            'allow_unknown': True,
        },
        'sig-vk': {
            'type': 'binary',
            'minlength': 32,
            'maxlength': 64,
            'required': True,
        },
    },
]


class DHKeyExchange:
    def __init__(self, protocol):
        self.proto = protocol
        self.peeraddr = self.proto.remoteaddr
        self.dhkeygen = DiffieHellman()
        self.validated = cerberus.Validator(DHExchangeSchema[0])
        self.next_phase = self.send_dh_pk


    def send_dh_pk(self, request):
        self.dhpk = self.dhkeygen.gen_public_key()
        response = {
            'response': 'accept',
            'pk': self.dhpk.to_bytes(256, byteorder='big'),
        }
        self.proto.sendData(response)
        logger.debug('DiffieHellman: sent public key for this session')
        self.next_phase = self.gen_dh_shk
        self.validated.schema = DHExchangeSchema[1]


    def gen_dh_shk(self, message):
        if self.validated(message):
            logger.debug('DiffieHellman: received remote public key')
            peer_pk = int.from_bytes(message['pk'], byteorder='big')
            sharedKey = self.dhkeygen.gen_shared_key(peer_pk)
            self.shk = bytes.fromhex(sharedKey)
            # We derive a nonce value using the shared key
            nonce = sha256(self.shk)
            self.nonce = nonce.digest()
            logger.info('generated DH shared key with ' + self.peeraddr)
            self.validated.schema = {}
            self.proto.aes_cipher = AES_cipher(self.shk, iv=self.nonce[:16])
            response = {
                'response': 'complete',
            }
            self.proto.sendData(response)
            self.proto.secureconn = True
        else:
            logger.info('invalid/incomplete DH exchange msg from ' + self.peeraddr)
            response = {
                'response': 'fail',
                'reason': 'invalid/incomplete data',
            }
            self.proto.sendData(response)


DHExchangeSchema = [
    {
        'm-type': {
            'type': 'string',
            'allowed': ['register'],
            'required': True,
        },
        'appid': {
            'type': 'string',
            'minlength': 3,
            'maxlength': 20,
        },
    },
    {
        'm-type': {
            'type': 'string',
            'allowed': ['dhexchange'],
            'required': True,
        },
        'pk': {
            'type': 'binary',
            'minlength': 256,
            'maxlength': 256,
            'required': True,
        },
    },
]
