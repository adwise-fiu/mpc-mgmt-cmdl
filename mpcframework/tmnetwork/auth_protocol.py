import logging
import types
from random import randrange
import msgpack
import cerberus

from twisted.internet import protocol, reactor, endpoints
from twisted.protocols import basic

from ..storage import sqliteutils as sqt
from ..crypto.symmetric_key_cryptography import AES_cipher

logger = logging.getLogger('AuthenticationProtocol')


class AuthenticationProtocol(basic.NetstringReceiver):

    MAX_LENGTH = 16384
    enforceIP = False

    def __init__(self, **kwargs):
        super().__init__()
        self.secureconn = False
        self.authenticated = False
        self.remotenode = types.SimpleNamespace(
            ip = '',
            name = '',
            role = '',
        )
        self.aes_cipher = None
        self.auth_stage = 0
        self.proto_schema = AUTH_SCHEMA
        self.validated = cerberus.Validator(self.proto_schema[0])
        self.process_authentication_msg = self.receiveAuthenticationRequest

    def connectionMade(self):
        self.remotenode.ip = self.transport.client[0]
        self.remoteaddr = ':'.join([self.transport.client[0], str(self.transport.client[1])])
        logger.info('new connection from {}'.format(self.remoteaddr))

    def connectionLost(self, reason):
        logger.info('closed connection with remote ' + self.remoteaddr)
        logger.debug('Reason: {}'.format(reason.getErrorMessage()))
        self.updateNodeStatus('offline')
        # Remove this protocol instance from the collection
        group = self.remotenode.role.lower()
        group += '' if group.endswith('s') else 's'
        self.factory.connections[group].pop(self.remotenode.name)


    def stringReceived(self, bstring):
        if self.secureconn:
            bstring = self.aes_cipher.decrypt(bstring)
        try:
            msg = msgpack.loads(bstring)
        except Exception as e:
            logger.error('error unpacking data received from: {}\n{}'.format(self.remoteaddr, e))
            logger.debug('data: {}'.format(bstring))
            return

        if self.authenticated:
            response = self.messageReceived(msg)  # Processed by the management protocol
        else:
            response = self.process_authentication_msg(msg)

        if response and type(response) == dict:
            logger.debug('sending response with status \'{}\' to \'{}\''
                         .format(response.get('response', None), self.remotenode.name)
            )
            self.sendData(response)


    def sendData(self, data, bypass=False):
        if type(data) == dict:
            data = msgpack.dumps(data)
        if self.secureconn and not bypass:
            data = self.aes_cipher.encrypt(data)
        self.sendString(data)


    def receiveAuthenticationRequest(self, msg):
        if not self.validated(msg):
            self.printSchemaValidationError()
            return

        if self.auth_stage == 0:
            self.remotenode.name = msg.get('nodename', '')
            self.remotenode.role = msg.get('role', '')
            logger.info('authentication request from {} {} ({})'.format(
                self.remotenode.role, self.remoteaddr, self.remotenode.name)
            )
            if self.remotenode.role in ['CLIENT', 'MPCS']:
                table_name = self.remotenode.role.lower()
                table_name += '' if table_name.endswith('s') else 's'
            else:
                logger.warning('unknown remote node role')
                return

            if self.remotenode.name and self.remotenode.name in self.factory.node_list[table_name]:
                query_filter = ('nodename', self.remotenode.name)
            elif self.enforceIP:
                query_filter = ('ip_address', self.remotenode.ip)
            else:
                logger.warning('authentication rejected: unkown remote hostname')
                return {'response': 'reject', 'reason': 'unknown hostname'}

            self.remotenode_id = sqt.getSingleRecordFromTable(
                self.factory.rodb, table_name, columns = [], filter=query_filter
            )
            if not self.remotenode_id:
                logger.error('could not retrieve remote host information')
                response = {'response': 'reject', 'reason': 'unknown host'}
            else:
                if not self.remotenode.name:
                    self.remotenode.name = self.remotenode_id['nodename']
                if self.enforceIP and self.remotenode_id['ip_address'] != self.remotenode.ip:
                    logger.warning('authentication rejected: unknown remote host IP')
                    response = {'response': 'reject', 'reason': 'IP address mismatch'}
                else:
                    self.aes_cipher = AES_cipher(
                        bytes.fromhex(self.remotenode_id['symm_k']),
                        iv=bytes.fromhex(self.remotenode_id['nonce'])[:16]
                    )
                    challenge = [randrange(1000), randrange(1000)]
                    self.remotenode.challenge = sum(challenge)
                    self.sendData({'response': 'accept'})
                    self.secureconn = True
                    response = {'response': 'accept', 'challenge': challenge}
                    self.updateNextStage()
                    logger.debug('sending challenge to {} ({})'.format(
                        self.remoteaddr, self.remotenode.name)
                    )
            return response

        elif self.auth_stage == 1:
            logger.debug('verifying challenge response')
            if msg['ch-response'] != self.remotenode.challenge:
                logger.warning('authentication failed: incorrect response to challenge')
                response = {'response': 'fail', 'reason': 'challenge-response failed'}
            else:
                self.updateNodeStatus()
                logger.info('{} {} ({}) authenticated!'.format(
                    self.remotenode.role, self.remoteaddr, self.remotenode.name)
                )
                self.authenticated = True
                response = {'response': 'complete'}
            return response


    def updateNodeStatus(self, status='online'):
        if self.remotenode.role == 'CLIENT':
            group = 'clients'
            if self.remotenode.name not in self.factory.client_status:
                self.factory.client_status[self.remotenode.name] = dict()
            self.factory.client_status[self.remotenode.name]['online'] = (status == 'online')
        elif self.remotenode.role == 'MPCS':
            group = 'mpcs'
            if self.remotenode.name not in self.factory.mpcs_status:
                self.factory.mpcs_status[self.remotenode.name] = dict()
            self.factory.mpcs_status[self.remotenode.name]['online'] = (status == 'online')
        self.factory.connections[group][self.remotenode.name] = self


    def updateNextStage(self):
        self.auth_stage += 1
        self.validated.schema = self.proto_schema[self.auth_stage]

    def printSchemaValidationError(self):
        logger.warning('invalid/incomplete request from ' + self.remoteaddr)
        logger.debug(self.validated.schema)


AUTH_SCHEMA = [
    {
        'm-type': {
            'type': 'string',
            'allowed': ['authenticate'],
            'required': True,
        },
        'nodename': {
            'type': 'string',
            'maxlength': 20,
        },
        'role': {
            'type': 'string',
            'allowed': ['MPCS', 'CLIENT'],
            'required': True,
        },
    },
    {
        'm-type': {
            'type': 'string',
            'allowed': ['authexchange'],
            'required': True,
        },
        'ch-response': {
            'type': 'integer',
            'required': True,
        },
    },
]
