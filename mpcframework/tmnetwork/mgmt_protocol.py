import logging
import msgpack
import time

from twisted.internet import protocol, reactor, endpoints
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from .auth_protocol import AuthenticationProtocol
from ..storage import sqliteutils as sqt

logger = logging.getLogger('ManagementProtocol')
AUTH_PORT = 1251
MPCS_MPC_PORT = 1250


class ManagementProtocol(AuthenticationProtocol):

    def __init__(self, factory, **kwargs):
        self.factory = factory
        super().__init__(**kwargs)
        self.currentJobId = ''  # assumes the consumer client can request one job at a time


    def messageReceived(self, msg):
        mtype = msg.pop('m-type', '')
        if mtype == 'runmpc':
            self.factory.job_count += 1  # TODO: Preliminary
            msg['job-id'] = self.currentJobId = 'J{:03}'.format(self.factory.job_count)
            t1 =time.time()
            print('start: {}'.format(t1))
            logger.info('new MPC job ({}) request from {}'.format(msg['job-id'], self.remotenode.name))
            requirements = msg.pop('required', {})
            self.factory.current_jobs[self.currentJobId] = {
                'requester': {
                    'name': self.remotenode.name,
                    'conn': self,
                },
                'requirements': requirements,
            }
            if 'fixp' in requirements:
                msg['fixp'] = requirements['fixp']
            self.inquiryDataSources(msg)
        elif mtype == 'ackmpc':
            self.processMpcAckResponse(msg)
        elif mtype == 'reportdsize':
            self.collectDataSize(msg)
        elif mtype == 'requestack':
            self.collectMpcRequestAck(msg)
        elif mtype == 'alive':
            self.updateLivenessState(msg)
        elif mtype == 'status':
            self.updateParticipantStatus(msg)
        return {}


    def inquiryDataSources(self, msg):
        current_job = self.factory.current_jobs[self.currentJobId]
        current_job['sources'] = jdatasources = list()
        source_clients = sqt.getRecordsFromTable(self.factory.rodb, 'clients', ['nodename'], ('input', 1))
        source_clients = [record['nodename'] for record in source_clients]
        # print(source_clients)
        msg['m-type'] = 'datarequest'
        for name, conn in self.factory.connections['clients'].items():
            if name in source_clients:
                logger.debug('requesting input data size from {}'.format(name))
                jdatasources.append(name)
                conn.sendData(msg)
        current_job['nsources'] = len(jdatasources)
        current_job['source_params'] = dict()


    def checkOnMpcs(self, metadata):
        current_job = self.factory.current_jobs[metadata.get('job-id', '')]
        current_job['mpcs'] = mpcs = list()
        current_job['mpcs_ntwk'] = dict()
        for name, conn in self.factory.connections['mpcs'].items():
            logger.debug('requesting availability from {}'.format(name))
            msg = {'m-type': 'mpcrequest'}
            msg.update(metadata)
            mpcs.append(name)
            conn.sendData(msg)


    def collectDataSize(self, msg):
        logger.debug('received metadata from {}'.format(self.remotenode.name))
        if jobId := msg.pop('job-id', ''):
            current_job = self.factory.current_jobs[jobId]
            if self.remotenode.name in current_job['sources']:
                current_job['source_params'][self.remotenode.name] = msg
                source_clt_replies = len(current_job['source_params'])
                if source_clt_replies == current_job['nsources']:
                    logger.info('all data sources\' responses received for job: {}'.format(jobId))
                    # print('All input client responses received:', current_job['source_params'])
                    self.checkOnMpcs({'job-id': jobId})
            else:
                logger.warning('received response from \'{}\' which is not a data source for job: {}'.
                                format(self.remotenode.name, jobId)
                )
        else:
            logger.warning('message from client \'{}\' with no job id'.format(self.remotenode.name))


    def collectMpcRequestAck(self, msg):
        logger.debug('received response to MPC request from {}'.format(self.remotenode.name))
        if jobId := msg.pop('job-id', ''):
            current_job = self.factory.current_jobs[jobId]
            if self.remotenode.name in current_job['mpcs']:
                available = msg.pop('available', False)
                if available:
                    current_job['mpcs_ntwk'][self.remotenode.name] = msg
                else:
                    current_job['mpcs'].remove(self.remotenode.name)
                mpcs_accepted = len(current_job['mpcs_ntwk'])
                if mpcs_accepted == len(current_job['mpcs']):
                    logger.info('all MPC servers\' responses received for job: {}'.format(jobId))
                    # print('All MPC server responses received:', current_job['mpcs_ntwk'])
                    any_client = current_job['sources'][0]
                    offeredsetup = {
                        'nservers': mpcs_accepted,
                        'locations': [],
                        'fixp': current_job['source_params'][any_client]['params']['fixp']
                    }
                    if not mpcs_accepted:
                        logger.warning('No MPC servers available to execute job: {}'.format(jobId))
                    self.sendMpcJobSetup(jobId, offeredsetup)
            else:
                logger.warning('received response from \'{}\' which was not required for job: {}'
                                .format(self.remotenode.name, jobId)
                )
        else:
            logger.warning('message from MPC server \'{}\' with no job id'.format(self.remotenode.name))


    def sendMpcJobSetup(self, jobId, setup_info):
        requester = self.factory.current_jobs[jobId]['requester']
        requirements = self.factory.current_jobs[jobId]['requirements']
        offer = {
            'm-type': 'mpcsetup',
            'job-id': jobId,
            'setup': setup_info,
        }
        requester['conn'].sendData(offer)
        logger.info('sent offered MPC configuration to {} (job: {})'.format(requester['name'], jobId))


    def processMpcAckResponse(self, msg):
        logger.debug('received MPC configuration response from {}'.format(self.remotenode.name))
        if jobId := msg.pop('job-id', ''):
            current_job = self.factory.current_jobs[jobId]
            if current_job['requester']['name'] != self.remotenode.name:
                logger.warning('{} is NOT the requester of MPC job: {}!!!'
                               .format(self.remotenode.name, jobId)
                )
                return
            if msg.get('execution', '') == 'proceed':
                logger.info('MPC job ({}) configuration accepted!'.format(jobId))
                current_job['pending_mpcs'] = list(current_job['mpcs'])
                current_job['pending_client'] = list(current_job['sources'])
                self._retrieveMpcsAuthInfo(jobId)
                self.distributeMpcPublicIds(jobId)
                self.distributeCredentials(jobId)
            else:
                logger.warning('MPC job ({}) execution not approved!'.format(jobId))
        else:
            logger.warning('message from MPC server \'{}\' with no job id'.format(self.remotenode.name))


    def _retrieveMpcsAuthInfo(self, jobId):
        current_job = self.factory.current_jobs[jobId]
        current_job['mpcs_auth'] = mpcs_auth = dict()
        columns = ['sig_vk', 'symm_k', 'nonce', 'enc_pk']
        for _id, name in enumerate(current_job['mpcs']):
            mpcs_auth[name] = {
                'id': _id + 1,
                'ip-address': self.factory.connections['mpcs'][name].remotenode.ip,
            }
            filter = ('nodename', name)
            mpcs_record = sqt.getSingleRecordFromTable(self.factory.rodb, 'mpcs', columns, filter)
            for k, v in mpcs_record.items():
                mpcs_record[k] = bytes.fromhex(v)
            mpcs_auth[name].update(mpcs_record)


    def distributeMpcPublicIds(self, jobId):
        current_job = self.factory.current_jobs[jobId]
        leadmsg = {
            'm-type': 'identities',
            'job-id': jobId,
            'n-peers': len(current_job['mpcs']) - 1,
        }
        logger.info('distributing identities among {} MPC servers associated to job {}...'
                    .format(leadmsg['n-peers']+1, jobId)
        )
        # inform each MPC server about the number of peers whose identities they'll receive
        for srvrname, srecord in (current_job['mpcs_auth']).items():
            mpcs_conn = self.factory.connections['mpcs'][srvrname]
            leadmsg['id'] = srecord['id']
            mpcs_conn.sendData(leadmsg)
        # distribute the identities
        for srvrname, srecord in (current_job['mpcs_auth']).items():
            for destname in current_job['mpcs']:
                destconn = self.factory.connections['mpcs'][destname]
                if destname != srvrname:
                    mpcs_info = {
                        'id': srecord['id'],
                        'ip-address': srecord['ip-address'],
                        'port': MPCS_MPC_PORT + srecord['id'],
                        'vfk': srecord['sig_vk'],
                    }
                    destconn.sendData(mpcs_info)


    def distributeCredentials(self, jobId):
        current_job = self.factory.current_jobs[jobId]
        random_generator = Random.new().read
        leadmsg = {
            'm-type': 'credentials',
            'job-id': jobId,
            'n-mpcs': len(current_job['mpcs']),
        }
        logger.info('distributing credentials for {} MPC servers associated to job {}...'
                    .format(leadmsg['n-mpcs'], jobId)
        )
        for srvrname, srecord in (current_job['mpcs_auth']).items():
            symm_k = srecord['symm_k']
            iv = srecord['nonce']
            server_nw_info = {
                'job-id': jobId,  # TODO: Is this needed for every server record?
                'server-id': srecord['id'],
                'ip-address': srecord['ip-address'],
                'port': current_job['mpcs_ntwk'][srvrname]['in-port'],
            }
            for name, conn in self.factory.connections['clients'].items():
                if name in current_job['sources']:
                    self._sendCredentialsToParticipant(
                        conn, leadmsg, server_nw_info, random_generator, symm_k, iv
                    )
                    logger.debug('sent credentials for {} to {}'.format(srvrname, name))


    def _sendCredentialsToParticipant(self, conn, leadmsg, srvr_info, generator, srvr_symm_k, srvr_nonce):
        if srvr_info['server-id'] == 1:  # the target node is alerted that credentials are coming
            conn.sendData(leadmsg)
        session_k = generator(32)
        session_iv = generator(16)
        session_details = {
            'ssk': session_k,
            'nonce': session_iv,
        }
        session_details.update(srvr_info)
        conn.sendData(session_details)
        ticket = {
            'nodename': conn.remotenode.name,
            'role': conn.remotenode.role,
            'ssk': session_k,
            'nonce': session_iv,
        }
        cipher = AES.new(srvr_symm_k, AES.MODE_CBC, srvr_nonce)
        ssticket = cipher.encrypt(pad(msgpack.dumps(ticket), AES.block_size))
        conn.sendData(ssticket, bypass=True)  # we do not want to double encrypt


    def updateParticipantStatus(self, msg):
        logger.debug('received status message from {}'.format(self.remotenode.name))
        if jobId := msg.pop('job-id', ''):
            if msg.get('status', '') == 'setup-ready':
                current_job = self.factory.current_jobs[jobId]
                key = 'pending_' + self.remotenode.role.lower()  # TODO add the s as in clients?
                current_job[key].remove(self.remotenode.name)
                logger.info('{} \'{}\' is ready to start MPC job {}'
                            .format(self.remotenode.role, self.remotenode.name, jobId)
                )
                if not len(current_job['pending_client']):
                    t2 = time.time()
                    print('stop: {}'.format(t2))
                    logger.info('participants READY! Comanding to start MPC job {}'.format(jobId))
            else:
                logger.warning('{} \'{}\' could not complete setup for MPC job {}'
                                .format(self.remotenode.role, self.remotenode.name, jobId)
                )
        else:
            logger.warning('message from \'{}\' with no job id'.format(self.remotenode.name))


    def updateLivenessState(self, metadata):
        logger.debug('received \'alive\' message from {}'.format(self.remotenode.name))
        jobId = metadata.get('job-id', '')
        server_group = self.remotenode.role.lower()
        server_group += '' if server_group.endswith('s') else 's'


class ManagementProtocolFactory(protocol.ServerFactory):

    def __init__(self, dbcon, **kwargs):
        self.node_list = kwargs['nodeList']
        self.initializeNodesStatus()
        self.rodb = dbcon
        self.connections = {
            'clients': {},
            'mpcs': {},
        }
        self.job_count = 0
        self.current_jobs = {}

    def buildProtocol(self, addr):
        p = ManagementProtocol(self)
        return p

    def initializeNodesStatus(self):
        # TODO: revise how new registered nodes are included in this status
        client_names = self.node_list['clients']
        nclients = len(client_names)
        mpcs_names = self.node_list['mpcs']
        nmpcs = len(mpcs_names)
        self.client_status = dict(zip(client_names, [{'online': False} for _ in range(nclients)]))
        self.mpcs_status = dict(zip(mpcs_names, [{'online': False} for _ in range(nmpcs)]))


class CoordinationServer:

    def __init__(self, dbcon, **kwargs):
        self.dbcon = dbcon
        self.kwargs = kwargs
        # self.nodeList = kwargs.pop('nodeList', {})

    def start(self):
        self.endpoint = endpoints.TCP4ServerEndpoint(reactor, AUTH_PORT)
        factory = ManagementProtocolFactory(self.dbcon, **self.kwargs)
        self.endpoint.listen(factory)
        logger.info('coordination server started')
