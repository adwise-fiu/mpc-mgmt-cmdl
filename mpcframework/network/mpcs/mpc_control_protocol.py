import logging
from twisted.internet import reactor, threads

from .mpcs_authentication_protocol import MPCSAuthenticationProtocol
from .mpc_outsourcing_network import OutsourcingServer

logger = logging.getLogger('MPCControlProtocol')
BASE_IN_PORT = 1270  # used for input (source) clients' connections
BASE_OUT_PORT = 1260  # used for output (consumer) clients' connections


class MPCControlProtocol(MPCSAuthenticationProtocol):

    def __init__(self, *args):
        super().__init__(*args)
        self.identity = args[0]
        self.currentJobId = ''
        self.ioserver = None
        self.mpc_ntwk_set = dict()

    def authenticate(self):
        return self.execute()

    def listenToServer(self):
        logger.info('listening to the coordination server...')
        while True:
            msg =  self.receiveData()
            descriptor = msg.pop('m-type', '')
            if descriptor == 'hello':
                logger.debug('alive check')
                response = {'m-type': 'alive'}

            elif descriptor == 'mpcrequest':
                jobId = msg.pop('job-id', '')
                logger.info('MPC request ({})'.format(jobId))
                response = {
                    'm-type': 'requestack',
                    'job-id': jobId
                }
                if self.currentJobId:  # already reserved to perform an MPC job
                    response.update({
                        'available': False,
                    })
                else:
                    self.currentJobId = jobId
                    self.ioserver = OutsourcingServer(self.identity, BASE_IN_PORT, BASE_OUT_PORT)
                    self.ioserver.start()

                    response.update({
                        'available': True,
                    })
                    for _ in range(2):
                        response.update(self.ioserver.portnumber.get())
                logger.info('MPC request acknowledged')

            elif descriptor == 'identities':
                jobId = msg.get('job-id', '')
                if jobId == self.currentJobId:
                    logger.info('receiving MPC server identities for job {}'.format(jobId))
                    try:
                        self.mpc_ntwk_set['myId'] = msg['id']
                        self.mpc_ntwk_set['n-peers'] = npeers = msg['n-peers']
                    except KeyError as e:
                        logger.error('missing parameter: {}'.format(e))
                else:
                    logger.warning('missing job id in \'identities\' message')
                    continue
                peers = self.mpc_ntwk_set['peers'] = {}
                for _ in range(npeers):
                    peer_info = self.receiveData()
                    try:
                        _id = peer_info.pop('id')
                        peers[_id] = peer_info
                    except KeyError as e:
                        logger.error('missing key: {}'.format(e))
                print('all MPC peer\'s identities received')
                response = {}

            elif msg == {}:
                logger.info('stopped listening to the coordination server\n')
                break

            if response:
                self.sendData(response)
