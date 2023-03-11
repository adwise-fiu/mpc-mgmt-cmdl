import logging

from .client_authentication_protocol import ClientAuthenticationProtocol
from ..pmp_network import PmpNetwork

logger = logging.getLogger('MPCRequestProtocol')


class MPCRequestProtocol(ClientAuthenticationProtocol):

    fp = 10

    def __init__(self, *args):
        super().__init__(*args)
        self.jobs = dict()

    def authenticate(self):
        return self.execute()

    def requestMpcJob(self, requirements):
        # TODO: check requirements for validity
        msg = {
            'm-type': 'runmpc',
            'required': {
                'fixp': self.fp,
            }
        }
        msg['required'].update(requirements)
        self.sendData(msg)
        response = self.receiveData()
        if response.pop('m-type', '') == 'mpcsetup':
            jobId = response.get('job-id', '')
            logger.info('received MPC job configuration from the coordinator server (job: {})'
                        .format(jobId)
            )
            accepted = True
            if requirements.get('nservers', object()) != response['setup'].get('nservers', object()):
                # logger.debug('MPC servers: {}'.format(response['setup'].get('nservers', None)))
                accepted = False
            if requirements.get('fixp', self.fp) != response['setup'].get('fixp', 0):
                # logger.debug('fixp: {}'.format(response['setup'].get('fixp', None)))
                accepted = False
            msg = {
                'm-type': 'ackmpc',
                'job-id': jobId,
            }
            if accepted:
                logger.info('MPC service configuration accepted\n')
                msg['execution'] = 'proceed'
            else:
                logger.warning('MPC service offered does not meet the requirements\n')
                msg['execution'] = 'abort'
            self.sendData(msg)
        else:
            logger.warning('unkown message type from the coordination server\n')

    def listenToServer(self):
        logger.info('listening to the coordination server...')
        while True:
            msg = self.receiveData()
            descriptor = msg.pop('m-type', '')
            if descriptor == 'datarequest':
                logger.info('received metadata request from the coordination server (job: {})'
                            .format(msg.get('job-id', ''))
                )
                if 'fixp' in msg and type(msg['fixp']) == int:
                    self.fp = max(min(msg['fixp'], 32), 4)
                response = {
                    'm-type': 'reportdsize',  # metadata?
                    'job-id': msg.get('job-id', ''),
                    'dsize': (10, 1),
                    'params': {
                        'fixp': self.fp,
                    }
                }
                self.sendData(response)
                logger.info('metadata sent')

            elif descriptor == 'credentials':
                jobId = msg.get('job-id', '')
                if jobId:
                    try:
                        current_job = self.jobs[jobId] = {
                            'n-mpcs': msg['n-mpcs'],
                        }
                    except KeyError as e:
                        logger.error('while receiving mpcs credentials, missing parameter: {}'.format(e))

                    logger.info('receiving credentials for {} MPC servers associated to job {}...'
                                .format(current_job['n-mpcs'], jobId)
                    )
                else:
                    logger.warning('missing job id in \'credentials\' message')
                    continue
                mpcs_info = current_job['mpcs'] = dict()
                for server in range(current_job['n-mpcs']):
                    server_conn_info = self.receiveData()
                    if jobId != server_conn_info.pop('job-id'):
                        self.receiveData(binary=True)  # receives and discards the session ticket
                        continue
                    srvrid = server_conn_info.get('server-id')
                    mpcs_info[srvrid] = server_conn_info
                    ssticket = self.receiveData(binary=True)  # do not attempt to decrypt the ticket
                    mpcs_info[srvrid]['ssticket'] = ssticket
                    srvraddr = ':'.join([server_conn_info['ip-address'], str(server_conn_info['port'])])
                    logger.debug('received credentials to authenticate to MPC server {} ({})'
                                .format(srvrid, srvraddr)
                    )
                # print('all server\'s connection information received:\n{}'.format(current_job))
                outsourcingNetwork = PmpNetwork.setup(self.nodeinfo['nodename'], mpcs_info)
                response = {
                    'm-type': 'status',
                    'job-id': jobId,
                }
                if outsourcingNetwork.fullyconnected:
                    response['status'] = 'setup-ready'
                else:
                    response['status'] = 'setup-incomplete'
                self.sendData(response)

            elif msg == {}:
                logger.info('stopped listening to the coordination server\n')
                break
