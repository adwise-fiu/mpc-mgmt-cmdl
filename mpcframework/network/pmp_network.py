import logging
import types
import selectors

from .secure_session_channel import SecureSessionChannel

logger = logging.getLogger('PmpNetwork')


class PmpNetwork:
    def __init__(self, nodename):
        self.nodename = nodename
        self.nmpcs = 0
        self.connections = dict()
        self._sel = selectors.DefaultSelector()
        self.fullyconnected = False

    def establishSecureConnections(self, mpcs_conn_info):
        nconnections = 0
        for _id, conn_info in mpcs_conn_info.items():
            self.nmpcs += 1
            schan = SecureSessionChannel(**conn_info)
            if schan.establishConnection():
                continue  # could not establish network communication with this server
            nconnections += 1
            schan.initiateAuthentication(self.nodename)
            data = types.SimpleNamespace(id=_id, channel=schan)
            self._sel.register(schan.mysocket, selectors.EVENT_READ, data=data)

        registeredIds = list()
        while len(self.connections) < nconnections:
            events = self._sel.select(timeout=None)
            for key, mask in events:
                data = key.data
                if data.id not in registeredIds:
                    msg = data.channel.receiveData()
                    if msg.get('result', '') == 'ok':
                        self.connections[data.id] = data.channel
                        registeredIds.append(data.id)
                        logger.debug('established secure communication with MPC server {}'.format(data.id))
                    else:
                        nconnections -= 1

        if nconnections < self.nmpcs:
            logger.warning('could not establish secure communication with all MPC servers')
            return 1
        logger.info('established secure communication with all MPC servers')
        self.fullyconnected = True
        return 0

    @classmethod
    def setup(cls, nodename, mpcs_conn_info):
        netobj = cls(nodename)
        netobj.establishSecureConnections(mpcs_conn_info)
        return netobj
