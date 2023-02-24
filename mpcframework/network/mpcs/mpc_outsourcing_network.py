import logging
import threading
import queue
import socket
from random import random
from time import sleep

from twisted.internet import protocol, endpoints, reactor, tcp
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.internet.error import CannotListenError

from ..outsourcing_protocol_base import OutsourcingProtocolBase

logger = logging.getLogger('OutsourcingServer')
ilogger = logging.getLogger('InputProtocol')
ologger = logging.getLogger('OutputProtocol')


class InputProtocol(OutsourcingProtocolBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class OutputProtocol(OutsourcingProtocolBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class InputProtocolFactory(protocol.ServerFactory):
    def __init__(self, srvr_identity):
        self.srvr_identity = srvr_identity

    def buildProtocol(self, addr):
        p = InputProtocol(factory=self, srvr_identity=self.srvr_identity)
        return p


class OutputProtocolFactory(protocol.ServerFactory):
    def __init__(self, srvr_identity):
        self.srvr_identity = srvr_identity

    def buildProtocol(self, addr):
        p = OutputProtocol(factory=self, srvr_identity=self.srvr_identity)
        return p


class OutsourcingServer(threading.Thread):
    def __init__(self, identity, startInport, startOutport):
        super().__init__(daemon=True)
        # self.setDaemon(True)
        self.identity = identity
        self.inport = startInport
        self.outport = startOutport
        self.portnumber = queue.Queue()

    def run(self):
        inputFactory = InputProtocolFactory(self.identity)
        bind_successful = False
        while not bind_successful:
            # _, self.inport = self.createEndpoint(inputFactory, self.inport)
            deferred = self.createEndpoint(inputFactory, self.inport)
            if isinstance(deferred.result, tcp.Port):
                bind_successful = True
            else:
                logger.debug('could not open port {}, trying with the next one'.format(self.inport))
                self.inport += 1
        logger.info('listening for clients on port {}...'.format(self.inport))
        self.portnumber.put({
            'in-port': self.inport,
        })
        outputFactory = OutputProtocolFactory(self.identity)
        bind_successful = False
        while not bind_successful:
            # _, self.outport = self.createEndpoint(outputFactory, self.outport)
            deferred = self.createEndpoint(outputFactory, self.outport)
            if isinstance(deferred.result, tcp.Port):
                bind_successful = True
            else:
                logger.debug('could not open port {}, trying with the next one'.format(self.outport))
                self.outport += 1
        logger.info('listening for verification servers on port {}...'.format(self.outport))
        self.portnumber.put({
            'out-port': self.outport,
        })
        reactor.run(installSignalHandlers=False)  # this prevent the error message

    def log_error(self, failure):
        failure.trap(CannotListenError)
        # logger.error('***** could not open port *****')

    @inlineCallbacks
    def createEndpoint(self, factory, port):
        endpoint = endpoints.TCP4ServerEndpoint(reactor, port)
        deferred = endpoint.listen(factory)
        deferred.addErrback(self.log_error)
        result = yield deferred
        returnValue(result)
