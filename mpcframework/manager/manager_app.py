'''
Multiparty Computation (MPC) Manager Application

Runs two servers. A registration server for new participants (MPC servers and clients) and a
management server that receives and process MPC request from clients, selects the MPC servers and
distributes network authentication credentials for secure communication between clients and servers.

Copyright (c) 2023, Oscar G. Bautista
'''

import os
import sys
import logging
import threading

from twisted.internet import reactor
from ..tmnetwork.regs_protocol import RegistrationServer
from ..tmnetwork.mgmt_protocol import ManagementServer
from ..storage import sqliteutils as sqt


logging.basicConfig(format='%(levelname)-7s| %(name)s:%(message)s', level=logging.DEBUG)
logger = logging.getLogger('ManagerServerApplication')


class ManagerApp:
    def __init__(self, dbcon):
        self.node_list = {
            'clients': [],
            'mpcs': [],
        }
        self._regServer = None
        self._authServer = None
        self.rwdb = dbcon
        self.rodb = sqt.openConnection(mode='ro')

    def run(self):
        self.populateParticipants()
        self.runRegistrationServer()
        self.runManagementServer()
        reactor.run()
        sqt.closeConnection(self.rodb)

    def populateParticipants(self):
        list_of_clients = sqt.getRecordsFromTable(self.rodb, 'clients', ['nodename'])
        list_of_mpcs = sqt.getRecordsFromTable(self.rodb, 'mpcs', ['nodename'])
        print('\nregistered clients:')
        for client in list_of_clients:
            name = client['nodename']
            self.node_list['clients'].append(name)
            print(' + {}'.format(name))
        print('\nregistered MPC servers:')
        for server in list_of_mpcs:
            name = server['nodename']
            self.node_list['mpcs'].append(name)
            print(' + {}'.format(name))
        print('')

    def runRegistrationServer(self):
        self._regServer = RegistrationServer(dbcon=self.rwdb, nodeList=self.node_list)
        self._regServer.start()

    def runManagementServer(self):
        self._authServer = ManagementServer(dbcon=self.rodb, nodeList=self.node_list)
        self._authServer.start()
