#!/usr/bin/env python3
import os
import sys
import logging

from ..storage import sqlitedb as db
from ..network.client.client_registration_protocol import ClientRegistrationProtocol
from ..network.client.mpc_request_protocol import MPCRequestProtocol

logging.basicConfig(format='%(asctime)s |%(levelname)-7s| %(name)s:%(message)s', level=logging.DEBUG)
logger = logging.getLogger('ClientApplication')
autoconnect = True
ctrlchannel = None  # an instance of the management exchange protocol (for MPC job requests)

mpc_params = {
    'nservers': 3,
    'location': 'any',
    'csp': 'any',  # cloud service provider
    'ncpus': 4,
    'ram': 8,
    'fixp': 12,
}

def exit_program():
    if ctrlchannel:
        ctrlchannel.close()
    print('application closed.\n')
    sys.exit(0)

def printClientName(identity):
    iotype = []
    if identity.get('datasource', False):
        iotype.append('source')
    if identity.get('dataconsumer', False):
        iotype.append('consumer')
    print('\xabdata {} client \'{}\'\xbb'.format('/'.join(iotype), identity.get('nodename', '')))


logger.info('application started')
prompt = '> '
authenticated = False
db.clt_dir = os.path.split(sys.argv[0])[0]
_id = None
if len(sys.argv) > 1:
    try:
        _id = int(sys.argv[1])
    except ValueError:
        logger.error('invalid client id \'{}\''.format(sys.argv[1]))
        sys.exit(1)
    folder = format(_id, '03d')
else:
    folderlist = next(os.walk(db.clt_dir))[1]
    folderlist.sort()
    if folderlist:
        folder = folderlist[0]
    else:
        folder = ''
identity = db.load_identity('CLIENT', folder)
if identity:
    printClientName(identity)
    prompt = '{}> '.format(identity['nodename'])

# If this is an output client (data consumer)
inloop = True
while inloop:
    if identity and autoconnect and not authenticated:
        token = 'connect'
    else:
        token = input(prompt).lower()
    if token == 'register':
        if not identity:
            regp = ClientRegistrationProtocol()
            identity = regp.execute()
            prompt = '{}> '.format(identity.get('nodename', ''))
        else:
            print('\xabit appears that this client id is already registered\xbb')
    elif token == 'connect':
        if not identity:
            if _id:
                resp = input('\xbb no information found for this client id. register new client? [yes]:')
                if resp.lower() not in ['', 'y', 'yes']:
                    logger.info('application ended.')
                    sys.exit(0)
            regp = ClientRegistrationProtocol()
            identity = regp.execute()

        elif not authenticated:
            ctrlchannel = MPCRequestProtocol(identity)
            authenticated = ctrlchannel.authenticate()
            if identity.get('datasource', False):
                inloop = False
        else:
            print('\xabclient node connected already\xbb')

    elif token.startswith('runmpc'):
        if authenticated:
            ctrlchannel.requestMpcJob(mpc_params)
        else:
            print('\xabtype \'connect\' to authenticate to the management server first\xbb')

    elif token == 'exit':
        exit_program()

# If this is an input client (data source)
ctrlchannel.listenToServer()
