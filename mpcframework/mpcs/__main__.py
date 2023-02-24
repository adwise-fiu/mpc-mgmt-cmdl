#!/usr/bin/env python3
import os
import sys
import logging

from ..storage import sqlitedb as db
from ..network.mpcs.mpcs_registration_protocol import MPCSRegistrationProtocol
from ..network.mpcs.mpc_control_protocol import MPCControlProtocol

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.DEBUG)
logger = logging.getLogger('MPCServerApplication')


logger.info('application started')
db.mpc_dir = os.path.split(sys.argv[0])[0]
_id = None
if len(sys.argv) > 1:
    try:
        _id = int(sys.argv[1])
    except ValueError:
        logger.error('invalid mpc server id \'{}\''.format(sys.argv[1]))
        sys.exit(1)
    folder = format(_id, '03d')
else:
    folderlist = next(os.walk(db.mpc_dir))[1]
    folderlist.sort()
    if folderlist:
        folder = folderlist[0]
    else:
        folder = ''
identity = db.load_identity('MPCS', folder)

if identity:
    print('\xabMPC server \'{}\'\xbb'.format(identity.get('nodename', '')))
else:
    if _id:
        resp = input('\xbb no information found for this mpc server id. register new mpcs? [yes]:')
        if resp.lower() not in ['', 'y', 'yes']:
            logger.info('application ended.')
            sys.exit(0)
    regp = MPCSRegistrationProtocol()
    identity = regp.execute()
    if not identity:
        logger.info('node registration NOT completed.')
        sys.exit(1)

mpc_ctrl = MPCControlProtocol(identity)
if not mpc_ctrl.authenticate():
    sys.exit(1)

mpc_ctrl.listenToServer()
