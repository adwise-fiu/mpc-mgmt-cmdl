'''
Multiparty Computation (MPC) Manager - entry program

Runs two servers. A registration server for new participants (MPC servers and clients) and a
coordination server that receives and process MPC request from clients, selects the MPC servers and
distributes network authentication credentials for secure communication between clients and servers.

Copyright (c) 2023, Oscar G. Bautista
'''

import sys

from .manager.manager_app import ManagerApp
from .storage import sqliteutils as sqt

conn = sqt.openConnection()
if not conn:
    sys.exit(1)

manager = ManagerApp(conn)
manager.run()

sqt.closeConnection(conn)
print('mpc manager closed.\n')
