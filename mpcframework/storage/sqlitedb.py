import os
import logging
import sqlite3
from urllib.request import pathname2url

logger = logging.getLogger('sqlitedb')
dbfilename = 'credentials.sqlite'

INSERT_RECORD = 'INSERT INTO {} ({}) VALUES ({})'
SELECT_RECORD = 'SELECT {} FROM {}'

CLIENT_ATTRS = [
    'location',
]

MPCS_ATTRS = [
    'location',
    'cpus',
    'ram',
]


def open_database(role, folder='', mode='rw'):
    logger.debug('opening \'{}\' database in \'{}\' mode'.format(dbfilename, mode))
    fullpath = os.path.join(getBaseDirectory(role), folder, dbfilename)
    try:
        fname = 'file:{}?mode={}'.format(pathname2url(fullpath), mode)
        conn = sqlite3.connect(fname, uri=True)
        conn.row_factory = sqlite3.Row
    except sqlite3.OperationalError as e:
        logger.warning('could not access \'{}\': {}'.format(dbfilename, e))
        if mode =='ro':
            return None
        return create_database(role, folder)
    confirm_table_list(role, conn)
    return conn


def create_database(role, folder=None):
    try:
        path = os.path.join(getBaseDirectory(role), folder)
        os.mkdir(path)
    except FileExistsError:
        logger.warning('path {} already exists'.format(path))
    except Exception as e:
        logger.error(e)
        return None
    logger.info('creating \'{}\' database file'.format(dbfilename))
    fullpath = os.path.join(path, dbfilename)
    try:
        conn = sqlite3.connect(pathname2url(fullpath))
        conn.row_factory = sqlite3.Row
    except sqlite3.OperationalError as e:
        logger.error('unable to create database file \'{}\': {}'.format(dbfilename, e))
        return None
    confirm_table_list(role, conn)
    return conn


def confirm_table_list(role, conn):
    with conn:
        try:
            if role == 'CLIENT':
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS nodeinfo (
                        nodename TEXT(20) NOT NULL,
                        datasource INTEGER NOT NULL,
                        dataconsumer INTEGER NOT NULL,
                        location TEXT(20),
                        server_port INTEGER NOT NULL,
                        symm_k BLOB NOT NULL,
                        nonce BLOB NOT NULL,
                        hash_N INTEGER
                    )
                    """
                )
            elif role in ['MPCS']:
                conn.execute(getTableSpecification(role))
        except (sqlite3.OperationalError, sqlite3.InterfaceError, sqlite3.IntegrityError) as e:
            logger.error(e)


def save_identity(role, folder, record):
    conn = open_database(role, folder)
    if not conn:
        logger.warning('could not save the registration information')
        return False
    allowed_attributes = CLIENT_ATTRS if role == 'CLIENT' else MPCS_ATTRS
    attrs = record.pop('attributes', {})
    for attr in allowed_attributes:
        if attr in attrs:
            record[attr] = attrs[attr]
    fields = tuple(record.keys())
    values = tuple(record.values())
    f_string = ('{}, '*len(values)).rstrip(', ').format(*fields)
    v_placeholder = ('?, '*len(values)).rstrip(', ')
    query = INSERT_RECORD.format('nodeinfo', f_string, v_placeholder)
    with conn:
        try:
            conn.execute(query, values)
            conn.commit()
            logger.info('registration information saved')
            status = True
        except (sqlite3.OperationalError, sqlite3.InterfaceError, sqlite3.IntegrityError) as e:
            logger.error(e)
            logger.warning('could not save the registration information')
            status = False
    conn.close()
    return status


def load_identity(role=None, folder=None):
    conn = open_database(role=role, folder=folder, mode='ro')
    if not conn:
        logger.warning('could not find stored credentials')
        return {}
    with conn:
        try:
            row = conn.execute(SELECT_RECORD.format('*', 'nodeinfo')).fetchone()
            logger.info('node information loaded')
        except sqlite3.OperationalError as e:
            logger.error(e)
            logger.warning('could not load the registration information')
    conn.close()
    if row:
        return dict(row)
    else:
        return dict()


def getTableSpecification(role):
    result = """
        CREATE TABLE IF NOT EXISTS nodeinfo (
            nodename TEXT(20) NOT NULL,
            location TEXT(20) NOT NULL,{}
            server_port INTEGER NOT NULL,
            sig_sk BLOB NOT NULL,
            sig_vk BLOB NOT NULL,
            symm_k BLOB NOT NULL,
            nonce BLOB NOT NULL,
            enc_sk BLOB NOT NULL
        )""".format('\ncpus INTEGER NOT NULL,\nram INTEGER NOT NULL,' if role == 'MPCS' else '')
    return result


def getBaseDirectory(role):
    if role == 'CLIENT':
        return clt_dir
    elif role == 'MPCS':
        return mpc_dir
    else:
        return ''


def close_database(conn):
    conn.close()
    logger.info('database connection closed.')
