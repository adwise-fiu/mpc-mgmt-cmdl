import logging
import sqlite3
from binascii import hexlify

logger = logging.getLogger('sqliteutils')
dbfilename = 'participants.sqlite'

INSERT_RECORD = 'INSERT INTO {} ({}) VALUES ({})'
UPDATE_SINGLE = 'UPDATE {} SET {} = ? WHERE id = 1'
SELECT_RECORDS = 'SELECT {} FROM {}'
SELECT_FILTERED_RECORDS = 'SELECT {} FROM {} WHERE {}={}'

CLIENT_ATTRS = [
    'location',
]

SERVER_ATTRS = {
    'mpcs': [
        'location',
        'cpus',
        'ram',
    ],
}


def openConnection(mode='rw'):
    try:
        fname = 'file:{}?mode={}'.format(dbfilename, mode)
        dbcon = sqlite3.connect(fname, uri=True)
        dbcon.row_factory = sqlite3.Row  # To be able to get fetched data as a dict
        logger.info('opened \'{}\' database in \'{}\' mode'.format(dbfilename, mode))
    except sqlite3.OperationalError as e:
        logger.warning('could not open \'{}\': {}'.format(dbfilename, e))
        if mode == 'ro':
            return None
        return createDatabase()
    if mode != 'ro':
        confirmTablesInitialization(dbcon)
    return dbcon


def createDatabase():
    logger.info('creating \'{}\' database file'.format(dbfilename))
    try:
        dbcon = sqlite3.connect(dbfilename)
        dbcon.row_factory = sqlite3.Row  # To be able to get fetched data as a dict
    except sqlite3.OperationalError as e:
        logger.error('unable to create database file \'{}\': {}'.format(dbfilename, e))
        return None
    confirmTablesInitialization(dbcon)
    return dbcon


def confirmTablesInitialization(dbcon):
    # Create tables if they don't exist
    try:
        dbcon.execute(getTableSpecification('clients'))
        dbcon.execute(getTableSpecification('mpcs'))
        dbcon.execute(
            """
            CREATE TABLE IF NOT EXISTS counters (
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
                clients INTEGER NOT NULL,
                mpcs INTEGER NOT NULL
            )
            """
        )
        logger.info('database tables\' structure verified')
        res = dbcon.execute('SELECT COUNT (*) FROM counters').fetchone()
        if not res[0]:
            dbcon.execute('INSERT INTO counters (clients, mpcs) VALUES (0, 0)')
            dbcon.commit()
            logger.info('\'counters\' table initialized')
    except (sqlite3.OperationalError, sqlite3.InterfaceError, sqlite3.IntegrityError) as e:
        logger.error(e)


def getRecordsFromTable(dbcon, table_name, columns=[], filter=()):
    recordgen = getTableRecordGenerator(dbcon, table_name, columns, filter)
    records = []
    for record in recordgen:
        records.append(record)
    return records


def getSingleRecordFromTable(dbcon, table_name, columns=[], filter=()):
    recordgen = getTableRecordGenerator(dbcon, table_name, columns, filter)
    return next(recordgen, {})


def getTableRecordGenerator(dbcon, table_name, columns, filter):
    if filter and len(filter) == 2:
        template = SELECT_FILTERED_RECORDS
        if type(filter[1]) == str:
            filter = (filter[0], '\'{}\''.format(filter[1]))
    else:
        template = SELECT_RECORDS

    f_string = ', '.join(columns) if columns else '*'
    query = template.format(f_string, table_name, *filter)
    # print(query)
    try:
        res = dbcon.execute(query)
    except (sqlite3.OperationalError, sqlite3.InterfaceError, sqlite3.IntegrityError) as e:
        logger.error(e)
        return
    row = res.fetchone()
    while row:
        yield dict(row)
        row = res.fetchone()
    return


def addClientRecord(dbcon, record):
    record['symm_k'] = hexlify(record['symm_k']).decode()  # This is to make it compatible with existing DB
    record['nonce'] = hexlify(record['nonce']).decode()
    insertRecord(dbcon, 'clients', record, CLIENT_ATTRS)


def addServerRecord(dbcon, srvrtype, record):
    record['sig_vk'] = hexlify(record['sig_vk']).decode()  # This is to make it compatible with existing DB
    record['symm_k'] = hexlify(record['symm_k']).decode()
    record['nonce'] = hexlify(record['nonce']).decode()
    record['enc_pk'] = hexlify(record['enc_pk']).decode()
    srvrtype = srvrtype.lower()
    table_name = srvrtype + ('' if srvrtype.endswith('s') else 's')
    insertRecord(dbcon, table_name, record, SERVER_ATTRS[table_name])


def insertRecord(dbcon, table_name, record, allowed):
    suffix = record.pop('n_suffix', 0)
    attrs = record.pop('attributes', {})
    for attr in allowed:
        if attr in attrs:
            record[attr] = attrs[attr]
    columns = tuple(record.keys())
    values = tuple(record.values())
    f_string = ', '.join(columns)
    v_placeholder = ('?, '*len(values)).rstrip(', ')
    try:
        dbcon.execute(INSERT_RECORD.format(table_name, f_string, v_placeholder), values)
        if suffix > getSingleValue(dbcon, 'counters', table_name):
            dbcon.execute(UPDATE_SINGLE.format('counters', table_name), (suffix,))
        dbcon.commit()
    except (sqlite3.OperationalError, sqlite3.InterfaceError, sqlite3.IntegrityError) as e:
        logger.error(e)


def getParticipantCount(dbcon):
    query = SELECT_RECORDS.format('*', 'counters')
    # print(query)
    try:
        row = dbcon.execute(query).fetchone()
    except (sqlite3.OperationalError, sqlite3.InterfaceError, sqlite3.IntegrityError) as e:
        logger.error(e)
        row = None
    return dict(row) if row else {}


def getSingleValue(dbcon, table_name, column):
    try:
        row = dbcon.execute(SELECT_RECORDS.format(column, table_name)).fetchone()
    except (sqlite3.OperationalError, sqlite3.InterfaceError, sqlite3.IntegrityError) as e:
        logger.error(e)
        row = None
    return row[0] if row else None


def getTableSpecification(table_name):
    if table_name == 'clients':
        result = """
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
                nodename TEXT(20) UNIQUE NOT NULL,
                input INTEGER NOT NULL,
                output INTEGER NOT NULL,
                ip_address TEXT(39),
                location TEXT(20),
                symm_k BLOB NOT NULL,
                nonce BLOB NOT NULL,
                hash_N INTEGER
            )
            """
    else:
        result = """
            CREATE TABLE IF NOT EXISTS {} (
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
                nodename TEXT(20) UNIQUE NOT NULL,
                ip_address TEXT(39) NOT NULL,
                location TEXT(20) NOT NULL,{}
                sig_vk BLOB NOT NULL,
                symm_k BLOB NOT NULL,
                nonce BLOB NOT NULL,
                enc_pk BLOB
            )""".format(
                    table_name,
                    '\ncpus INTEGER NOT NULL,\nram INTEGER NOT NULL,' if table_name == 'mpcs' else ''
                )
    return result


def closeConnection(dbcon):
    dbcon.close()
    logger.info('database connection closed.')
