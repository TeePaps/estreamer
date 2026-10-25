from estreamer import plugin
from estreamer import config
import ConfigParser
import json
import sqlite3

try:
    import pymssql
except ImportError:  # pragma: no cover
    pymssql = None

try:
    import psycopg2
except ImportError:  # pragma: no cover
    psycopg2 = None

try:
    import MySQLdb
except ImportError:  # pragma: no cover
    MySQLdb = None


class SQLPlugin(plugin.Plugin):
    '''
    Generic SQL sink for normalized eStreamer records.

    This plugin converts eStreamer records into a simple, cross-database
    event table. It is intentionally lightweight so it works as a default
    sink for legacy SourceFire installations and newer FMC/FTD deployments.
    '''

    __info__ = {
        'description': 'generic SQL writer',
        'author': 'GitHub Copilot',
        'version': '0.2',
        'callback': 'process_record',
    }

    def __init__(self, *args, **kwargs):
        plugin.Plugin.__init__(self, *args, **kwargs)
        self.cfg = ConfigParser.ConfigParser()
        self.cfg.read('estreamer.config')
        self.columns = [
            'event_type',
            'event_id',
            'event_time',
            'initiator_ip',
            'responder_ip',
            'initiator_port',
            'responder_port',
            'user_id',
            'user_name',
            'url_category',
            'client_url',
            'payload',
        ]
        self.backend = self.cfg.get('sink', 'backend', fallback='sqlite').lower()
        self.table_name = self.cfg.get('sink', 'table', fallback='estreamer_events')
        self.conn = self._connect()
        self._ensure_table()

    def _connect(self):
        if self.backend == 'sqlite':
            db_path = self.cfg.get('sink', 'path', fallback='estreamer.db')
            return sqlite3.connect(db_path)

        if self.backend == 'mssql':
            if pymssql is None:
                raise ImportError('pymssql is required for the mssql backend')
            hostname = self.cfg.get('sql', 'hostname')
            username = self.cfg.get('sql', 'user')
            password = self.cfg.get('sql', 'password')
            database = self.cfg.get('sql', 'database')
            return pymssql.connect(hostname, username, password, database)

        if self.backend == 'postgresql':
            if psycopg2 is None:
                raise ImportError('psycopg2 is required for the postgresql backend')
            dsn = self.cfg.get('sql', 'dsn')
            return psycopg2.connect(dsn)

        if self.backend == 'mysql':
            if MySQLdb is None:
                raise ImportError('MySQLdb is required for the mysql backend')
            username = self.cfg.get('sql', 'user')
            password = self.cfg.get('sql', 'password')
            hostname = self.cfg.get('sql', 'hostname')
            database = self.cfg.get('sql', 'database')
            return MySQLdb.connect(hostname, username, password, database)

        raise ValueError('Unsupported SQL backend: {}'.format(self.backend))

    def _ensure_table(self):
        if self.backend == 'sqlite':
            placeholder = '?'
        else:
            placeholder = '%s'

        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS {} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                event_id TEXT,
                event_time TEXT,
                initiator_ip TEXT,
                responder_ip TEXT,
                initiator_port INTEGER,
                responder_port INTEGER,
                user_id INTEGER,
                user_name TEXT,
                url_category TEXT,
                client_url TEXT,
                payload TEXT
            )
        '''.format(self.table_name))
        self.conn.commit()

    def _clean_value(self, value):
        if value is None:
            return None
        if isinstance(value, (int, float, str)):
            return value
        return str(value)

    def _safe_addr(self, value):
        if value in [0, None]:
            return None
        try:
            return config.get_addr(value)
        except Exception:
            return None

    def _normalize_record(self, evt_data):
        if evt_data is None or not hasattr(evt_data, 'type'):
            return None

        record_type = evt_data.type
        payload = {
            'type': record_type,
        }
        if hasattr(evt_data, 'timestamp'):
            payload['timestamp'] = evt_data.timestamp

        if hasattr(evt_data, 'data') and evt_data.data is not None:
            data_obj = evt_data.data
            payload['data'] = data_obj.__dict__ if hasattr(data_obj, '__dict__') else str(data_obj)

        event_type = 'unknown'
        event_id = getattr(evt_data, 'event_id', None)
        event_time = getattr(evt_data, 'timestamp', None)
        initiator_ip = None
        responder_ip = None
        initiator_port = None
        responder_port = None
        user_id = None
        user_name = None
        url_category = None
        client_url = None

        if record_type == config.RCD_TYPE_Connection:
            event_type = 'connection'
            conn = evt_data.data
            event_id = getattr(conn, 'conn_counter', event_id)
            initiator_ip = self._safe_addr(getattr(conn, 'initiator_ip', None))
            responder_ip = self._safe_addr(getattr(conn, 'responder_ip', None))
            initiator_port = getattr(conn, 'initiator_port', None)
            responder_port = getattr(conn, 'responder_port', None)
            user_id = getattr(conn, 'user_id', None)
            client_url = getattr(getattr(conn, 'client_url', None), 'string', None)
            url_category = getattr(conn, 'url_category', None)
            event_time = getattr(evt_data, 'timestamp', None)

        elif record_type == config.RCD_TYPE_UserMeta:
            event_type = 'user_meta'
            user = evt_data.data
            user_id = getattr(user, 'user_id', None)
            user_name = getattr(getattr(user, 'username', None), 'string', None)
            event_id = user_id

        elif record_type == config.RCD_TYPE_URLCategory:
            event_type = 'url_category'
            category = evt_data.data
            url_category = getattr(category, 'category_id', None)
            client_url = getattr(category, 'name', None)
            event_id = getattr(category, 'category_id', None)

        elif record_type == config.RCD_TYPE_IntrusionEvent:
            event_type = 'intrusion_event'
            event_id = getattr(evt_data.data, 'event_id', event_id)

        elif record_type == config.RCD_TYPE_MalwareEvent:
            event_type = 'malware_event'
            event_id = getattr(evt_data.data, 'event_id', event_id)

        if event_time is None and hasattr(evt_data, 'data'):
            event_time = getattr(evt_data.data, 'timestamp', None)

        row = {
            'event_type': event_type,
            'event_id': self._clean_value(event_id),
            'event_time': self._clean_value(event_time),
            'initiator_ip': self._clean_value(initiator_ip),
            'responder_ip': self._clean_value(responder_ip),
            'initiator_port': self._clean_value(initiator_port),
            'responder_port': self._clean_value(responder_port),
            'user_id': self._clean_value(user_id),
            'user_name': self._clean_value(user_name),
            'url_category': self._clean_value(url_category),
            'client_url': self._clean_value(client_url),
            'payload': json.dumps(payload, sort_keys=True, default=str),
        }
        return row

    def process_record(self, record):
        rows = []

        if record.type == config.MSG_TYPE_MessageBundle:
            for evt_data in record.data.data:
                row = self._normalize_record(evt_data)
                if row:
                    rows.append(tuple(row[col] for col in self.columns))
        else:
            if hasattr(record, 'data') and hasattr(record.data, 'data'):
                evt_data = record.data.data
                row = self._normalize_record(evt_data)
                if row:
                    rows.append(tuple(row[col] for col in self.columns))

        if not rows:
            return

        col_sql = ', '.join(self.columns)
        if self.backend == 'sqlite':
            placeholder = ', '.join(['?'] * len(self.columns))
        else:
            placeholder = ', '.join(['%s'] * len(self.columns))

        query = 'INSERT INTO {} ({}) VALUES ({})'.format(self.table_name, col_sql, placeholder)
        self.conn.cursor().executemany(query, rows)
        self.conn.commit()


# -*-
# Legacy plugin compatibility intentionally mirrors the existing examples/
# directory pattern. The SQL sink can be enabled by dropping this file into
# the plugins directory and updating estreamer.config.
# -*-































































































































































    




































































































































































































































































































































































































































































































































































































n












































none
























































































































































