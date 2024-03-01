import os.path, functools

def relpath(*args):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), *args)

# http://flask.pocoo.org/docs/0.11/patterns/sqlite3/
import sqlite3, contextlib
import flask

class Passthrough:
    rewrite = ()

    def __init__(self, parent):
        self.parent = parent

    def __getattribute__(self, name):
        if name in ("parent", "rewrite") or name in self.rewrite:
            return object.__getattribute__(self, name)
        return getattr(self.parent, name)

class TransactionCursor(Passthrough):
    rewrite = ("close",)

    def close(self):
        pass

class TransactionConnection(Passthrough):
    rewrite = ("commit", "cursor", "_transaction_cursor")

    def __init__(self, parent):
        super().__init__(parent)
        self._transaction_cursor = None

    def cursor(self):
        if self._transaction_cursor is None:
            self._transaction_cursor = TransactionCursor(self.parent.cursor())
        return self._transaction_cursor

    def commit(self):
        pass

class TransactionContext(Passthrough):
    rewrite = ("get", "commit", "close", "_transaction_con", "begin", "ctx")

    def __init__(self, parent):
        super().__init__(parent)
        self._transaction_con = None

    def __getattribute__(self, name):
        res = super().__getattribute__(name)
        if name not in ("parent", "rewrite") and name not in self.rewrite:
            member = getattr(self.parent.__class__, name, None)
            if callable(member):
                return functools.partial(member, self)
        return res

    def get(self):
        if self._transaction_con is None:
            self._transaction_con = TransactionConnection(self.parent.get())
        return self._transaction_con

    def commit(self):
        self.parent.commit()
        return self

    def close(self):
        if self._transaction_con is not None:
            if self._transaction_con._transaction_cursor is not None:
                self._transaction_con._transaction_cursor.close()
        if isinstance(self.parent, AppContext):
            self.parent.close()

    @property
    def ctx(self):
        raise Exception("context should be added before the transaction")

class AppContext(Passthrough):
    rewrite = ("wrapper", "ctx", "begin", "_transacting")

    def __init__(self, parent):
        super().__init__(parent)
        self._transacting = False

    def __getattribute__(self, name):
        res = super().__getattribute__(name)
        return self.wrapper(res) if \
            name not in ("__class__", "parent", "rewrite") and \
            name not in self.rewrite and callable(res) \
            else res

    def wrapper(self, f):
        @functools.wraps(f)
        def wrapped(*a, **kw):
            return self.ctx(lambda: f(*a, **kw))
        return wrapped

    def ctx(self, f):
        if self._transacting:
            return f()
        with self.parent.app.app_context():
            return f()

    def begin(self):
        self._transacting = True
        self.parent.app.app_context().__enter__()
        return TransactionContext(self)

    def close(self):
        self._transacting = False
        self.parent.app.app_context().__exit__()

class HeadlessDB:
    def __init__(self, database, schema, init=[], debug=False):
        self.database = os.path.abspath(database)
        self.schema, self.init, self.debug = schema, init, debug

        self._g, self.app = None, type("resource_app", (), {
            "open_resource": open, "app_context": contextlib.contextmanager(
                lambda: iter([None]))})()

    def ensure(self):
        if not os.path.exists(self.database):
            with self.app.app_context():
                db = self.get()
                cur = db.cursor()
                with self.app.open_resource(self.schema, mode='r') as f:
                    cur.executescript(f.read())
                cur.close()
                db.commit()
                self.db_init_hook()

    @property
    def persist(self):
        if self._g is None:
            self._g = type("global_store", (), {})()
        return self._g

    # returns a database connection
    def get(self):
        db = getattr(self._g, "_auth_database", None)
        if db is None:
            db = self._g._auth_database = {}
        if self.database not in db:
            con = db[self.database] = self._g._auth_database[self.database] = \
                sqlite3.connect(self.database)
            for i in self.init:
                self.execute(i)
            if self.debug:
                con.set_trace_callback(print)
        return db[self.database]

    # TODO: add paging before use at scale
    def queryall(self, query, args=()):
        cur = self.get().cursor()
        cur.execute(query, args)
        rv = cur.fetchall()
        cur.close()
        return rv

    def queryone(self, query, args=()):
        cur = self.get().cursor()
        cur.execute(query, args)
        rv = cur.fetchone()
        cur.close()
        return rv

    def execute(self, query, args=()):
        con = self.get()
        cur = con.cursor()
        cur.execute(query, args)
        con.commit()
        res = cur.lastrowid
        cur.close()
        return res or None

    def begin(self):
        return TransactionContext(self)

    def commit(self):
        return self.get().commit()

    def close(self):
        db = getattr(self._g, '_auth_database', None)
        if db is not None:
            for con in db.values():
                con.close()

    def db_init_hook(self):
        pass

class Database(HeadlessDB):
    # creates database if it doesn't exist; set up by schema
    def __init__(self, app, database, schema, init=[], debug=False):
        super().__init__(database, schema, init, debug)
        self.app, self._g = app, flask.g
        if app != flask.current_app:
            app.teardown_appcontext(lambda e: self.close())
        self.ensure()

    @property
    def ctx(self):
        return AppContext(self)

class DefaultsDB:
    default_sql = []

    def get(self):
        if not hasattr(self._g, "_auth_database"):
            lower_init = set(sql.lower() for sql in self.init)
            prepend = []
            for sql in self.default_sql:
                if sql.lower() not in lower_init:
                    prepend.append(sql)
            self.init = prepend + self.init
        return super().get()

class FKDatabase(DefaultsDB, Database):
    default_sql = ["PRAGMA foreign_keys = ON"]

from flask_caching.backends.memcache import MemcachedCache

# https://github.com/memcached/memcached/wiki/ConfiguringServer#unix-sockets
# remember TLS for all sensitive ISP traffic, see: MUSCULAR

# TODO: why does this seemingly work without the server running?
class ThreadedMemcached(MemcachedCache):
    def import_preferred_memcache_lib(self, servers):
        import libmc
        return libmc.ThreadedClient(servers, hash_fn=libmc.MC_HASH_FNV1_32)

def threaded_client(app, config, args, kwargs):
    return ThreadedMemcached.factory(app, config, args, kwargs)
