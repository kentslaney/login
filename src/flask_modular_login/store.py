import os.path, functools

def relpath(*args):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), *args)

project_path = lambda *a: relpath("..", "..", *a)

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
    def queryall(self, query, args=(), names=False):
        cur = self.get().cursor()
        cur.execute(query, args)
        rv = cur.fetchall()
        cur.close()
        if names:
            return [self.names(query, r) for r in rv]
        return rv

    def queryone(self, query, args=(), names=False):
        cur = self.get().cursor()
        cur.execute(query, args)
        rv = cur.fetchone()
        row = cur.lastrowid
        cur.close()
        if names and rv:
            return self.names(query, rv, row)
        return rv

    def execute(self, query, args=()):
        con = self.get()
        cur = con.cursor()
        cur.execute(query, args)
        con.commit()
        res = cur.lastrowid
        cur.close()
        return res or None

    def executemany(self, query, args=()):
        con = self.get()
        cur = con.cursor()
        cur.executemany(query, args)
        con.commit()
        cur.close()

    def begin(self):
        return TransactionContext(self)

    def commit(self):
        return self.get().commit()

    def close(self):
        db = getattr(self._g, '_auth_database', None)
        if db is not None:
            for con in db.values():
                con.close()

    # Has limited reliability, but accuracy is per query so use it if it works.
    # If correctness becomes an issue, SQL syntax is a well specified state
    #     machine which can be parsed if needbe.
    # Current limitations include aliased expressions.
    # Should fail if it can't parse the values.
    @staticmethod
    def names(query, values, rowid=None):
        words = query.lower().split()
        assert words[0] == "select"
        assert words[1] not in ("distinct", "all")
        names = []
        terms = iter(sum(filter(None, (
            sum(([j, ","] for j in i.split(",")), [])[:-1]
            for i in words[1:]), [])))
        for word in terms:
            assert ord('a') <= ord(word[0]) <= ord('z')
            # https://www.sqlite.org/syntax/expr.html
            assert word not in (
                "null", "true", "false", "current_time", "current_date",
                "current_timestamp", "is", "not", "and", "or", "in", "match",
                "like", "regexp", "glob", "collate", "glob", "isnull",
                "notnull", "between", "case", "cast", "raise")
            # attr problems
            assert all(i not in word for i in "()*'\"- ")
            names.append(word.rsplit(".", 1)[-1])
            word = next(terms)
            if word != ",":
                assert not word.startswith("(")
                if word == "as":
                    names[-1] = next(terms)
                    word = next(terms)
                    if word == ",":
                        continue
                break
        assert len(names) == len(values)
        obj = collections.namedtuple(
            "row" + ("" if rowid is None else str(rowid)), names)
        return obj(**dict(zip(names, values)))

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

class RouteLobby:
    routes = None

    @classmethod
    def route(cls, *a, **kw):
        def wrapper(f):
            if cls.routes is None:
                cls.routes = []
            cls.routes.append((a, kw, f))
            return f
        return wrapper

    def register_lobby(self, bp):
        for a, kw, f in self.routes:
            bp.route(*a, **kw)(
                functools.wraps(f)(functools.partial(f, self)))

key_paths = (project_path("run"), project_path())
def secret_key(paths = key_paths):
    for path in paths:
        file = os.path.join(path, "secret_key")
        if os.path.exists(file):
            with open(file, "rb") as f:
                return f.read()

    os.makedirs(paths[0], exist_ok=True)
    with open(os.path.join(paths[0], "secret_key"), "wb") as f:
        secret = os.urandom(24)
        f.write(secret)
    return secret
