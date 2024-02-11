def relpath(*args):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), *args)

# http://flask.pocoo.org/docs/0.11/patterns/sqlite3/
import sqlite3, os.path
from flask import g

class HeadlessDB:
    def __init__(self, database, init=[]):
        self.database = os.path.abspath(database)
        self.init = init

    # returns a database connection
    def get(self):
        db = getattr(g, "_database", None)
        if db is None:
            db = g._database = sqlite3.connect(self.database)
            for i in self.init:
                self.execute(i)
        return db

    def queryall(self, query, args=()):
        cur = self.get().execute(query, args)
        rv = cur.fetchall()
        cur.close()
        return rv

    def queryone(self, query, args=()):
        cur = self.get().execute(query, args)
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

    def close(self):
        db = getattr(g, '_database', None)
        if db is not None:
             db.close()

    def db_init_hook(self):
        pass

class Database(HeadlessDB):
    # creates database if it doesn't exist; set up by schema
    def __init__(self, app, database, schema, init=[]):
        super().__init__(database, init)
        if not os.path.exists(database):
            with app.app_context():
                db = self.get()
                with app.open_resource(schema, mode='r') as f:
                    db.cursor().executescript(f.read())
                db.commit()
                self.db_init_hook()

        self.app = app
        app.teardown_appcontext(lambda e: self.close())

from flask_caching.backends.memcache import MemcachedCache

class ThreadedMemcached(MemcachedCache):
    def import_preferred_memcache_lib(self, servers):
        import libmc
        return libmc.ThreadedClient(servers, hash_fn=libmc.MC_HASH_FNV1_32)

def threaded_client(app, config, args, kwargs):
    return ThreadedMemcached.factory(app, config, args, kwargs)
