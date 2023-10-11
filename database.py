# http://flask.pocoo.org/docs/0.11/patterns/sqlite3/
import sqlite3, os.path
from flask import g

class database:
    # creates database if it doesn't exist; set up by schema
    def __init__(self, app, database, schema, init=[]):
        self.database = os.path.abspath(database)
        self.init = init
        if not os.path.exists(database):
            with app.app_context():
                db = self.get()
                with app.open_resource(schema, mode='r') as f:
                    db.cursor().executescript(f.read())
                db.commit()

        self.app = app
        app.teardown_appcontext(lambda e: self.close())

    # returns a database connection
    def get(self):
        db = getattr(g, "_database", None)
        if db is None:
            db = g._database = sqlite3.connect(self.database)
            for i in self.init:
                self.execute(i)
        return db

    def query(self, query, args=(), one=False):
        cur = self.get().execute(query, args)
        rv = cur.fetchall()
        cur.close()
        return (rv[0] if rv else None) if one else rv

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
