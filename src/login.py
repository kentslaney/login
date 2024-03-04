import json, time, secrets, uuid, urllib.parse
import flask
from flask_dance.consumer import oauth_before_login, oauth_authorized
from flask_dance.consumer.storage import BaseStorage
from flask_dance.utils import FakeCache

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from platforms import methods, userlookup

end_locals()

def get_next():
    try:
        return json.loads(flask.session.get("next", "{}"))
    except json.JSONDecodeError:
        return {}

def store_next(stored):
    flask.session["next"] = json.dumps(stored)

@oauth_before_login.connect
def before_login(blueprint, url):
    state = urllib.parse.parse_qs(urllib.parse.urlparse(url)[4])["state"][0]
    stored = get_next()
    stored[state] = flask.request.args.get("next", "/")
    store_next(stored)

@oauth_authorized.connect
def logged_in(blueprint, token):
    state = flask.request.args["state"]
    stored = get_next()
    next_url = stored.pop(state, "/")
    store_next(stored)
    blueprint.token = token
    return flask.redirect(next_url)

def authorized(session_=None):
    session_ = session_ or flask.session
    method = session_.get("method", None)
    if method in methods:
        return methods[method][0].authorized

class DBStore(BaseStorage):
    def __init__(self, db, method, cache=None, session_=None,
                 refresh=3600*24, timeout=3600*24*90):
        super().__init__()
        self.db, self.method = db, method
        self.refresh, self.timeout = refresh, timeout
        self.cache = cache or FakeCache()
        self.session = session_ or (lambda: flask.session)

    def set(self, blueprint, token):
        session_ = self.session()
        session_["method"] = self.method
        info = userlookup(self.method)
        encoded = json.dumps(token)
        uniq = str(uuid.uuid4())

        # upsert returns None
        uid = self.db.execute(
            "INSERT INTO auths"
            "(method, platform_id, display_name, picture, token, uuid) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(method, platform_id) "
            "DO UPDATE SET "
            "token=excluded.token, "
            "display_name=excluded.display_name, "
            "picture=excluded.picture",
            (self.method, info["id"], info["name"], info["picture"],
             encoded, uniq))
        if uid is None:
            uniq = uid if uid is not None else self.db.queryone(
                "SELECT uuid FROM auths WHERE method = ? AND platform_id = ?",
                (self.method, info["id"]))[0]

        secret, authtime = secrets.token_urlsafe(32), int(time.time())
        refresh = secrets.token_urlsafe(32)
        ip = flask.request.remote_addr
        session_["user"], session_["access"] = uniq, secret
        session_["refresh"], session_["refresh_time"] = refresh, authtime
        session_["name"], session_["picture"] = info["name"], info["picture"]
        self.db.execute(
            "INSERT INTO active"
            "(uuid, access, refresh, ip, authtime, refresh_time) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (uniq, secret, refresh, ip, authtime, authtime))
        self.cache.set(refresh, (token, secret, ip, authtime, authtime))

    def get(self, blueprint):
        session_, info = self.session(), None
        if "refresh" not in session_:
            return None

        refresh = session_["refresh"]
        cached = self.cache.get(refresh)
        if cached is None:
            info = self.db.queryone(
                "SELECT auths.token, active.access, active.ip, "
                "active.authtime, active.refresh_time "
                "FROM active LEFT JOIN auths ON auths.uuid=active.uuid "
                "WHERE active.refresh=?", (refresh,))
            if info is None:
                session_.clear()
                return None

            token, access, ip, authtime, refresh_time = info
        else:
            token, access, ip, authtime, refresh_time = cached

        if self.timeout and int(time.time()) - authtime > self.timeout:
            self.deauthorize(refresh)
            session_.clear()
            return None

        if self.refresh and int(time.time()) - refresh_time > self.refresh:
            skip = False
            if cached is not None:
                cur, update = self.db.queryone(
                    "SELECT access, refresh_time from active WHERE refresh=?",
                    (refresh,))
                if cur != access and int(time.time()) - update < self.refresh:
                    access, refresh_time = cur, update
                    skip = True
            if not skip:
                access = secrets.token_urlsafe(32)
                refresh_time = int(time.time())
                self.db.execute(
                    "UPDATE active SET access=?, refresh_time=? "
                    "WHERE refresh=?", (access, refresh_time, refresh))
            info = info or cached
            info[1], info[4] = access, refresh_time

        current_ip = flask.request.remote_addr
        if ip != current_ip:
            self.db.execute("UPDATE active SET ip=? WHERE refresh=?",
                (current_ip, refresh))
            info = info or cached
            info[2] = current_ip

        if info is not None:
            self.cache.set(refresh, info)

        return json.loads(token)

    def delete(self, blueprint):
        session_ = self.session()
        if "user" not in session_:
            return None

        for (refresh,) in self.db.queryall(
                "SELECT refresh FROM active WHERE uuid=?", (session_["user"],)):
            self.deauthorize(refresh)

        self.db.execute("DELETE FROM auths WHERE uuid=?", (session_["user"],))

    def deauthorize(self, refresh, user=None):
        session_ = self.session()
        db = self.db.begin()
        user_query, user_args = ("", ()) if user is None else \
            (" AND user=?", (user,))
        authtime = db.queryone(
            "SELECT authtime FROM active WHERE refresh=?" + user_query,
            (refresh,) + user_args)
        if authtime == None:
            return None
        db.execute(
            "INSERT INTO revoked(revoked_time, access, authtime, refresh_time) "
            "VALUES (?, ?, ?, ?)", (
                float(time.time()), session_["access"], authtime[0],
                session_["refresh_time"]))
        db.execute(
            "DELETE FROM active WHERE refresh=?", (refresh,))
        self.cache.delete(refresh)
        db.commit().close()
