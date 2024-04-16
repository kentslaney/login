import json, time, secrets, uuid, urllib.parse
import flask
from flask_dance.consumer import oauth_before_login, oauth_authorized
from flask_dance.consumer.storage import BaseStorage
from flask_dance.utils import FakeCache

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from platforms import methods, userlookup

end_locals()

def safe_redirect(url, app=None):
    app = flask.current_app if app is None else app
    checking = urllib.parse.urlparse(url)
    # fallback could be app.config['SERVER_NAME'] but if multiple subdomains
    # point endpoints to the same flask app (same API token, different logins)
    # then the url redirect should be within the same host
    trusted = app.config['SESSION_COOKIE_DOMAIN'] or flask.request.host
    # cookies shared across ports
    trimmed = checking.netloc.rsplit(":")[0]
    trusted = trusted.rsplit(":")[0]
    valid = not trimmed or trimmed.endswith(trusted)
    if "localhost" in trusted:
        return valid
    return checking.scheme in ("", "https", "wss") and valid

def get_next():
    try:
        return json.loads(flask.session.get("next", "{}"))
    except json.JSONDecodeError:
        return {}

def store_next(stored):
    flask.session["next"] = json.dumps(stored)

# TODO: customizable fallback URL ("/" right now)
@oauth_before_login.connect
def before_login(blueprint, url):
    state = urllib.parse.parse_qs(urllib.parse.urlparse(url)[4])["state"][0]
    stored = get_next()
    current_redirect = flask.request.args.get("next", "/")
    if not safe_redirect(current_redirect):
        flask.abort(400)
    stored[state] = current_redirect
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

def refresh_access(db, access, refresh, refresh_time, access_timeout, cached):
    now = int(time.time())
    if access_timeout and now - refresh_time > access_timeout:
        if cached:
            cur, update = db.queryone(
                "SELECT access_token, refresh_time from active WHERE refresh=?",
                (refresh,))
            if cur != access and now - update < access_timeout:
                return True, False, cur, update
        access = secrets.token_urlsafe(32)
        db.execute(
            "UPDATE active SET access_token=?, refresh_time=? "
            "WHERE refresh=?", (access, now, refresh))
        return True, False, access, now
    return False, False, access, refresh_time

class DBStore(BaseStorage):
    def __init__(self, db, method, cache=None, session_=None,
                 access_timeout=3600*24, refresh_timeout=3600*24*90):
        super().__init__()
        self.db, self.method = db, method
        self.access_timeout = access_timeout
        self.refresh_timeout = refresh_timeout
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
            "(uuid, access_token, refresh, ip, authtime, refresh_time) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (uniq, secret, refresh, ip, authtime, authtime))
        self.cache.set(refresh, (token, secret, ip, authtime, authtime))

    def get(self, blueprint):
        db = self.db.begin()
        session_, info = self.session(), None
        if "refresh" not in session_:
            return None

        refresh = session_["refresh"]
        cached = self.cache.get(refresh)
        if cached is None:
            info = db.queryone(
                "SELECT auths.token, active.access_token, active.ip, "
                "active.authtime, active.refresh_time "
                "FROM active LEFT JOIN auths ON auths.uuid=active.uuid "
                "WHERE active.refresh=?", (refresh,))
            if info is None:
                session_.clear()
                return None

            token, access, ip, authtime, refresh_time = info
            info = list(info)
        else:
            token, access, ip, authtime, refresh_time = cached
            cached = list(cached)

        if self.refresh_timeout and int(
                time.time()) - authtime > self.refresh_timeout:
            self.deauthorize(refresh)
            session_.clear()
            return None

        updated, write, access, refresh_time = refresh_access(
            db, access, refresh, refresh_time, self.access_timeout,
            cached is not None)

        if updated:
            info = info or cached
            info[1], info[4] = access, refresh_time

        current_ip = flask.request.remote_addr
        if ip != current_ip:
            db.execute("UPDATE active SET ip=? WHERE refresh=?",
                (current_ip, refresh))
            info = info or cached
            info[2] = current_ip
            write = True

        if info is not None:
            self.cache.set(refresh, tuple(info))

        if write:
            db.commit()
        db.close()

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
            "INSERT INTO revoked(revoked_time, access_token, authtime, "
            "refresh_time) VALUES (?, ?, ?, ?)", (
                float(time.time()), session_["access"], authtime[0],
                session_["refresh_time"]))
        db.execute(
            "DELETE FROM active WHERE refresh=?", (refresh,))
        self.cache.delete(refresh)
        db.commit().close()

