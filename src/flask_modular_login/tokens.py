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
    next_url = stored.pop(state, "/") # TODO: fallback URL here too
    store_next(stored)
    blueprint.token = token
    return flask.redirect(next_url)

def authorized(session_=None):
    session_ = session_ or flask.session
    method = session_.get("method", None)
    if method in methods:
        flask.g.login_session = session_
        return methods[method][0].authorized

default_timeouts = (3600 * 24, None)

# this needs to go through login server for remote calls
def refresh_access(db, refresh, refresh_time, lease_timeout, cached):
    now = int(time.time())
    if lease_timeout and now - refresh_time > lease_timeout:
        if cached:
            update = db.queryone(
                "SELECT refresh_time from active WHERE refresh=?",
                (refresh,))
            if update is not None and now - update[0] < lease_timeout:
                return True, False, update[0]
        db.execute(
            "UPDATE active SET refresh_time=? WHERE refresh=?",
            (now, refresh))
        return True, True, now
    return False, False, refresh_time

class DBStore(BaseStorage):
    def __init__(
            self, db, method, cache=None, session_=None,
            lease_timeout=default_timeouts[0],
            refresh_timeout=default_timeouts[1]):
        super().__init__()
        self.db, self.method = db, method
        self.lease_timeout = lease_timeout
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

        authtime = int(time.time())
        refresh = secrets.token_urlsafe(32)
        ip = flask.request.remote_addr
        session_["user"], session_["authtime"] = uniq, authtime
        session_["refresh"], session_["refresh_time"] = refresh, authtime
        session_["name"], session_["picture"] = info["name"], info["picture"]
        self.db.execute(
            "INSERT INTO active"
            "(uuid, refresh, ip, authtime, refresh_time) "
            "VALUES (?, ?, ?, ?, ?)",
            (uniq, refresh, ip, authtime, authtime))
        self.cache.set(refresh, (encoded, ip, authtime, authtime))

    def get(self, blueprint):
        db, info = self.db.begin(), None
        session_ = flask.g.get("login_session", None) or self.session()
        if "refresh" not in session_:
            return None

        refresh = session_["refresh"]
        cached = self.cache.get(refresh)
        if cached is None:
            info = db.queryone(
                "SELECT auths.token, active.ip, "
                "active.authtime, active.refresh_time "
                "FROM active LEFT JOIN auths ON auths.uuid=active.uuid "
                "WHERE active.refresh=?", (refresh,))
            if info is None:
                session_.clear()
                return None

            token, ip, authtime, refresh_time = info
            info = list(info)
        else:
            token, ip, authtime, refresh_time = cached
            cached = list(cached)

        if self.refresh_timeout and int(
                time.time()) - authtime > self.refresh_timeout:
            self.deauthorize(refresh)
            session_.clear()
            return None

        updated, write, refresh_time = refresh_access(
            db, refresh, refresh_time, self.lease_timeout,
            cached is not None)

        if updated:
            info = info or cached
            info[3] = refresh_time
            session_["refresh_time"] = refresh_time

        current_ip = flask.request.remote_addr
        if ip != current_ip:
            db.execute("UPDATE active SET ip=? WHERE refresh=?",
                (current_ip, refresh))
            info = info or cached
            info[1] = current_ip
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

    def deauthorize(self, refresh, user=None, callback=lambda *a: None):
        session_ = self.session()
        db = self.db.begin()
        user_query, user_args = ("", ()) if user is None else \
            (" AND user=?", (user,))
        authtime = db.queryone(
            "SELECT authtime FROM active WHERE refresh=?" + user_query,
            (refresh,) + user_args)
        if authtime == None:
            return None
        now = float(time.time())
        rowid = db.execute(
            "INSERT INTO revoked(revoked_time, refresh, authtime, "
            "refresh_time) VALUES (?, ?, ?, ?)", (
                now, session_["refresh"], authtime[0],
                session_["refresh_time"]))
        callback(
            rowid, now, session_["refresh"], session_["refresh_time"])
        db.execute(
            "DELETE FROM active WHERE refresh=?", (refresh,))
        self.cache.delete(refresh)
        db.commit().close()

