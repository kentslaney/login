import json, time, secrets, uuid, urllib.parse
import flask
from flask_dance.contrib.google import google, make_google_blueprint
from flask_dance.contrib.facebook import facebook, make_facebook_blueprint
from flask_dance.contrib.github import github, make_github_blueprint
from flask_dance.consumer import oauth_before_login, oauth_authorized
from flask_dance.consumer.storage import BaseStorage
from flask_dance.utils import FakeCache

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from test import test, make_test_blueprint

end_locals()

methods = {
    "google": (google, make_google_blueprint, None),
    "facebook": (facebook, make_facebook_blueprint, None),
    "github": (github, make_github_blueprint, None),
    "test": (test, make_test_blueprint, None)
}

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

def userlookup(method):
    if method == "google":
        return remap(google.get("/oauth2/v3/userinfo").json(), {
            "id": "sub", "name": "name", "picture": "picture"})
    elif method == "facebook":
        conf = ".width(200).height(200)"
        return remap(facebook.get(f"/me?fields=id,name,picture{conf}").json(), {
            "id": "id", "name": "name", "picture": ["picture", "data", "url"]})
    elif method == "github":
        return remap(github.get("/user").json(), {
            "id": "node_id", "name": "name", "picture": "avatar_url"})
    elif method == "test":
        return test.get()

def authorized(session_=None):
    session_ = session_ or flask.session
    method = session_.get("method", None)
    if method in methods:
        return methods[method][0].authorized

def remap(old, mapping):
    res = {}
    for k, v in mapping.items():
        r = old
        for i in [v] if type(v) == str else v:
            r = r if r is None else r.get(i, None)
        res[k] = r
    return res

class DBStore(BaseStorage):
    def __init__(self, db, method, cache=None, session_=None, timeout=None):
        super().__init__()
        self.db, self.method, self.timeout = db, method, timeout
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
        ip = flask.request.remote_addr
        session_["user"], session_["token"] = uniq, secret
        session_["name"], session_["picture"] = info["name"], info["picture"]
        self.db.execute(
            "INSERT INTO active(uuid, token, ip, authtime) VALUES (?, ?, ?, ?)",
            (uniq, secret, ip, authtime))
        self.cache.set(secret, (encoded, ip, authtime))

    def get(self, blueprint):
        session_ = self.session()
        if "token" not in session_:
            return None

        cached = self.cache.get(session_["token"])
        if cached is None:
            info = self.db.queryone(
                "SELECT auths.token, active.ip, active.authtime FROM active "
                "LEFT JOIN auths WHERE active.token = ?",
                (session_["token"],))
            if info is None:
                session_.clear()
                return None

            token, ip, authtime = info
            self.cache.set(session_["token"], (token, ip, authtime))
        else:
            token, ip, authtime = cached

        if self.timeout and int(time.time()) - authtime > self.timeout:
            return None

        current_ip = flask.request.remote_addr
        if ip != current_ip:
            self.db.execute("UPDATE active SET ip = ? WHERE token = ?",
                (current_ip, session_["token"]))
            self.cache.set(session_["token"], (token, current_ip, authtime))

        return json.loads(token)

    def delete(self, blueprint):
        session_ = self.session()
        if "user" not in session_:
            return None

        for (token,) in self.db.queryall(
                "SELECT token FROM active WHERE uuid = ?", (session_["user"],)):
            self.cache.delete(token)

        self.db.execute("DELETE FROM auths WHERE uuid = ?", (session_["user"],))

    def deauthorize(self, user, token):
        self.db.execute(
            "DELETE FROM active WHERE uuid = ? AND token = ?", (user, token,))
        self.cache.delete(token)
