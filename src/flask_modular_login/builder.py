import os, os.path, functools, urllib.parse
from werkzeug.middleware.proxy_fix import ProxyFix
import flask

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from utils import secret_key
from login import authorized
from access import AccessGroup
from interface import OAuthBlueprint

end_locals()

# create the minimal app context so that other apps can push it to the stack and
# check the login status of the request
app = flask.Flask(__name__)
app.config["SESSION_COOKIE_NAME"] = "login"
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config["TIMEOUTS"] = (3600 * 24, 3600 * 24 * 90)

class LoginBuilder:
    def __init__(self, app=app, prefix=None, g_attr="user"):
        self.app = app
        self.prefix = prefix
        self.g_attr = g_attr
        app.secret_key = secret_key()

    @property
    def endpoint(self):
        prefix = flask.request.root_url if self.prefix is None and \
            flask.current_app == self.app else self.prefix or ""
        return prefix + OAuthBlueprint.login_endpoint(self.app)

    @property
    def g(self):
        return flask.g.get(self.g_attr)

    @g.setter
    def g(self, value):
        flask.g.__setattr__(self.g_attr, value)

    def bounce(self, redirect=None, group=None):
        # repeated in AccessRoot
        if group is not None:
            # TODO: request access page
            flask.abort(403)
        if flask.request.method == "GET":
            return flask.redirect(
                self.endpoint + "?" + urllib.parse.urlencode(
                    {"next": redirect or flask.request.url}))
        else:
            flask.abort(401)

    def auth(self, redirect=None, required=True):
        session_ = OAuthBlueprint.session(self.app)
        with self.app.app_context():
            # the flask dance blueprints modify the current context
            # with before_app_request for all requests to allow lookup
            for ctx_setup in flask.current_app.before_request_funcs[None]:
                ctx_setup()
            if not authorized(session_):
                if not required:
                    return
                return self.bounce(redirect)
            return {
                    "id": session_["user"],
                    "name": session_["name"],
                    "picture": session_["picture"],
                }

    def vet(self, user, group, redirect=None, required=True):
        permissions = group.vet(self.app, user["id"])
        # TODO: cache
        if permissions is None:
            return self.bounce(redirect, group) if required else user
        return {**user, "via": dict(zip(("group", "membership"), permissions))}

    def decorate(self, kw=None, required=True, group=None, redirect=None):
        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                user = self.auth(redirect, required)
                if user is None:
                    return f(*args, **kwargs)
                elif not isinstance(user, dict):
                    return user
                if group is not None:
                    user = self.vet(user, group, redirect, required)
                    if not isinstance(user, dict):
                        return user
                if kw is None:
                    self.g = user
                    return f(*args, **kwargs)
                else:
                    return f(*args, **{kw: user, **kwargs})
            return wrapper
        return decorator

    def before_request(self, bp, required=True, group=None, redirect=None):
        def user_auth():
            res = self.auth(redirect, required)
            if not isinstance(res, dict):
                return res
            elif group is not None:
                res = self.vet(res, group, redirect, required)
                if not isinstance(res, dict):
                    return res
            self.g = res
        bp.before_request(user_auth)

    def login(
            self, ambiguous=None, kw=None, group=None, redirect=None,
            required=True):
        if isinstance(ambiguous, AccessGroup):
            if group is not None:
                raise TypeError(
                    f"{__class__.__name__}.login()"
                    " got multiple values for argument 'kw'")
            group, ambiguous = ambiguous, None
        if isinstance(ambiguous, str) or ambiguous is None or kw is not None:
            if ambiguous is not None and kw is not None:
                raise TypeError(
                    f"{__class__.__name__}.login()"
                    " got multiple values for argument 'kw'")
            kw = ambiguous if kw is None else kw
            return self.decorate(kw, required, group, redirect)
        elif isinstance(ambiguous, flask.Blueprint) or \
                isinstance(ambiguous, flask.Flask):
            self.before_request(ambiguous, required, group, redirect)
            return ambiguous
        elif callable(ambiguous):
            return self.decorate(None, required, group, redirect)(ambiguous)

    def login_required(
            self, ambiguous=None, kw=None, group=None, redirect=None):
        return self.login(ambiguous, kw, group, redirect, True)

    def login_optional(
            self, ambiguous=None, kw=None, group=None, redirect=None):
        return self.login(ambiguous, kw, group, redirect, False)

    @property
    def decorators(self):
        return self.login_required, self.login_optional

class BoundCall:
    caller, f = None, None

    @staticmethod
    def calls(caller, f):
        self = BoundCall()
        self.caller = caller
        self.f = f
        return self

    @property
    def login_required(self):
        return __class__.calls(self, super().login_required)

    @property
    def login_optional(self):
        return __class__.calls(self, super().login_optional)

    def __getattribute__(self, attr):
        if attr in ("caller", "f"):
            try:
                return object.__getattribute__(self, attr)
            except AttributeError:
                return None
        if object.__getattribute__(self, "caller") is not None:
            return getattr(self.caller, attr)
        return object.__getattribute__(self, attr)

    def __setattr__(self, attr, value):
        if attr in ("caller", "f") or self.caller is None:
            return object.__setattr__(self, attr, value)
        return setattr(self.caller, attr, value)

    def __call__(self, *args, **kwargs):
        assert self.f is not None, "invalid call to LoginBuilder base"
        return self.f(*args, **kwargs)

class LoginCaller(BoundCall, LoginBuilder):
    pass

