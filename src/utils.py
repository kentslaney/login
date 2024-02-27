import json, os.path, functools, urllib.parse
from werkzeug.middleware.proxy_fix import ProxyFix
import flask, flask_caching

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from store import Database, relpath
from login import methods, authorized, DBStore

end_locals()

# create the minimal app context so that other apps can push it to the stack and
# check the login status of the request
app = flask.Flask(__name__)
app.config["SESSION_COOKIE_NAME"] = "login"
app.wsgi_app = ProxyFix(app.wsgi_app)

try:
    with open(relpath("..", "secret_key"), "rb") as f:
        app.secret_key = f.read()
except FileNotFoundError:
    import os
    with open(relpath("..", "secret_key"), "wb") as f:
        secret = os.urandom(24)
        f.write(secret)
        app.secret_key = secret

class LoginBuilder:
    def __init__(self, app=app, prefix=None, g_attr="user"):
        self.app = app
        self.prefix = prefix
        self.g_attr = g_attr

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

    @staticmethod
    def session(app):
        if flask.current_app == app and not isinstance(
                flask.session, flask.sessions.NullSession):
            return flask.session
        return app.session_interface.open_session(app, flask.request)

    def auth(self, required=True):
        session_ = LoginBuilder.session(self.app)
        with self.app.app_context():
            # the flask dance blueprints modify the current context
            # with before_app_request for all requests to allow lookup
            for ctx_setup in flask.current_app.before_request_funcs[None]:
                ctx_setup()
            if not authorized(session_):
                if not required:
                    return
                if flask.request.method == "GET":
                    return flask.redirect(
                        self.endpoint + "?" + urllib.parse.urlencode(
                            {"next": flask.request.url}))
                else:
                    flask.abort(401)
            return {
                    "id": session_["user"],
                    "name": session_["name"],
                    "picture": session_["picture"],
                }

    def decorate(self, arg=None, required=True):
        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                user = self.auth(required)
                if user is None:
                    return f(*args, **kwargs)
                elif arg is None:
                    self.g = user
                    return f(*args, **kwargs)
                else:
                    return f(*args, **{arg: user, **kwargs})
            return wrapper
        return decorator

    def before_request(self, bp, required=True):
        def user_auth():
            res = self.auth(required)
            if not isinstance(res, dict):
                return res
            else:
                self.g = res
        bp.before_request(user_auth)

    def login(self, arg=None, required=True):
        if isinstance(arg, str) or arg is None:
            return self.decorate(arg, required)
        elif isinstance(arg, flask.Blueprint) or isinstance(arg, flask.Flask):
            self.before_request(arg, required)
            return arg
        elif callable(arg):
            return self.decorate(None, required)(arg)

    def login_required(self, arg=None):
        return self.login(arg, True)

    def login_optional(self, arg=None):
        return self.login(arg, False)

    def optional(self, arg=None):
        return self.login(arg, False)

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

login_config = LoginCaller()
login_required = login_config.login_required
login_optional = login_config.login_optional

class OAuthBlueprint(flask.Blueprint):
    _oauth_name = "modular_login"

    @functools.wraps(flask.Blueprint.__init__)
    def __init__(self, path_root=relpath(".."), url_prefix="/login"):
        super().__init__(self._oauth_name, __name__, url_prefix=url_prefix)
        self._oauth_path_root = path_root
        self._oauth_apps = []
        self.route("/")(self.login)
        self.record(lambda setup_state: self._oauth_register(setup_state.app))

        credentials = os.path.join(self._oauth_path_root, "credentials.json")
        try:
            with open(credentials) as f:
                self._oauth_keys = json.load(f)
        except FileNotFoundError:
            self._oauth_keys = {
                name: {"id": "", "secret": ""} for name in methods.keys()}

    def login(self):
        if not authorized():
            url = {"next": flask.request.args["next"]} \
                if "next" in flask.request.args else {}
            debug = all(i.debug for i in self._oauth_apps)
            return flask.render_template("login.html", debug=debug, **{
                name: flask.url_for(method.name + ".login", **url)
                for name, method in self._oauth_blueprints.items()})
        return flask.redirect("/")

    def _oauth_deauthorize(self, user, token, method):
        self._oauth_stores[method].deauthorize(user, token)

    def _oauth_db(self, app=None):
        app = app or flask.current_app
        return Database(
            app, os.path.join(self._oauth_path_root, "users.db"),
            relpath("schema.sql"), ["PRAGMA foreign_keys = ON"])

    def _oauth_register(self, app):
        self._oauth_apps.append(app)
        db = self._oauth_db(app)
        cache = flask_caching.Cache(app, config={
            'CACHE_TYPE': 'store.threaded_client'})
        stores, blueprints = {}, {}
        for name, (_, factory, scope) in methods.items():
            stores[name] = DBStore(
                db, name, cache, lambda: LoginBuilder.session(app))
            blueprints[name] = factory(
                client_id=self._oauth_keys[name]["id"],
                client_secret=self._oauth_keys[name]["secret"],
                redirect_url=f"/login/{name}/continue",
                storage=stores[name],
                scope=scope
            )
            app.register_blueprint(
                url_prefix="/login", blueprint=blueprints[name])

        self._oauth_blueprints = blueprints
        self._oauth_stores = stores

    @staticmethod
    def login_endpoint(app):
        return next(
            i.rule for i in app.url_map.iter_rules()
            if i.endpoint == f"{OAuthBlueprint._oauth_name}.login")

bp = OAuthBlueprint()
app.register_blueprint(bp)
