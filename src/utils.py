import json, os.path
from flask import Flask, request, redirect, session, current_app, url_for, abort, render_template, sessions
from functools import wraps
from flask_caching import Cache
from werkzeug.middleware.proxy_fix import ProxyFix
from urllib.parse import urlencode

import sys, os.path; start_local, end_local = (lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__))), lambda: sys.path.pop(0)

from store import Database, relpath
from login import methods, authorized, DBStore

end_local()

# create the minimal app context so that other apps can push it to the stack and
# check the login status of the request
app = Flask(__name__)
app.config["SESSION_COOKIE_NAME"] = "login"
app.wsgi_app = ProxyFix(app.wsgi_app)
db = Database(app, relpath("users.db"), relpath("schema.sql"), ["PRAGMA foreign_keys = ON"])
# https://github.com/memcached/memcached/wiki/ConfiguringServer#unix-sockets
# remember TLS for all sensitive ISP traffic, see: MUSCULAR
cache = Cache(app, config={'CACHE_TYPE': 'store.threaded_client'})

try:
    with open(relpath("secret_key"), "rb") as f:
        app.secret_key = f.read()
except FileNotFoundError:
    import os
    with open(relpath("secret_key"), "wb") as f:
        secret = os.urandom(24)
        f.write(secret)
        app.secret_key = secret

try:
    with open(relpath("..", "credentials.json")) as f:
        oauth = json.load(f)
except FileNotFoundError:
    oauth = {name: {"id": "", "secret": ""} for name in methods.keys()}

@app.route("/login/")
def login():
    if not authorized():
        url = {"next": request.args["next"]} if "next" in request.args else {}
        return render_template("login.html", debug=app.debug,
            **{name: url_for(method.name + ".login", **url)
                for name, method in blueprints.items()})
    return redirect("/")

class LoginBuilder:
    login_endpoint = next(i.rule for i in app.url_map.iter_rules() if i.endpoint == "login")

    def __init__(self, prefix=""):
        self.prefix = prefix

    @property
    def endpoint(self):
        return self.prefix + self.login_endpoint

    @staticmethod
    def _session():
        if current_app == app and not isinstance(session, sessions.NullSession):
            return session
        return app.session_interface.open_session(app, request)

    @staticmethod
    def session():
        res = __class__._session()
        return res

    def login_required(self, user_arg=None):
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                login_session = LoginBuilder.session()
                with app.app_context():
                    # the flask dance blueprints modify the current context
                    # with before_app_request for all requests to allow lookup
                    for ctx_setup in current_app.before_request_funcs[None]:
                        ctx_setup()
                    if not authorized(login_session):
                        if request.method == "GET":
                            return redirect(self.endpoint + "?" + urlencode({"next": request.url}))
                            return redirect(url_for("login", next=request.path))
                        else:
                            abort(401)
                    if user_arg is not None:
                        user = {
                                "id": login_session["user"],
                                "name": login_session["name"],
                                "picture": login_session["picture"]
                            }
                if user_arg is None:
                    return f(*args, **kwargs)
                else:
                    return f(*args, **{**kwargs, user_arg: user})
            return wrapper

        if type(user_arg) != str and user_arg is not None:
            wrapped = decorator(user_arg)
            user_arg = None
            return wrapped
        else:
            return decorator

    def __call__(self, user_arg=None):
        return self.login_required(user_arg)

login_required = LoginBuilder()

stores, blueprints = {}, {}
for name, (_, factory, scope) in methods.items():
    stores[name] = DBStore(db, name, cache, LoginBuilder.session)
    blueprints[name] = factory(
        client_id=oauth[name]["id"],
        client_secret=oauth[name]["secret"],
        redirect_url=f"/login/{name}/continue",
        storage=stores[name],
        scope=scope
    )
    app.register_blueprint(url_prefix="/login", blueprint=blueprints[name])

def deauthorize(user, token, method):
    stores[method].deauthorize(user, token)
