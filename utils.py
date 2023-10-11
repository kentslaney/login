import json, os.path
from flask import Flask, request, redirect, session, current_app, url_for, abort, render_template
from database import database
from functools import wraps
from flask_caching import Cache
from login import methods, authorized, DBStore
from flask_dance.consumer.requests import OAuth2Session

# create the minimal app context so that other apps can push it to the stack and
# check the login status of the request
relpath = lambda *args: os.path.join(os.path.dirname(os.path.realpath(__file__)), *args)
app = Flask(__name__)
db = database(app, relpath("users.db"), relpath("schema.sql"), ["PRAGMA foreign_keys = ON"])
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

app.session_cookie_name = "login"
try:
    with open(relpath("secret_key"), "rb") as f:
        app.secret_key = f.read()
except FileNotFoundError:
    import os
    with open(relpath("secret_key"), "wb") as f:
        secret = os.urandom(24)
        f.write(secret)
        app.secret_key = secret

with open(relpath("credentials.json")) as f:
    oauth = json.load(f)

stores, blueprints = {}, {}
for name, (_, factory, scope) in methods.items():
    stores[name] = DBStore(db, name, cache)
    blueprints[name] = factory(
        client_id=oauth[name]["id"],
        client_secret=oauth[name]["secret"],
        redirect_url=f"/login/{name}/continue",
        storage=stores[name],
        scope=scope
    )
    app.register_blueprint(url_prefix="/login", blueprint=blueprints[name])

@app.route("/login/")
def login():
    if not authorized():
        url = request.args.get("next", "/")
        return render_template("login.html",
            **{name: url_for(method.name + ".login", next=url)
                for name, method in blueprints.items()})
    return redirect("/")

def deauthorize(user, token, method):
    stores[method].deauthorize(user, token)

def login_required(user_arg=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            with app.app_context():
                # the flask dance blueprints modify the current context
                # with before_app_request for all requests to allow lookup
                for ctx_setup in current_app.before_request_funcs[None]:
                    ctx_setup()
                if not authorized():
                    if request.method == "GET":
                        return redirect(url_for("login", next=request.path))
                    else:
                        abort(401)
                if user_arg is not None:
                    user = {
                            "id": session["user"],
                            "name": session["name"],
                            "picture": session["picture"]
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
