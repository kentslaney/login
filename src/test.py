from flask import Blueprint, request, abort, url_for, render_template, redirect, g
from werkzeug.local import LocalProxy
from functools import wraps

class MonoBlueprint(Blueprint):
    apps = []

    def register(self, app, options):
        super().register(app, options)
        self.apps.append(app)

test_bp = MonoBlueprint("test", __name__)

def debug_only(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not all(app.debug for app in test_bp.apps):
            abort(403)
        return f(*a, **kw)
    return wrapped

@test_bp.route("/test")
@debug_only
def login():
    url = {"next": request.args["next"]} if "next" in request.args else {}
    url = url_for("test.test_auth_as", **url)
    return render_template("test.html", ip=request.remote_addr, next=url)

test_whois = lambda: request.args.get("who", "")
test_icon = "https://github.githubassets.com/assets/GitHub-Mark-ea2971cee799.png"

class TestMockSession():
    def __init__(self, store):
        self.store = store

    @property
    def authorized(self):
        return self.store.get(self)

    def get(self):
        id = test_whois()
        return {"id": id, "name": id, "picture": test_icon}

@test_bp.route("/test/as")
@debug_only
def test_auth_as():
    who = test_whois()
    if len(who) == 0:
        abort(403)
    test.store.set(test_bp, who)
    return redirect(request.args.get("next", "/"))

def make_test_blueprint(storage, **kw):
    test_session = TestMockSession(storage)

    @test_bp.before_app_request
    def set_applocal_session():
        g.flask_dance_test = test_session
    return test_bp

test = LocalProxy(lambda: g.flask_dance_test)