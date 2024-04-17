import flask
from werkzeug.local import LocalProxy
from functools import wraps

class MonoBlueprint(flask.Blueprint):
    apps = []

    def register(self, app, options):
        super().register(app, options)
        self.apps.append(app)

class TestBP(MonoBlueprint):
    def __init__(self):
        super().__init__("test", __name__)
        self.route("/test")(self.debug_only(login))
        self.route("/test/as")(self.debug_only(self.test_auth_as))
        self.route("/test/failure")(self.debug_only(failure))

    def debug_only(self, f):
        @wraps(f)
        def wrapped(*a, **kw):
            if not all(app.debug for app in self.apps):
                flask.abort(403)
            return f(*a, **kw)
        return wrapped

    def test_auth_as(self):
        who = test_whois()
        if len(who) == 0:
            flask.abort(403)
        test.store.set(self, who)
        return flask.redirect(flask.request.args.get("next", "/"))

def login():
    url = {"next": flask.request.args["next"]} if "next" in flask.request.args \
        else {}
    url = flask.url_for("test.test_auth_as", **url)
    return flask.render_template(
        "test.html", ip=flask.request.remote_addr, next=url)

def failure():
    raise RuntimeError()

test_whois = lambda: flask.request.args.get("who", "")
test_pic = "https://github.githubassets.com/assets/GitHub-Mark-ea2971cee799.png"

class TestMockSession():
    def __init__(self, store):
        self.store = store

    @property
    def authorized(self):
        return self.store.get(self)

    def get(self):
        id = test_whois()
        return {"id": id, "name": id, "picture": test_pic}

def make_test_blueprint(storage, **kw):
    test_session = TestMockSession(storage)
    test_bp = TestBP()

    @test_bp.before_app_request
    def set_applocal_session():
        flask.g.flask_dance_test = test_session
    return test_bp

test = LocalProxy(lambda: flask.g.flask_dance_test)

