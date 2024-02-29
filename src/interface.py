import json, os.path, functools
import flask, flask_caching

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from store import FKDatabase, relpath
from login import methods, authorized, DBStore
from access import AccessRoot

end_locals()

class OAuthBlueprint(flask.Blueprint):
    _oauth_name = "modular_login"

    @functools.wraps(flask.Blueprint.__init__)
    def __init__(self, path_root=relpath("..", "run"), url_prefix="/login"):
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

        self.group = AccessRoot(self._oauth_db, OAuthBlueprint.login_endpoint)
        self.register_blueprint(self.group.bp)

    def login(self):
        if not authorized(): # only accessed in auth app's context
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
        return FKDatabase(
            app, os.path.join(self._oauth_path_root, "users.db"),
            relpath("schema.sql"), debug=True)

    def _oauth_register(self, app):
        self._oauth_apps.append(app)
        db = self._oauth_db(app)
        cache = flask_caching.Cache(app, config={
            'CACHE_MEMCACHED_SERVERS': [relpath("..", "run", "memcached.sock")],
            'CACHE_TYPE': 'store.threaded_client'})
        stores, blueprints = {}, {}
        for name, (_, factory, scope) in methods.items():
            stores[name] = DBStore(
                db, name, cache, lambda: OAuthBlueprint.session(app))
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
    def login_endpoint(app=None):
        app = app or flask.current_app
        return next(
            i.rule for i in app.url_map.iter_rules()
            if i.endpoint == f"{OAuthBlueprint._oauth_name}.login")

    @staticmethod
    def session(app):
        if flask.current_app == app and not isinstance(
                flask.session, flask.sessions.NullSession):
            return flask.session
        return app.session_interface.open_session(app, flask.request)
