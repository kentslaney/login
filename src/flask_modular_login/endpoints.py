import datetime, flask, urllib.parse, functools, time

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from interface import OAuthBlueprint
from tokens import authorized
from utils import RouteLobby
from pubsub import ServerBP

end_locals()

login_lobby = RouteLobby()

# all endpoints can only be called with flask.current_app as the auth app
class LoginBlueprint(OAuthBlueprint):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        login_lobby.register_lobby(self, self)
        self._oauth_ws = ServerBP(
            self._oauth_db, root_path=self._oauth_root_path)
        self.register_blueprint(self._oauth_ws.bp)

    def _oauth_deauthorize(self, token, method):
        super()._oauth_deauthorize(
            token, method, callback=self._oauth_ws.deauthorize)

    @login_lobby.route("/logout")
    def _oauth_logout(self):
        if "method" in flask.session:
            self._oauth_deauthorize(
                flask.session["refresh"], flask.session["method"])
            flask.session.clear()
        return flask.redirect(flask.request.args.get(
            "next", self.login_endpoint()))

    @login_lobby.route("/deauthorize/<refresh>", methods=["POST"])
    def _oauth_kick(self, refresh):
        if not authorized():
            flask.abort(401)
        self._oauth_deauthorize(refresh, flask.session["method"])
        return ""

    @login_lobby.template_json("/sessions", "sessions.html")
    def _oauth_sessions(self):
        if not authorized():
            return flask.redirect(
                self.login_endpoint() + "?" + urllib.parse.urlencode(
                    {"next": flask.request.url}))
        active = [
            dict(zip(["token", "ip", "authtime", "refresh_time"], sess))
            for sess in self._oauth_db().queryall(
                "SELECT refresh, ip, authtime, refresh_time FROM active "
                "WHERE uuid = ?", (flask.session["user"],))]
        for sess in active:
            sess["authtime"] = datetime.datetime.fromtimestamp(
                sess["authtime"]).strftime("%m/%d/%Y %H:%M:%S UTC")
            sess["current"] = sess["token"] == flask.session["refresh"]
        return {"active": active}

