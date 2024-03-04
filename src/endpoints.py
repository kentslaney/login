import datetime, flask, urllib.parse

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from interface import OAuthBlueprint
from login import authorized

end_locals()

# all endpoints can only be called with flask.current_app as the auth app
class LoginBlueprint(OAuthBlueprint):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.route("/logout")(self._oauth_logout)
        self.route("/deauthorize/<refresh>", methods=["POST"])(
            self._oauth_kick)
        self.route("/sessions")(self._oauth_sessions)

    def _oauth_logout(self):
        if "method" in flask.session:
            self._oauth_deauthorize(
                flask.session["refresh"], flask.session["method"])
            flask.session.clear()
        return flask.redirect(flask.request.args.get(
            "next", self.login_endpoint()))

    def _oauth_kick(self, refresh):
        if not authorized():
            flask.abort(401)
        self._oauth_deauthorize(
            refresh, flask.session["method"], flask.session["user"])

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
        return flask.render_template("sessions.html", active=active)
