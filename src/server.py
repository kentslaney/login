import datetime
import flask

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from utils import app, auth_bp, login_required

end_locals()

# TODO: these should be part of auth_bp

@app.route("/login/sessions")
@login_required(kw="user")
def active(user):
    active = [dict(zip(["token", "ip", "authtime"], sess))
              for sess in auth_bp._oauth_db(app).queryall(
                  "SELECT token, ip, authtime FROM active "
                  "WHERE uuid = ?", (user["id"],))]
    for sess in active:
        sess["authtime"] = datetime.datetime.fromtimestamp(sess["authtime"])\
            .strftime("%m/%d/%Y %H:%M:%S UTC")
        sess["current"] = sess["token"] == flask.session["token"]
    return flask.render_template("sessions.html", active=active)

@app.route("/login/logout")
@login_required(kw="user")
def logout(user):
    auth_bp._oauth_deauthorize(
        user["id"], flask.session["token"], flask.session["method"])
    flask.session.clear()
    return flask.redirect(flask.url_for(auth_bp.name + ".login"))

@app.route("/login/deauthorize/<token>", methods=["POST"])
@login_required(kw="user")
def kick(token, user):
    auth_bp._oauth_deauthorize(user["id"], token, flask.session["method"])
    return ""

if __name__ == "__main__":
    app.run(port=8972, debug=True)
