import datetime
from utils import app, db, login_required, deauthorize
from flask import redirect, session, request, render_template, url_for
from login import authorized

# fixes request protocol after proxy_pass to http
class ReverseProxied(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        scheme = environ.get('HTTP_X_FORWARDED_PROTO')
        if scheme:
            environ['wsgi.url_scheme'] = scheme
        return self.app(environ, start_response)

app.wsgi_app = ReverseProxied(app.wsgi_app)

@app.route("/login/<method>/continue")
def done(method):
    return redirect("/")

@app.route("/login/sessions")
@login_required("user")
def active(user):
    active = [dict(zip(["token", "ip", "authtime"], sess)) for sess in db.query(
        "SELECT token, ip, authtime FROM active WHERE uuid = ?",
        (user["id"],))]
    for sess in active:
        sess["authtime"] = datetime.datetime.fromtimestamp(sess["authtime"])\
            .strftime("%m/%d/%Y %H:%M:%S UTC")
        sess["current"] = sess["token"] == session["token"]
    return render_template("sessions.html", active=active)

@app.route("/login/logout")
@login_required("user")
def logout(user):
    deauthorize(user["id"], session["token"], session["method"])
    session.clear()
    return redirect(url_for("login"))

@app.route("/login/deauthorize/<token>", methods=["POST"])
@login_required("user")
def kick(token, user):
    deauthorize(user["id"], token, session["method"])
    return ""

if __name__ == "__main__":
    app.run(port=8972)
