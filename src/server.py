import datetime
from flask import redirect, session, request, render_template, url_for, abort

import sys, os.path; start_local, end_local = (lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__))), lambda: sys.path.pop(0)

from utils import app, db, login_required, deauthorize

end_local()

@app.route("/login/<method>/continue")
def done(method):
    return redirect("/")

@app.route("/login/sessions")
@login_required("user")
def active(user):
    active = [dict(zip(["token", "ip", "authtime"], sess)) for sess in db.queryall(
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
    app.run(port=8972, debug=True)
