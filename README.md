# Flask Modular Login
The goal of this project is to allow multiple flask projects to share a single
OAuth login interface, removing the need for multiple API keys and user
databases.

## Usage as a Service
Add a `credentials.json` to the root directory of this project, in the form
```json
{
    "google|facebook|github": {"id": "username", "secret": "API key"},
}
```
In case the project doesn't have OAuth credentials or a public facing URL yet,
starting the server in debug mode will add a "test" login option.

Next, start the caching service and server via
```bash
$ memcached -d
$ source venv/bin/activate # assuming you have one
$ python server.py
```

In the client project with a login requirement, install the local copy of this
repo using
```bash
$ pip install -e path/to/repo
$ ln -s path/to/repo/src path/to/site-packages/flask_modular_login
```
Ideally, the project should have a virtual environment the package is installed
into, in which case the `site-packages` path will look like
`venv/lib/python3.VERSION/site-packages/flask_modular_login`

For in the server code for the client project, login requirements can now be
specified using
```python
import flask
from flask_modular_login import login_required, login_optional

app = flask.Flask(__name__)

@app.route("/user_info/<str:kind>")
@login_required("user")
def protected_or_user_info(kind, user):
    # only logged in users can access this route, others redirected by flask
    # user argument now contains keys id, name, picture
    return user["id"]

@app.route("/profile_api")
@login_optional("user")
def profile(user=None):
    # login optional can be used when logged out users shouldn't see a redirect
    return str(user)

@app.route("/hidden")
@login_required
def hidden():
    # same as before, but the user info is now stored in flask.g.user
    return profile(user={"id": flask.g.user["id"], "name": "anon", "picture": ""})
    # methods with optional login can also be called with a custom user argument
    # but only as a keyword, since *args wrappers can make positional matching
    # unreliable

bp = flask.Blueprint("private", __name__, url_prefix="/private")
login_required(bp) # returns bp, could be integrated into line above

@bp.route("/page")
def page():
    # user info in flask.g.user, access limited to logged in users
    return flask.g.user["name"]

app.register_blueprint(bp) # login_required call could also be here

if __name__ == "__main__":
    app.run(port=8080)
```

Note that this project only works if the two project URLs share cookies. If the
two projects aren't hosted on the same subdomain, the login redirect will 404,
since the client project doesn't have access to the public facing setup for the
login server. If this is the case, a prefix can be added to the redirect URL via

```python
from flask_modular_login import LoginBuilder

login_config = LoginBuilder(prefix="//example.com/path/prefix")
login_required, login_optional = login_config.decorators
```
or
```python
from flask_modular_login import login_required

login_required.prefix = "//example.com/path/prefix"
# this will modify the default object for both login_required and login_optional
# for all submodules as well
```

You can then use `login_required` and `login_optional` as you normally would.

For the default `server.py` setup, when run as a script, `prefix` should be
`"//localhost:8972"`, and the only working login option will be "test" until
the server is running on externally visable URLs for OAuth services to redirect
to. By default, `server.py` runs on debug mode, so be careful to change that
as whell when updating `host` for external visibility.

When deploying, it's also recommended to use a WSGI server, which can be
configured using a `.ini` file. It has been excluded from this repo since it's
fairly platform dependent, but here is an example implementation for reference
```
[uwsgi]
module = wsgi
master = true

socket = /tmp/flask_modular_login.sock
chmod-socket = 666
vacuum = true
die-on-term = true

chdir = [path to src]
module = server:app
processes = 4
threads = 2
```
which is then run using
```bash
$ uwsgi --ini uwsgi.ini
```
The correspoinding Nginx setup should look like
```
location = /login { rewrite ^ /login/; }
location /login { try_files $uri @login; }
location @login {
        include uwsgi_params;
        uwsgi_pass unix:/tmp/flask_modular_login.sock;
}
```

## Usage as a Package
If there is only one project (ie one flask app) that this login service is being
deployed for, it is also possible to use this repo as a normal package, removing
the extra service/cache to set up.
```python
import flask
from flask_modular_login import OAuthBlueprint, LoginBuilder, login_required

app = flask.Flask(__name__)
app.register_blueprint(OAuthBlueprint("path/to/credentials/dir"))

login_required.app = app
# or
login_required, login_optional = LoginBuilder(app=app).decorators

@app.route("/secret")
@login_required
def hidden():
    return "personal"

if __name__ == "__main__":
    app.run(port=8080)
```

This repo isn't currently on pypi, but it can be included as a requirement by
specifying the git URL. While this setup wasn't the original design goal of the
project, it's still effective and easier to transition into a separate service
later on as needed.

## Customization and OAuth Platform Support
At the moment, the project serves the login interface from the templates in
`src/templates`, which probably need styling to match the application if they're
used. As an alternative, the links that are filled into `/login` by default can
be opened to in a separate window, which should redirect appropiately. The
`next` query parameter sets the redirect location.

This project relies on
[flask-dance](https://github.com/singingwolfboy/flask-dance) for OAuth provider
integration. To change which are supported, modify the interface connected in
`src/platforms.py`. Removing items can be done by commenting out lines in the
`methods` dictionary.

## TODOs
- invite links (requires group permissions)
- alternate language bindings
- conform to PEP8, specifically a reasonable character limit
- flask-dance implementation for apple OAuth
([Github issue](https://github.com/singingwolfboy/flask-dance/issues/418),
[Reference implementation](https://github.com/python-social-auth/social-core/blob/master/social_core/backends/apple.py))
