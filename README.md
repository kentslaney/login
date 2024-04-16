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

The only dependency not included is the memcached server. Once installed, start
the caching service and server via
```bash
$ ./server debug
```

In the client project with a login requirement, install the local copy of this
repo using
```bash
$ pip install -e path/to/repo
```

For in the server code for the client project, login requirements can now be
specified using
```python
import flask
from flask_modular_login import login_required, login_optional

app = flask.Flask(__name__)

@app.route("/user_info/<kind>")
@login_required(kw="user")
def protected_or_user_info(kind, user):
    # only logged in users can access this route, others redirected by flask
    # user argument now contains keys id, name, picture
    return user["id"]

@app.route("/profile_api")
@login_optional(kw="user")
def profile(user=None):
    # login optional can be used when logged out users shouldn't see a redirect
    return str(user)

@app.route("/hidden")
@login_required
def hidden():
    # same as before, but the user info is now stored in flask.g.user
    return profile(user={"id": flask.g.user["id"], "name": "me", "picture": ""})
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

For the default server setup, when runing in debug, `prefix` should be
`"//localhost:8000"`, and the only working login option will be "test" until
the server is running on externally visable URLs for OAuth services to redirect
to.

For reference, the correspoinding Nginx deployment setup looks like
```
location = /login { rewrite ^ /login/; }
location /login { try_files $uri @login; }
location @login {
        include uwsgi_params;
        uwsgi_pass unix:/tmp/flask_modular_login.sock;
}
```

Another important option for load balancing is being able to have the login
system as a separate service, only contacted when a access token needs to be
refreshed or a refresh token revoked (eg when the user logs out). In order to
connect the login service with the client server, the client needs to be able to
access an open port on the login server. While the protocol allows this to be
open to the internet while remaining secure, it's likely preferable to use
(reverse) port forwarding on top of ssh to establish the connection unless the
entire cluster is running behind a firewall.

The login server will automatically create the websocket processes and to
integrate a client project `LoginBuilder` just has to be substituted with
`RemoteLoginBuilder`. The default port is `8765`, and the host string will need
to be changed if it's accessed via IP/DNS instead of port forwarding.

## Usage as a Package
If there is only one project (ie one flask app) that this login service is being
deployed for, it is also possible to use this repo as a normal package, removing
the extra service/cache to set up.
```python
import flask
from flask_modular_login import OAuthBlueprint, LoginBuilder, login_required

app = flask.Flask(__name__)
app.register_blueprint(OAuthBlueprint(root_path="path/to/credentials/dir"))

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

```bash
echo "$(grep TODO -r src && grep '^#\+ TODO' README.md \
-A `wc -l README.md | sed 's![^0-9]!!g'` | tail -n +2)" | nl
```

## TODOs
- group __and__ __or__ __xor__ __invert__ __contains__
- group add_user, remove_user, etc
- linked accounts
- RemoteLoginBuilder needs to implement access group creation/adding users/etc
    - would distribution at the DB level make more sense?
- check path interface consitency (pub/sub, memcached, secret_key)
- what happens with multiple login_optional/login_required in a row?
- fresh_login_required?
- it'd be nice to make the invite limitations separated and composable
- consistent indentation between if statements and others
- pub/sub JSON and group access queries
- purge access tokens from remote clients after they're stale
- custom login BP (for the sake of public MVPs)
- invite option to limit sharing by total use time?
- include `X-API-Version` header to enable easier upgrades
- alternate language bindings [link](https://github.com/discord/itsdangerous-rs)
- flask-dance implementation for apple OAuth
([Github issue](https://github.com/singingwolfboy/flask-dance/issues/418),
[Reference implementation](
https://github.com/python-social-auth/social-core/blob/master/social_core/backends/apple.py))
- consider sql alchemy
- rewrite/restructure README to allow quickest start possible
- horizontal scaling ([maybe?](https://github.com/vitessio/vitess))
- type hints would be helpful
- check SQL indicies
- caching in various places
- ...unit tests (hopefully higher up please)
- get a security audit from someone else

