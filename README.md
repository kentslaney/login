## TODOs
- invite links
- login_required for blueprints
- alternate language bindings
- conform to PEP8, specifically a reasonable character limit

(duplicated from login.py)
- flask-dance implementation for apple OAuth

## usage
Add a `credentials.json` to the root directory of this project, in the form
```json
{
    "google|facebook|github": {"id": "username", "secret": "API key"},
}
```
If you don't have OAuth credentials or a public facing URL yet, starting the
server in debug mode will add a "test" login option.

Next, start the caching service and server via
```bash
$ memcached -d
$ source env/bin/activate
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
`env/lib/python3.VERSION/site-packages/flask_modular_login`

For in the server code for the client project, login requirements can now be
specified using
```python
from flask_modular_login import login_required

@login_required
def route():
    # only logged in users can access this route, others redirected by flask
    ...

@login_required("user")
def protected_or_user_info(user):
    # user now contains keys id, name, picture
    ...
```

Note that this project only works if the two project URLs share cookies. If the
two projects aren't hosted on the same subdomain, the login redirect will 404,
since the client project doesn't have access to the public facing setup for the
login server. If this is the case, a prefix can be added to the redirect URL via

```python
from flask_modular_login import LoginBuilder

login_required = LoginBuilder("//example.com/path/prefix")
```
or
```python
from flask_modular_login import login_required

login_required.prefix = "//example.com/path/prefix"
```

You can then use `login_required` as you normally would.

For the default `server.py` setup, when run as a script, `prefix` should be
`"//localhost:8972"`, and the only working login option will be `test` until
the server is running on externally visable URLs for OAuth services to redirect
to. By default, `server.py` runs on debug mode, so be careful to change that
as whell when updating `host` for external visibility.
