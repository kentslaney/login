## Usage
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

## TODOs
- login_required for blueprints
- invite links
- alternate language bindings
- conform to PEP8, specifically a reasonable character limit
- flask-dance implementation for apple OAuth
([Github issue](https://github.com/singingwolfboy/flask-dance/issues/418),
[Reference implementation](https://github.com/python-social-auth/social-core/blob/master/social_core/backends/apple.py))
