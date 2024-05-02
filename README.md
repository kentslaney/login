# Flask Modular Login
The goal of this project is to allow multiple servers to share a single OAuth
login interface, removing the need for multiple access tokens across separate
user databases. It also serves as an authentication microservice, enabling load
balancing for a distributed system without acting as a bottleneck. Finally, the
project also handles role based access control, including hierarchical groups
and limited-privledge sharing with user friendly QR code support.

It is written in Flask has the simplest interface with client applications also
in Flask, but also has an interface for any other Python web framework. The
middleware for aiohttp, for example, will be covered below. The project doesn't
have bindings for projects in languages besides Python yet, but is well equipped
to handle them using the same interfaces as the ones supporting non-Flask based
Python applications.

## Starting the Login Service
Start the login service on port 8000 with
```bash
$ sh server.sh debug
```

If you go to [`http://localhost:8000/login/view/sessions`](
http://localhost:8000/login/view/sessions), you should see a
'test' link, which will let you specify a username, then show you the current
session.

Clearly, this isn't much of a secure login interface yet, but it does allow for
testing the process without any OAuth API keys. The 'test' option will go away
once the server is run without the `debug` subcommand.

You may notice that the user interfaces are very bare-bones. This is because
they are generally expected to be used through their corresponding AJAX
endpoints from a page styled by the corresponding project. Alternatively, the
templates are in `src/flask_modular_login/templates`.

## Authentication Groups
Most applications need more state information about a user than just whether
they're logged in. For example, to do a closed beta, there needs to be a
distinction betweeen a user that logged in versus one of the testers. Another
common example is a remote file system where users can access or share private
documents.

The most general justification for a unified authentication/access control
system is that any time a user accesses private data, they need to be allowed
to. This by itself is a bad argument though, since, if users just need to access
their own data, then their username is an easy substitute for their access
group. Unfortunately, including user groups is a natural extension of the
requirements in many cases.

Access groups are organized as a disjoint set of [trees](
https://en.wikipedia.org/wiki/Tree_(data_structure)), with permissions flowing
downwards. This is backwards from the unix groups system, where access to each
of the ancestor nodes is required to interact with a node. That being said, most
file system sharing software (Google Drive, Dropbox, etc) uses a top down setup
for permissions: access to a parent folder gives access to the files. In cases
where a disconnect in permissions is needed, the client can symlink two group
trees.

The snippet below both requires a user to be logged in, as well as creates an
access group the user needs to either own or join to see their profile.
```python
import flask
from flask_modular_login import AccessNamespace
from flask_modular_login import login_required

app = flask.Flask(__name__)
login_required.prefix = "//localhost:8000"

group = AccessNamespace(
    "test_group", ownership_method="test", owner_id="127.0.0.1")

@app.route("/access_profile")
@login_required(kw="user", group=group)
def access_profile(user):
    return str(user)

if __name__ == "__main__":
    app.run(port=8080)
```

By logging into the 'test' option named `127.0.0.1` (which should be the
default), it is now possible to:
- Invite people to `test_group`:
[`http://localhost:8000/login/access/view/invite`](
http://localhost:8000/login/access/view/invite)
- Remove users from `test_group`:
[`http://localhost:8000/login/access/view/remove`](
http://localhost:8000/login/access/view/remove)
- Revoke an invitation to `test_group`:
[`http://localhost:8000/login/access/view/renege`](
http://localhost:8000/login/access/view/renege)

Group hierarchies are created using the `group` method, and can be composed
using the binary operators `|` and `&` to indicate `or` and `and` respectively.
For information on more than one group, use `+`, and to reference a subgroup by
name, a `pathlib`-like `/` can be used. Groups can also be constructed based on
arguments passed to the endpoint, including the user dictionary.

As a brief, incomplete example to showcase the usage, consider a messaging app
where images can be unsent or users can be blocked altogether
```python
chat = AccessNamespace("chat", ownership_method="test", owner_id="127.0.0.1")

@app.route("/chats/<DMing>/images/<img>")
@login_required(kw="user", group=lambda DMing, user: \
    !(chat / DMing / "blocked") & \
    chat / DMing / user["id"] / img / "read_access")
def access_profile(DMing, img, user):
    ...
```

## Adding OAuth Providers
This project [currently](#todos) relies on
[flask-dance](https://github.com/singingwolfboy/flask-dance) for its OAuth
interface, meaning that any of the [providers supported there](
https://flask-dance.readthedocs.io/en/latest/providers.html) will also work
here. For now, the easiest platforms to set up are Google, Facebook, and Github,
for reasons that will be explained momentarily.

Add a `credentials.json` to the root directory of this project, in the form
```json
{
    "google|facebook|github": {"id": "username", "secret": "API key"},
}
```

Once the user logs in, the service guarantees a username (`id`), display name
(`name`), and picture (`picture`).

The available platforms are defined in `src/flask_modular_login/platforms.py`,
which maps the OAuth response to the platform-agnostic keys given to client
projects. Remove unused providers from the `methods` dictionary, or add them in
both `userlookup` and `methods`.

At this point, some providers may require a public facing URL to redirect to.
For notes on deployment to public facing URLs, see the [Deployment](#deployment)
section.

## Add Logging in to Projects
In the project with a login requirement ('client'), install the local copy of
this repo using
```bash
$ pip install -e path/to/repo
```

The client can either be on the same server as the login service ('local') or on
a separate one ('remote'), and the server can be either Flask ('builder') or not
('interface'). For naming purposes, the project is assumed to be on the same
server and written in Flask by default.

### (Local)LoginBuilder
When all the URLs are accessed via localhost loopback, the client and server
projects are served on different ports. This is in contrast to the default setup
for deployment, where only the paths differ. To run a test setup, then, the URL
prefix for the login server has to be specified as `http://localhost:8000`. This
will be included in the example code below, but needs to be removed or updated
when deploying to public facing URLs.

For in the server code for the client project, login requirements can now be
specified using `login_required` and `login_optional`. This login system was
demonstrated briefly above, but a more complete walkthrough of the features is
below
```python
import flask
from flask_modular_login import login_required, login_optional

app = flask.Flask(__name__)
login_required.prefix = "//localhost:8000"

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

Because the `login_required` and `login_optional` objects refer to the same
`LoginBuilder`, updating one will update both. Another way to achieve this would
be

```python
from flask_modular_login import LoginBuilder

login_config = LoginBuilder(prefix="http://localhost:8000")
login_required, login_optional = login_config.decorators
```

## Websocket Interfaces
The other methods for connecting to the login server rely on sockets to forward
request information. In general, the websocket servers should be started using

```bash
$ python src/flask_modular_login/pubsub.py
```

### LocalLoginInterface
Python projects using web servers other than Flask are also supported, but have
to specify a way to
 1. get the web request's IP address
 2. get the HTTP cookie `login` (barring config changes)
 3. set the HTTP cookie `login` (again, subject to config)

For example, a web server written in [aiohttp](
https://github.com/aio-libs/aiohttp) might set up the login interface as
```python
from aiohttp import web
from flask_modular_login import LocalLoginInterface

class LoginBuilder(LocalLoginInterface):
    def remote_addr(self, request):
        return request.remote

    def get_cookie(self, request):
        return request.cookies.get('login')

    def set_cookie(self, value, request):
        request["login"] = value

login = LoginBuilder()

@web.middleware
async def process_request(request, handler):
    request['user'] = await login(request)
    response = await handler(request)
    if 'login' in request:
        response.set_cookie('login', request['login'])
    return response

app = web.Application(middlewares=[process_request])

async def handler(request):
    return web.Response(text='Hello, ' + str(request["user"]))

app.router.add_get('/', handler)

if __name__ == '__main__':
    web.run_app(app)
```

### RemoteLoginBuilder
Another important option for load balancing is being able to have the login
system as a separate service, only contacted when an access token lease needs to
be refreshed or revoked (eg when the user logs out). In order to connect the
login service from the client server, the client needs to be able to access

- an open port on the login server
  - by default, the server websocket is hosted on port 8001
  - the port can be made accessable using SSH reverse tunneling to port forward
- a copy of the `secret_key` used by Flask.
  - by default, this is stored in `run/login_secret_session_key`
- the base URL that the login service is hosted on
  - this can be either the public URL or port forwarded
  - used to coordinate shared secrets before opening the websocket connection

### RemoteLoginInterface
Using frameworks other than Flask for a remote client requires the same
information as above.

## Deployment
Deployment requires `memcached` to be installed in the environment hosting the
login service. Installation is OS dependant. The python virtual environment will
be set up and started by the server script, so if it's already running in a
container, you may prefer to uncomment the early exit from the setup function in
`server.sh`.

### Serving via Unix Socket
With the default deployment, `uwsgi.ini` will serve requests from
`run/uwsgi.sock`, relative to this project's root directory. The other important
thing for the web server middleware is that only requests prefixed with `/login`
should be passed to this process.

Here is an example pulled from a working Nginx setup where `socket` in
`uwsgi.ini` has been modified to be `/tmp/flask_modular_login.sock`:
```
location = /login { rewrite ^ /login/; }
location /login { try_files $uri @login; }
location @login {
    include uwsgi_params;
    uwsgi_pass unix:/tmp/flask_modular_login.sock;
}
```

## Useful commands
```bash
echo "$(grep TODO -r src && grep '^#\+ TODO' README.md \
-A `wc -l README.md | sed 's%[^0-9]%%g'` | tail -n +2)" | nl
```

## Project Structure
Rough, slightly outdated builder/interface boxes and "client login app" doesn't
set the available platforms yet. The goal is to have the login server launched
via `LoginBlueprint` and use the repo as a package so it doesn't have to be
modified.
```
+-------------+
| access root |
+-------------+
       |      \\_______
       |       \  \_   \_______
       |        \   \_         \_______
       |         \    \_               \_______
       |          \     \__                    \_______
       |           \       \                           \
+-------------+     \       +-------------+             +-------------+
|  oauth BP   |      \      |access group |____________ |local client |
|  interface  |       \     +-------------+             |  flask app  |
+-------------+        \           |                    +-------------+
       |      \         \          |                 __/
       |       \         \         |              __/
       |        \         \        |           __/
       |         \         \       |        __/
       |          \         \      |       /
+-------------+    \        +-------------+
|  platforms  |     \       |login builder|
+-------------+      \      +-------------+
       |              \            |       \__
       |               \           |          \_
       |                \          |            \_
       |                 \         |              \_
       |                  \        |                \__
       |                   \       |                   \
+-------------+             +-------------+             +-------------+
|   client    |_____________|  login app  |             |   remote    |
|  login app  |             +-------------+             |login builder|
+-------------+             /                           +-------------+
                           /                           /       |
                          /                           /        |
                         /                           /         |
                        /                           /          |
                       /                           /           |
                      /     +-------------+       /     +-------------+
                     /      |local client |      /      |remote client|
                    /       |   compat    |     /       |     app     |
                   /        +-------------+    /        +-------------+
                  /                |          /                |
                 /                 |         /                 |
                /                  |        /                  |
               /                   |       /                   |
              /                    |      /                    |
+-------------+             +-------------+             +-------------+
|  server BP  |             |login builder|             |  client BP  |
+-------------+             |  interface  |             +-------------+
               \__          +-------------+                    |
                  \_               |                           |
                    \_             |                           |
                      \_           |                           |
                        \__        |                           |
                           \       |                           |
                            +-------------+             +-------------+
                            |  server WS  |-------------|  client WS  |
                            +-------------+             +-------------+
```

## TODOs
- set the platforms via launch conditions
- other language compat
- build a use case
- option to auto-redirect to QR code link on first login if not at /qr
- linked accounts
- check path interface consitency (pub/sub, memcached, secret_key)
- consistent indentation between if statements and others
- purge access tokens from remote clients after they're stale
- invite option to limit sharing by total use time?
- include `X-API-Version` header and/or version field in WS messages
- alternate language bindings [link](https://github.com/discord/itsdangerous-rs)
- login.gov integration might be a polite civil service
- switch to python-social-auth
- consider sql alchemy, prep database schema migration system
- horizontal scaling ([maybe?](https://github.com/vitessio/vitess))
- check SQL indicies
- caching in various places
- API docs (doxygen?)
- ...unit tests (hopefully higher up please)
- get a security audit from someone else

