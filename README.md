## TODOs
- create directory containing a minimal auth verification setup which can be
installed to client projects' virtual environment as an egg dependency using pip
develop mode. Is the whole project as an import that much overhead? what about
bindings for other languages?
- is there some way to sign using multiple keys so that a single compromised
client can have their access revoked and key cycled without impacting the others
- conform to PEP8, specifically a reasonable character limit

(duplicated from login.py)
- flask-dance implementation for apple OAuth

## usage
start server (starting in debug mode will add a "test" login option)
```bash
$ memcached -d
$ source env/bin/activate
$ python server.py
```
client project with login requirement; install
```bash
$ pip install -e path/to/repo
```
use
```python
from login.utils import login_required

@login_required
def route():
    # only logged in users can access this route, others redirected by flask
    ...

@login_required("user")
def protected_or_user_info(user):
    # user now contains keys id, name, picture
    ...
```
