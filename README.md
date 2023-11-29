## TODOs
- create directory containing a minimal auth verification setup which can be
installed to client projects' virtual environment as an egg dependency using pip
develop mode. Is the whole project as an import that much overhead? what about
bindings for other languages?
- is there some way to sign using multiple keys so that a single compromised
client can have their access revoked and key cycled without impacting the others
- is the current setup vulnerable to replay attacks?
- conform to PEP8, specifically a reasonable character limit

(duplicated from login.py)
- flask-dance implementation for apple OAuth