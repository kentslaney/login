import flask, os, os.path, time, requests, websockets, json, asyncio, urllib
import multiprocessing, base64, functools, inspect, datetime
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from itsdangerous import BadSignature

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from utils import project_path, RouteLobby, secret_key
from login import refresh_access, default_timeouts, authorized
from group import AccessGroupRef
from store import ThreadDB, FKDatabase
from utils import relpath, dict_names
from builder import LoginBuilder, app as DefaultBuilder
from interface import OAuthBlueprint

end_locals()

# custom made protocol; approach with skepticism
class Handshake:
    """
    threat model: lateral movement on a shared machine
    assumptions:
      - the WS URI's numeric port can be hijecked by a malicious process
      - anything in the run directory is privledged including unix sockets
      - run has a secret_key needed to verify the flask session's login cookie
      - HTTPS certs validate primary's authority over secondary

    requirements:
      - secondaries shouldn't be able to immitate the primary
      - significantly delayed/successfully replayed messages are failures
      - the primary should also be able to connect via port number
    """

    signing_params = (padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    otp_timeout_ms = 5000

    def __init__(self, root_path=None):
        self._root_path = root_path or project_path()
        self.server_unix_path = self.run_path("server.sock")
        self.client_unix_path = self.run_path("client.sock")

    def root_path(self, *a):
        return os.path.join(self._root_path, *a)

    def run_path(self, *a):
        return self.root_path("run", *a)

    @staticmethod
    def serialized_public(key):
        return key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    # guarantees self.key
    def keypair(self):
        if os.path.exists(self.run_path("private.pem")):
            with open(self.run_path("private.pem"), "rb") as fp:
                key = serialization.load_pem_private_key(
                    fp.read(), password=None)
        else:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            with open(self.run_path("private.pem"), "wb") as fp:
                fp.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))

            with open(self.run_path("public.pem"), "wb") as fp:
                fp.write(self.serialized_public(key))

        self.key = key

    # returns exit status as bool
    public = None
    def load_public(self):
        if os.path.exists(self.run_path("public.pem")):
            with open(self.run_path("public.pem"), 'rb') as fp:
                self.public = serialization.load_pem_public_key(fp.read())
            return False
        return True

    @staticmethod
    def now():
        return int(time.time() * 10 ** 3).to_bytes(8, 'big')

    # limits app secret key to 128, 192, or 256 bits
    @property
    def secret(self):
        return secret_key(self.run_path())

    _salt = None
    @property
    def salt(self):
        if self._salt is None:
            self._salt = os.urandom(32)
        return self._salt

    # hmac is 0x20 long, private key signature is 0x100 long
    # client: proves possession of the shared_secret as OTP
    #    0:   8 is timestamp
    #    8:0x28 is timestamp signed by shared_secret
    # 0x28:0x48 is timestamp plus salt signed by shared_secret
    def client_syn(self):
        message = self.now()
        h = hmac.HMAC(self.secret, hashes.SHA256())
        h.update(message)
        g = h.copy()
        g.update(self.salt)
        return message + h.finalize() + g.finalize()

    def otp(self):
        message = self.now()
        h = hmac.HMAC(self.secret, hashes.SHA256())
        h.update(message)
        return message + h.finalize()

    def timestamp_expiration(self, data):
        latency = time.time() - int.from_bytes(data[:8], 'big')
        assert latency < self.otp_timeout_ms, "signature timeout"

    # verifies the OTP timing but not salt
    def server_timer(self, data):
        self.timestamp_expiration(data)
        h = hmac.HMAC(self.secret, hashes.SHA256())
        h.update(data[:8])
        g = h.copy()
        h.verify(data[8:0x28])
        return g

    # verifies OTP timing and salt
    def client_timer(self, data):
        h = server_timer(data)
        g = h.copy()
        h.update(self.salt)
        h.verify(data[0x28:0x48])
        return g

    # saves/returns the AES encrypted public key
    def save_public(self, serialized):
        with open(self.run_path("public.pem"), "wb") as fp:
            fp.write(serialized)
        public = serialization.load_pem_public_key(serialized)
        return public

    # server: verifies the client has the shared secret
    #         proves possession of the shared secret
    #         proves possession of the private key
    #         sends private key encrypted with the shared secret
    #     0: 0x48 is OTP
    #  0x48: 0x68 is salted hash signed by shared secret
    #  0x68:0x168 is salted hash signed by private key
    # 0x168:      is AES encrypted public key with above as nonce
    def server_sign_otp(self, otp):
        g = self.server_timer(otp)
        g.update(data[0x28:0x48])
        return otp + g.finalize() + \
            self.key.sign(self.secret, otp[0x28:0x48], *self.signing_params) + \
            AESGCM(self.secret).encrypt(
                otp[0x28:0x34], self.serialized_public(self.key.public_key()),
                None)

    # client: verifies the OTP is still valid
    #         verifies the OTP was generated with the shared secret
    #         verifies the server has the shared secret
    #         decrypts and stores the public key
    #         verifies the OTP was signed with the corresponding private key
    def client_verify_ack(self, reply):
        h = self.client_timer(reply)
        h.update(data[0x28:0x48])
        h.verify(data[0x48:0x68])
        public = self.save_public(AESGCM(self.secret).decrypt(
            reply[0x28:0x34], reply[0x168:], None))
        public.verify(reply[0x68:0x168], reply[0x28:0x48], *self.signing_params)
        self.public = public
        return public

    def server_send(self, data):
        nonce = os.urandom(12)
        message = nonce + AESGCM(self.secret).encrypt(
            nonce, self.now() + data.encode(), None)
        signature = self.key.sign(message, *self.signing_params)
        return signature + message

    def client_recieve(self, data):
        self.public.verify(data[:0x100], data[0x100:], *self.signing_params)
        data = AESGCM(self.secret).decrypt(
            data[0x100:0x10C], data[0x10C:], None)
        self.timestamp_expiration(data)
        return data[8:].decode()

    def client_send(self, data):
        nonce = os.urandom(12)
        return nonce + AESGCM(self.secret).encrypt(
            nonce, self.now() + data.encode(), None)

    def server_recieve(self, data):
        data = AESGCM(self.secret).decrypt(data[:12], data[12:], None)
        self.timestamp_expiration(data)
        return data[8:].decode()

    def server_sync(self, data):
        message = self.now()
        signature = self.key.sign(message + data.encode(), *self.signing_params)
        return signature + message + data.encode()

    def server_verify(self, data):
        self.key.public_key().verify(
            data[:0x100], data[0x100:], *self.signing_params)
        return self.server_send(data[0x108:])

    def _fork(self, ws):
        e = multiprocessing.Event()
        multiprocessing.Process(target=ws.run, args=(e,), daemon=True).start()
        e.wait()
        return ws

server_lobby = RouteLobby()

class ServerBP(Handshake):
    def __init__(
            self, db=None, host="localhost", port=8001, cache=None,
            lease_timeout=3600*24, refresh_timeout=None, remote=None,
            root_path=None):
        super().__init__(root_path)
        self.a = (host, port, cache, lease_timeout, refresh_timeout)
        self.db, self.timeouts = db, self.a[-2:]
        self.bp = flask.Blueprint("ws_handshake", __name__, url_prefix="/ws")
        self.sock = (lambda: websockets.connect(remote)) if remote else \
            (lambda: websockets.unix_connect(self.server_unix_path))
        self.encoding = self.server_sync if remote else lambda x: x
        if db is not None:
            server_lobby.register_lobby(self.bp, self)
        self.keypair()

    def _fork(self):
        return super()._fork(
            ServerWS(*self.a, root_path=self.root_path()))

    @server_lobby.route("/syn", methods=["POST"])
    def syn(self):
        try:
            return self.server_sign_otp(flask.request.data)
        except:
            flask.abort(401)

    @server_lobby.route("/updates", methods=["POST"])
    def updates(self):
        try:
            self.server_timer(flask.request.data)
        except:
            flask.abort(401)
        since = flask.request.args.get("since", 0)
        return json.dumps({
            "action": "deauthorized",
            "data": self.db().queryall(
                "SELECT rowid, revoked_time, refresh, refresh_time "
                "FROM revoked WHERE revoked_time>?", (since,)),
            "timeouts": self.timeouts,
        })

    async def send_deauthorize(self, row, revoked_time, refresh, refresh_time):
        async with self.sock() as websocket:
            await websocket.send(self.encoding(json.dumps({
                "action": "deauthorize",
                "data": [[row, revoked_time, refresh, refresh_time]]})))

    def deauthorize(self, *a, **kw):
        try:
            asyncio.run(self.send_deauthorize(*a, **kw))
        except ConnectionRefusedError:
            pass

class WSHandshake(Handshake):
    _db = None
    def db(self):
        if self._db is None:
            self._db = ThreadDB(
                self.run_path("users.db"), relpath("schema.sql"))
        return self._db

class FunctionList(dict):
    def __call__(self, f):
        self[f.__name__] = f
        return f

actionable = FunctionList()

class SessionLoader(flask.sessions.SecureCookieSessionInterface, Handshake):
    permanent_session_lifetime = datetime.timedelta(days=31)

    def get_signing_serializer(self, app=None):
        return super().get_signing_serializer(
            type("key_wrapper", (), {"secret_key": self.secret})()
            if app is None else app)

    def open(self, val):
        s = self.get_signing_serializer()
        if s is None:
            return None
        if not val:
            return self.session_class()
        max_age = int(self.permanent_session_lifetime.total_seconds())
        try:
            data = s.loads(val, max_age=max_age)
            return self.session_class(data)
        except BadSignature:
            return self.session_class()

    def save(self, session):
        return self.get_signing_serializer().dumps(dict(session))

class ServerWS(WSHandshake):
    def __init__(
            self, host="localhost", port=8001, cache=None,
            lease_timeout=3600*24, refresh_timeout=None, *, root_path=None):
        super().__init__(root_path)
        self.host, self.port = host, port
        self.cache, self.secondaries = cache, set()
        self.lease_timeout = lease_timeout
        self.refresh_timeout = refresh_timeout
        self.session_loader = SessionLoader(root_path)

    _key = None
    @property
    def key(self):
        self.keypair()
        return self._key

    @key.setter
    def key(self, value):
        self._key = value

    _app = None
    def app(self):
        # can no longer coexist with the server module
        if self._app is None:
            self._app = DefaultBuilder
            bp = OAuthBlueprint(root_path=self.root_path())
            bp.session = staticmethod(lambda app: flask.g.session)
            self._app.register_blueprint(bp)
        return self._app

    @actionable
    def refresh(self, auth):
        db = self.db().begin()
        cached = self.cache and self.cache.get(auth)
        if cached is None:
            timing = db.queryone(
                "SELECT authtime, refresh_time FROM active WHERE refresh=?",
                (auth,))
            if timing is None:
                return json.dumps(None)
            authtime, refresh_time = timing
        else:
            _, _, authtime, refresh_time = cached

        if self.refresh_timeout and int(
                time.time()) - authtime > self.refresh_timeout:
            if cached is not None:
                self.cache.delete(auth)
            return json.dumps(None)

        updated, write, refresh_time = refresh_access(
            db, auth, refresh_time, self.lease_timeout,
            cached is not None)
        # TODO: cache on updated

        if write:
            db.commit()
        db.close()

        return refresh_time

    @actionable
    def access_query(self, user, access_group, sep='/'):
        return dict_names(AccessGroupRef.reconstruct(
            self.db, access_group, sep).vet(user))

    @actionable
    def ensure_access(self, access_group, sep='/', owner=None):
        group = AccessGroupRef.reconstruct(self.db, access_group, sep, owner)
        group.ensure()
        return group.uuid

    @actionable
    def add_access(self, user, access_group, sep='/'):
        return AccessGroupRef.reconstruct(
            self.db, access_group, sep).add_user(user)

    @actionable
    def remove_access(self, guild):
        return AccessGroupRef.reconstruct(
            self.db, access_id=guild).remove_access(user)

    @actionable
    def from_value(self, cookie, remote_addr, group=None, sep='/'):
        session = self.session_loader.open(cookie)
        with self.app().app_context():
            # the flask dance blueprints modify the current context
            # with before_app_request for all requests to allow lookup
            for ctx_setup in flask.current_app.before_request_funcs[None]:
                ctx_setup()
            flask.g.session = session
            with self.app().test_request_context(
                    environ_base={'REMOTE_ADDR': remote_addr}):
                if not authorized(session):
                    return {"user": None, "cookie": None, "modified": True}
        user = {
                "id": session["user"],
                "name": session["name"],
                "picture": session["picture"],
            }
        if group is not None:
            user["via"] = {"access": self.access_query(user["id"], group, sep)}
        return {
            "user": user, "modified": session.modified,
            "cookie": self.session_loader.save(session)
        }

    async def local_primary(self, ws, init):
        websockets.broadcast(self.secondaries, self.server_send(init))
        async for message in ws:
            websockets.broadcast(self.secondaries, self.server_send(message))

    async def local_router(self, ws):
        message = await ws.recv()
        data = json.loads(message)
        if data["action"] == "deauthorize":
            await self.local_primary(ws, message)
        else:
            await ws.send(self.handler(message))
            async for message in ws:
                await ws.send(self.handler(message))

    def relay(self, message):
        websockets.broadcast(self.secondaries, self.server_verify(message))

    async def remote_primary(self, ws, init):
        self.relay(init)
        async for message in ws:
            self.relay(message)

    def handler(self, message):
        data = json.loads(message)
        action = data.pop("action")
        assert action in actionable
        return json.dumps(actionable[action](self, **data))

    async def secondary(self, ws, init):
        self.server_timer(base64.b64decode(init["data"]))
        subscribed = init["action"] == "subscribe"
        if subscribed:
            self.secondaries.add(ws)
        try:
            async for message in ws:
                refresh_token = self.handler(self.server_recieve(message))
                await ws.send(self.server_send(refresh_token))
        finally:
            if subscribed:
                self.secondaries.remove(ws)

    async def remote_router(self, ws):
        message = await ws.recv()
        data = json.loads(message)
        if data["action"] in ("subscribe", "establish"):
            await self.secondary(ws, data)
        else:
            await self.remote_primary(ws, message)

    async def main(self, ready=None):
        async with websockets.serve(self.remote_router, self.host, self.port), \
                websockets.unix_serve(self.local_router, self.server_unix_path):
            if ready is not None:
                ready.set()
            await asyncio.Future()

    def run(self, ready=None):
        asyncio.run(self.main(ready))

callback = FunctionList()

class ClientWS(WSHandshake):
    # TODO: maybe timeout after long silence and reconnect when a request hits

    def __init__(self, base_url, uri, cache=None, *, root_path=None):
        super().__init__(root_path)
        self.uri, self.cache = uri, cache
        self._url = base_url

    def url(self, path, query=None):
        return self._url + "/login/ws" + path + (
            "" if query is None else "?" + urllib.urlencode(query))

    _public = None
    @property
    def public(self):
        if self._public is None:
            return self.load_public()
        return self._public

    @public.setter
    def public(self, value):
        self._public = value

    def load_public(self):
        if super().load_public():
            return self.client_verify_ack(requests.post(
                self.url("/syn"), self.client_syn()).content)
        return self.public

    def update(self):
        since = self.db().queryone("SELECT MAX(revoked_time) FROM ignore")[0]
        response = requests.post(
            self.url("/updates"), self.otp(),
            params=since and {"since": str(since)})
        data = json.loads(response.content)
        self.revoke(data["data"])
        self.purge(*data["timeouts"])

    def revoke(self, info):
        # TODO: cache sync
        self.db().executemany(
            "INSERT INTO ignore(ref, revoked_time, refresh, refresh_time) "
            "VALUES (?, ?, ?, ?)", info)

    def purge(self, lease_timeout, refresh_timeout):
        now = time.time()
        if lease_timeout is not None:
            self.db().execute(
                "DELETE FROM ignore WHERE refresh_time - ?>?",
                (now, lease_timeout))

    async def io_hook(self, message, reply):
        # print(message, reply)
        data = json.loads(message)
        if data["action"] in callback:
            callback[data["action"]](self, data, reply)

    def router(self, message):
        return self.revoke(message["data"])

    async def listen(self, ready=None):
        q = asyncio.Queue()
        async def handler(ws):
            e = asyncio.Event()
            async for message in ws:
                await q.put((ws, message, e))
                await e.wait()

        async with websockets.connect(self.uri) as notify, \
                websockets.connect(self.uri) as query, \
                websockets.unix_serve(handler, self.client_unix_path):
            await notify.send(json.dumps({
                "action": "subscribe",
                "data": base64.b64encode(self.otp()).decode()}))
            await query.send(json.dumps({
                "action": "establish",
                "data": base64.b64encode(self.otp()).decode()}))
            remote, local = list(map(
                asyncio.create_task, [notify.recv(), q.get()]))
            await asyncio.to_thread(self.update)
            if ready is not None:
                ready.set()

            while True:
                done, pending = await asyncio.wait(
                    [remote, local], return_when=asyncio.FIRST_COMPLETED)
                done = next(iter(done))
                if remote is done:
                    self.router(json.loads(self.client_recieve(done.result())))
                    remote = asyncio.create_task(notify.recv())
                else:
                    res = done.result()
                    ws, message, event = done.result()
                    await query.send(self.client_send(message))
                    reply = self.client_recieve(await query.recv())
                    await self.io_hook(message, reply)
                    await ws.send(reply)
                    event.set()
                    local = asyncio.create_task(q.get())

    def run(self, ready=None):
        asyncio.run(self.listen(ready))

class ClientBP(Handshake):
    def _closure(self, f):
        sig = inspect.signature(f)
        sig = sig.replace(parameters=list(sig.parameters.values())[1:])
        @functools.wraps(f)
        def wrapper(*a, **kw):
            return self._send(f.__name__, **sig.bind(*a, **kw).arguments)
        return staticmethod(wrapper)

    def __init__(self, *a, local=False, root_path=None, **kw):
        super().__init__(root_path)
        self.a, self.kw, self.unix_path = a, kw, \
            self.server_unix_path if local else self.client_unix_path
        for k, v in actionable.items():
            setattr(self, k, self._closure(v))

    async def _send(self, action, **kw):
        async with websockets.unix_connect(self.unix_path) as websocket:
            await websocket.send(json.dumps({"action": action, **kw}))
            return json.loads(await websocket.recv())

    def _fork(self):
        return super()._fork(
            ClientWS(*self.a, root_path=self.root_path(), **self.kw))

class SessionFromValueMixin:
    bp = None # unimplemented

    async def __call__(self, *a, group=None, **kw):
        if callable(group) and not isinstance(group, AccessGroup):
            user = await self.bp.from_value(
                self.get_cookie(*a, **kw), self.remote_addr(*a, **kw))
            group = group(user)
        res = await self.bp.from_value(
            self.get_cookie(*a, **kw), self.remote_addr(*a, **kw), group)
        if res["modified"]:
            self.set_cookie(res["cookie"], *a, **kw)
        return res["user"]

    def remote_addr(self, *a, **kw):
        raise NotImplementedError()

    def get_cookie(self, *a, **kw):
        raise NotImplementedError()

    def set_cookie(self, value, *a, **kw):
        raise NotImplementedError()

class LocalLoginInterface(LoginBuilder, SessionFromValueMixin):
    def __init__(self, root_path=None):
        super().__init__(prefix=None, root_path=root_path)
        self.bp = ClientBP(local=True, root_path=root_path)

class RemoteLoginBuilder(LoginBuilder):
    def __init__(self, base_url, uri, app=None, root_path=None, g_attr="user"):
        app_kw = {} if app is None else {"app": app}
        super().__init__(
            prefix=base_url, g_attr=g_attr, root_path=root_path, **app_kw)
        self.bp = ClientBP(base_url=self.endpoint, uri=uri, root_path=root_path)
        self.lease_timeout, self.refresh_timeout = self.app.config.get(
            "TIMEOUTS", default_timeouts)

    def membership(self, group, user):
        return self.bp.access_query(user, group)

    _db = None
    @property
    def db(self):
        if self._db is None:
            self._db = FKDatabase(
                self.app, self.bp.run_path("users.db"), relpath("schema.sql"))
        return self._db

    def auth(self, redirect=None, required=True, session=None):
        # only checks timing, blacklist
        session, now = session or self.session, time.time()
        bounced = lambda: self.bounce(redirect) if required else None
        if "user" not in session:
            return bounced()
        if self.refresh_timeout and \
                now - session["authtime"] > self.refresh_timeout:
            session.clear()
            return bounced()
        # TODO: caching
        if self.db.queryone(
                "SELECT EXISTS(SELECT 1 FROM ignore WHERE refresh=?)",
                (session["refresh"],))[0]:
            session.clear()
            return bounced()
        if self.lease_timeout and \
                now - session["refresh_time"] > self.lease_timeout:
            refresh_time = asyncio.run(self.bp.refresh(session["refresh"]))
            if refresh_time is None:
                session.clear()
                return bounced()
            session["refresh_time"] = refresh_time
        return {
                "id": session["user"],
                "name": session["name"],
                "picture": session["picture"],
            }

class RemoteLoginInterface(RemoteLoginBuilder, SessionFromValueMixin):
    def __init__(self, base_url, uri, app=None, root_path=None):
        super().__init__(base_url, uri, app, root_path)
        self.session_loader = SessionLoader(root_path)

    _db = None
    @property
    def db(self):
        if self._db is None:
            self._db = ThreadDB(
                self.bp.run_path("users.db"), relpath("schema.sql"))
        return self._db

    async def __call__(self, *a, group=None, **kw):
        if group is None:
            session = self.session_loader.open(self.get_cookie(*a, **kw))
            res = self.auth(required=False, session=session)
            if session.modified:
                session = self.session_loader.save(cookie)
                self.set_cookie(session, *a, **kw)
            return res
        return await super().__call__(*a, group=group, **kw)

def repl(client):
    while True:
        message = input("send action [argv 0] JSON [rest]: ")
        if message == "":
            continue
        message = message.split(" ", 1)
        message = message if len(message) == 2 else message + ["{}"]
        if message[0] not in actionable:
            print("invalid action call")
            continue
        print(asyncio.run(client._send(message[0], **json.loads(message[1]))))

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        'launching', choices=["client", "server", "all", "repl"])
    parser.add_argument('--host-url', default="http://localhost:8000")
    parser.add_argument('--ws-port', default=8001)
    parser.add_argument('--ws-host', default="localhost")
    args = parser.parse_args()

    server_factory = ServerWS if args.launching == "server" else ServerBP
    client_factory = ClientBP if args.launching == "repl" else ClientWS
    server = server_factory(host=args.ws_host, port=args.ws_port)
    client = client_factory(
        base_url=args.host_url, uri=f"ws://{args.ws_host}:{args.ws_port}")

    if args.launching == "server":
        server.run()
    elif args.launching in {"all", "repl"}:
        server._fork()
    if args.launching in {"client", "all"}:
        client.run()
    repl(client._fork())

