import flask, os, os.path, time, requests, websockets, json, asyncio, urllib
import multiprocessing
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from utils import project_path, RouteLobby, secret_key
from login import refresh_access
from group import ismember
from store import FKHeadless
from utils import relpath

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
        self._root_path = root_path or project_path("run")
        self.unix_path = self.root_path("refresh.sock")

    def root_path(self, *a):
        return os.path.join(self._root_path, *a)

    @staticmethod
    def serialized_public(key):
        return key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    # guarantees self.key
    def keypair(self):
        if os.path.exists(self.root_path("private.pem")):
            with open(self.root_path("private.pem"), "rb") as fp:
                key = serialization.load_pem_private_key(
                    fp.read(), password=None)
        else:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            with open(self.root_path("private.pem"), "wb") as fp:
                fp.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))

            with open(self.root_path("public.pem"), "wb") as fp:
                fp.write(self.serialized_public(key))

        self.key = key

    # returns exit status as bool
    public = None
    def load_public(self):
        if os.path.exists(self.root_path("public.pem")):
            with open(self.root_path("public.pem"), 'rb') as fp:
                self.public = serialization.load_pem_public_key(fp.read())
            return False
        return True

    @staticmethod
    def now():
        return int(time.time() * 10 ** 3).to_bytes(8, 'big')

    # limits app secret key to 128, 192, or 256 bits
    @property
    def secret(self):
        return secret_key()

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
        with open(self.root_path("public.pem"), "wb") as fp:
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
                otp[0x28:0x34], self.serialized_public(self.key.public_key()))

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
            reply[0x28:0x34], reply[0x168:]))
        public.verify(reply[0x68:0x168], reply[0x28:0x48])
        self.public = public
        return public

    def server_send(self, data):
        return self.key.encrypt(self.now() + data)

    def client_recieve(self, data):
        data = self.public.decrypt(data)
        self.timestamp_expiration(data)
        return data[8:]

    def client_send(self, data):
        nonce = os.urandom(12)
        return nonce + AESGCM(self.secret).encrypt(nonce, self.now() + data)

    def server_recieve(self, data):
        data = AESGCM(self.secret).decrypt(data[:12], data[12:])
        self.timestamp_expiration(data)
        return data[8:]

    def server_sync(self, data):
        message = self.now()
        signature = self.key.sign(message + data, *self.signing_params)
        return message + signature + data

    def server_verify(self, data):
        self.key.public_key().verify(
            data[0x8:0x108], data[:8] + data[0x108:], *self.signing_params)
        return self.server_send(data[0x108:])

server_lobby = RouteLobby()

class ServerBP(Handshake):
    def __init__(self, db, *a, root_path=None, **kw):
        super().__init__(root_path)
        self.db, self.a, self.kw = db, a, kw
        self.bp = flask.Blueprint("ws_handshake", __name__, url_prefix="/ws")
        server_lobby.register_lobby(self.bp, self)
        self.keypair()
        self.forkWS() # TODO

    def forkWS(self):
        ws = ServerWS(*self.a, root_path=self.root_path(), **self.kw)
        multiprocessing.Process(target=ws.run, daemon=True).start()

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
        return json.dumps(self.db().queryall(
            "SELECT rowid, revoked_time, access_token, refresh_time "
            "FROM revoked WHERE revoked_time>?", (since,)))

    async def send_deauthorize(self, revoked_time, access, refresh_time):
        async with websockets.connect(self.unix_path) as websocket:
            await websocket.send(self.server_sync(json.dumps(
                [[revoked_time, access, refresh_time]])))

    def deauthorize(self, revoked_time, access, refresh_time):
        asyncio.run(self.send_deauthorize(revoked_time, access, refresh_time))

class WSHandshake(Handshake):
    _db = None
    def db(self):
        if self._db is None:
            self._db = FKHeadless(
                self.root_path("users.db"), relpath("schema.sql"))
        return self._db

class ServerWS(WSHandshake):
    def __init__(
            self, host="localhost", port=8001, cache=None,
            access_timeout=3600*24, refresh_timeout=3600*24*90, *,
            root_path=None):
        super().__init__(root_path)
        self.host, self.port = host, port
        self.cache, self.secondaries = cache, set()
        self.access_timeout = access_timeout
        self.refresh_timeout = refresh_timeout

    @property
    def key(self):
        self.keypair()
        return self.key

    def refresh(self, auth):
        db = self.db().begin()
        cached = self.cache and self.cache.get(auth)
        if cached is None:
            timing = db.queryone(
                "SELECT access_token, authtime, refresh_time FROM active "
                "WHERE refresh=?", (auth,))
            if timing is None:
                return json.dumps([None, None])
            access, authtime, refresh_time = timing
        else:
            _, access, _, authtime, refresh_time = cached

        if self.refresh_timeout and int(
                time.time()) - authtime > self.refresh_timeout:
            if cached is not None:
                self.cache.delete(auth)
            return json.dumps([None, None])

        write, access, refresh_time = refresh_access(
            db, access, auth, refresh_time, self.access_timeout,
            cached is not None)

        if write:
            db.commit()
        db.close()

        return json.dumps([access, refresh_time])

    def access_query(self, user, access_group):
        db = self.db().begin()
        res = json.dumps(ismember(db, user, access_group))
        db.close()
        return res

    async def local_primary(self, ws):
        async for message in ws:
            websockets.broadcast(self.secondaries, self.server_send(message))

    def relay(self, message):
        websockets.broadcast(self.secondaries, self.server_verify(message))

    async def remote_primary(self, ws, init):
        self.relay(init)
        async for message in ws:
            self.relay(message)

    def handler(self, message):
        return self.refresh(message)

    async def secondary(self, ws, init):
        self.server_timer(init)
        self.secondaries.add(ws)
        try:
            async for message in ws:
                refresh_token = self.handler(self.server_recieve(message))
                await ws.send(self.server_send(refresh_token))
        finally:
            self.secondaries.remove(ws)

    async def router(self, ws):
        message = await ws.recv()
        if len(message) == 0x28: # OTP length
            await self.secondary(ws, message)
        else:
            await self.remote_primary(ws, message)

    async def main(self):
        async with websockets.serve(self.router, self.host, self.port), \
                websockets.unix_serve(self.local_primary, self.unix_path):
            await asyncio.Future()

    def run(self):
        asyncio.run(self.main())

class ClientWS(WSHandshake):
    # TODO: json based messages

    # TODO: maybe timeout after long silence and reconnect when a request hits
    # TODO: add versioning to messages/events to allow upgrades w/o downtime
    # TODO: access queries

    def __init__(self, base_url, uri, cache=None, *, root_path=None):
        super().__init__(root_path)
        self.uri, self.cache = uri, cache
        self._url = base_url

    def url(self, path, query=None):
        return self._url + "/ws" + path + (
            "" if query is None else "?" + urllib.urlencode(query))

    @property
    def public(self):
        return self.load_public()

    def load_public(self):
        if super().load_public():
            return self.client_verify_ack(requests.post(
                self.url("/syn"), self.client_syn()).content)
        return self.public

    def update(self):
        since = self.db().queryone("SELECT MAX(revoked_time) FROM revoked")[0]
        data = requests.post(
            self.url("/updates"), self.otp(), params=since or {"since": since})
        self.revoke(json.loads(data.content))

    def revoke(self, info):
        # TODO: cache sync
        self.db().executemany(
            "INSERT INTO ignore(ref, revoked_time, access_token, refresh_time) "
            "VALUES (?, ?, ?, ?)", info)

    def refresh_access(self, refresh, access, refresh_time):
        self.db().execute(
            "UPDATE active SET access_token=?, refresh_time=? WHERE refresh=?",
            (access, refresh_time, refresh))

    async def io_hook(self, message, reply):
        data = json.dumps(reply)
        self.refresh_access(message, *data)

    def router(self, message):
        return self.revoke(message)

    async def listen(self):
        q = asyncio.Queue()
        async def handler(ws):
            e = asyncio.Event()
            async for message in ws:
                local.put((ws, message, e))
                await e.wait()

        async with websockets.connect(self.uri) as notify, \
                websockets.connect(self.uri) as query, \
                websockets.unix_serve(handler, self.unix_path):
            await notify.send(self.otp())
            await query.send(self.otp())
            remote, local = notify.recv(), q.get()
            await asyncio.to_thread(self.update)

            while True:
                done, pending = await asyncio.wait(
                    list(map(asyncio.create_task, [remote, local])),
                    return_when=asyncio.FIRST_COMPLETED)
                done = next(iter(done))
                if remote is done:
                    self.router(json.loads(self.client_recieve(done.result())))
                    remote = notify.recv()
                else:
                    ws, message, event = done.result()
                    await query.send(self.client_send(message))
                    reply = self.client_recieve(await query.recv())
                    asyncio.to_thread(self.io_hook(message, reply))
                    await ws.send(reply)
                    e.set()
                    local = q.get()

    def run(self):
        asyncio.run(self.listen())

class ClientBP(Handshake):
    def __init__(self, *a, root_path=None, **kw):
        super().__init__(root_path)
        self.a, self.kw = a, kw
        self.forkWS() # TODO

    async def reload_access(self, refresh):
        async with websockets.unix_connect(self.unix_path) as websocket:
            return json.loads(await websocket.send(refresh))

    def refresh(self, refresh):
        return asyncio.run(self.reload_access(refresh))

    def forkWS(self):
        ws = ClientWS(*self.a, root_path=self.root_path(), **self.kw)
        multiprocessing.Process(target=ws.run, daemon=True).start()

class RemoteLoginBuilder:
    ...

if __name__ == "__main__":
    ClientWS(
        base_url="http://localhost:8000/login", uri="ws://localhost:8001",
        root_path=project_path("run")).run()

