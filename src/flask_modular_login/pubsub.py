import flask, os.path, time, requests, websockets, json, asyncio, urllib
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import (
    default_backend as crypto_default_backend)

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from store import project_path, RouteLobby, secret_key
from login import refresh_access

end_locals()

# custom made protocol; approach with skepticism
class Handshake:
    host, port = "localhost", 8765 # TODO: client port; make init arg?
    signing_params = (padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    otp_timeout_ms = 5000

    def __init__(self, root_path=None):
        self.root_path = lambda *a: os.path.join(root_path, *a)
        root_path = root_path or project_path("run")
        self.uri = f"wss://{self.host or 'localhost'}:{self.port}"

    @staticmethod
    def serialized_public(key):
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def keypair(self):
        if os.path.exists(self.root_path("private.pem")):
            with open(self.root_path("private.pem"), "rb") as fp:
                key = serialization.load_pem_private_key(
                    fp.read(), crypto_default_backend())
        else:
            key = rsa.generate_private_key(
                backend=crypto_default_backend(),
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

    # limits app secret key to 128, 192, or 256 bits
    @staticmethod
    def shared_secret():
        return secret_key()

    # verifies the OTP (returns HMAC instance from shared secret and symmetric)
    def timer(self, data):
        latency = time.time() - int.from_bytes(data[:8])
        assert latency < self.otp_timeout_ms, "signature timeout"
        h = hmac.HMAC(self.secret, hashes.SHA256())
        g = h.copy()
        h.update(data[:8])
        h.verify(data[8:0x28])
        g.update(data[8:0x28])
        return g

    # encrypts the public key with the shared secret
    def encode(self, reply):
        return reply + AESGCM(self.secret).encrypt(
            reply, self.serialized_public(self.key.public_key()))

    # decrypts the public key with the shared secret
    def decode(self, reply):
        serialized = AESGCM(self.secret).decrypt(reply[:0x148], reply[0x148:])
        with open(self.root_path("public.pem"), "wb") as fp:
            fp.write(serialized)
        return serialization.load_pem_public_key(
            serialized, crypto_default_backend())

    # client: proves possesion of the shared secret
    def otp(self):
        message = int(time.time()*10**3).to_bytes(8, 'big')
        h = hmac.HMAC(self.secret, hashes.SHA256())
        h.update(message)
        return message + h.finalize()

    # server: verifies the client has the shared secret
    #         proves possession of the shared secret
    #         proves possession of the private key
    #         sends private key encrypted with the shared secret
    def sign(self, otp):
        g = self.timer(otp)
        return self.encode(otp + g.finalize() + self.key.sign(
            self.secret, otp[:8], *self.signing_params))

    # client: verifies the OTP is still valid
    #         verifies the OTP was generated with the shared secret
    #         verifies the server has the shared secret
    #         decrypts and stores the public key
    #         verifies the OTP was signed with the corresponding private key
    def verify(self, reply):
        self.timer(reply).verify(reply[:8])
        public = self.decode(reply[0x148:])
        public.verify(reply[0x48:0x148], reply[0:0x28])
        return public

    # primary: proves it has the shared secret and private key
    #              in a way distinct from the OTP method the server uses
    def sync(self, data):
        message = int(time.time()*10**3).to_bytes(8, 'big')
        signature = self.key.sign(message + data, *self.signing_params)
        h = hmac.HMAC(self.secret, hashes.SHA256())
        h.update(signature)
        symmetric = h.finalize()
        return message + symmetric + signature + data

    # secondary: verifies the primary has the shared secret and private key and
    #                didn't just forward an OTP
    #            returns the rest of the data
    def accept(self, data):
        self.key.public_key().verify(
            data[0x28:0x128], data[:8] + data[0x128:], *self.signing_params)
        h = hmac.HMAC(self.secret, hashes.SHA256())
        h.update(data[0x28:0x128])
        h.verify(data[8:0x28])
        return data[0x128:]

class ServerRouter(RouteLobby):
    pass

class ServerBP(Handshake, ServerRouter):
    def __init__(self, db, root_path=None):
        super().__init__(root_path)
        self.db = db
        self.bp = flask.Blueprint("ws_handshake", __name__, url_prefix="/ws")
        self.register_lobby(self.bp)
        self.keypair()

    @ServerRouter.route("/syn", methods=["POST"])
    def syn(self):
        try:
            return self.sign(flask.request.data)
        except:
            flask.abort(401)

    @ServerRouter.route("/updates", methods=["POST"])
    def updates(self):
        try:
            self.timer(flask.request.data)
        except:
            flask.abort(401)
        since = flask.request.args.get("since")
        if since is None:
            flask.abort(400)
        return json.dumps(self.db.queryall(
            "SELECT rowid, revoked_time, access, refresh_time FROM revoked "
            "WHERE revoked_time>?", (since,)))

    async def send_deauthorize(self, revoked_time, access, refresh_time):
        async with websockets.connect(self.uri) as websocket:
            await websocket.send(self.sync(json.dumps(
                [[revoked_time, access, refresh_time]])))

    def deauthorize(self, revoked_time, access, refresh_time):
        asyncio.run(self.send_deauthorize(revoked_time, access, refresh_time))

class ServerWS(Handshake):
    def __init__(self, db, cache=None, root_path=None,
                 access_timeout=3600*24, refresh_timeout=3600*24*90):
        super().__init__(root_path)
        self.db, self.cache, self.secondaries = db, cache, set()
        self.access_timeout = access_timeout
        self.refresh_timeout = refresh_timeout
        self.keypair()

    def refresh(self, auth):
        db = self.db.begin()
        cached = self.cache and self.cache.get(auth)
        if cached is None:
            timing = db.queryone(
                "SELECT access, authtime, refresh_time FROM active WHERE "
                "refresh=?", (auth,))
            if timing is None:
                return json.dumps([None, None])
            access, authtime, refresh_time = timing
        else:
            _, access, _, authtime, refresh_time = cached

        if self.refresh_timeout and int(
                time.time()) - authtime > self.refresh_timeout:
            return json.dumps([None, None])

        write, access, refresh_time = refresh_access(
            db, access, auth, refresh_time, self.access_timeout,
            cached is not None)

        if write:
            db.commit()
        db.close()

        return json.dumps([access, refresh_time])

    def broadcast(self, message):
        self.accept(message)
        websockets.broadcast(self.secondaries, message)

    async def primary(self, ws, init):
        self.broadcast(init)
        async for message in ws:
            self.broadcast(message)

    async def secondary(self, ws, init):
        self.timer(init)
        self.secondaries.add(ws)
        try:
            async for message in ws.recv():
                await ws.send(self.refresh(message))
        finally:
            self.secondaries.remove(ws)

    async def handler(self, ws):
        message = ws.recv()
        if len(message) == 0x28:
            await self.secondary(ws, message)
        else:
            await self.primary(ws, message)

    async def main(self):
        async with websockets.serve(self.handler, self.host, self.port):
            await asyncio.Future()

    def run(self):
        asyncio.run(self.main())

class ClientWS(Handshake):
    # TODO
    # connect to ws
    # send otp
    # concurrently, after sending otp, call update
    # maybe timeout after long silence and reconnect when a request hits
    # probably add versioning to messages/events to allow upgrades w/o downtime
    # create ws server for client flask BP to use for refreshing access tokens
    #     need one per thread though, maybe use multiprocessing to fork
    #     when the client interface is created in LoginBuilder subclass

    def __init__(self, base_url, db, cache=None, root_path=None):
        super.__init__(root_path)
        self.db, self.cache = db, cache
        self.url = lambda path, query=None: base_url + "/ws" + path + (
            "" if query is None else "?" + urllib.urlencode(query))
        self.public = self.load_public()
        self.key = type('fake_key', (), {"public_key": lambda: self.public})
        self.register_lobby(self.bp)

    def load_public(self):
        if os.path.exists(self.root_path("public.pem")):
            with open(self.root_path("public.pem"), 'rb') as fp:
                return serialization.load_pem_public_key(
                    fp.read(), crypto_default_backend())
        else:
            return self.verify(requests.post(
                self.url("/syn"), self.otp()).content)

    def notify(self, data):
        self.revoke(json.loads(json.loads(data)))

    def update(self):
        since = self.db.queryone("SELECT MAX(revoked_time) FROM revoked")
        data = requests.get(self.url("updates"), since or {"since": since[0]})
        self.revoke(json.loads(data))

    def revoke(self, info):
        # TODO: cache sync
        self.db.executemany(
            "INSERT INTO ignore(ref, revoked_time, access, refresh_time) "
            "VALUES (?, ?, ?, ?)", info)
