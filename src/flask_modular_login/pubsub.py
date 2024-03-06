import flask, os.path, time, ssl, requests
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import (
    default_backend as crypto_default_backend)

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from store import project_path, RouteLobby, secret_key

end_locals()

# custom made protocol; approach with skepticism
class HandshakeTLS:
    _ssl = None
    signing_params = (padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    otp_timeout_ms = 5000

    def __init__(self, root_path=project_path("run")):
        self.root_path = lambda *a: os.path.join(root_path, *a)

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

    # server: proves it has the shared secret and private key
    def otp(self):
        message = int(time.time()*10**3).to_bytes(8, 'big')
        h = hmac.HMAC(self.secret, hashes.SHA256())
        h.update(message)
        return message + h.finalize() + self.key.sign(
            message, *self.signing_params)

    # client: verifies the server has the shared secret
    #         proves that it has the shared secret
    def sign(self, otp):
        h = hmac.HMAC(self.secret, hashes.SHA256())
        g = h.copy()
        h.update(otp[:8])
        h.verify(otp[8:0x20])
        g.update(otp)
        return otp + g.finalize()

    # server: verifies the OTP is still valid
    #         verifies the OTP was signed by the private key
    #         verifies the client has the shared secret
    #         sends the public key encrypted with the shared secret
    def verify(self, reply):
        start, proof, signature = (reply[:8], reply[0x20:0x128], reply[0x128:])
        rtt = time.time() - int.from_bytes(start)
        assert rtt < self.otp_timeout_ms, "otp timeout"
        self.key.public_key().verify(proof, start, *self.signing_params)
        h = hmac.HMAC(self.secret, hashes.SHA256())
        h.update(reply[:0x128])
        h.verify(signature)
        return reply + AESGCM(self.secret).encrypt(
            reply, self.serialized_public(self.key.public_key()))

    # client: decrypts the public key with the shared secret
    def decode(self, reply):
        serialized = AESGCM(self.secret).decrypt(reply[:0x228], reply[0x228:])
        with open(self.root_path("public.pem"), "wb") as fp:
            fp.write(serialized)

    # technically unnecessary since the ssl context confirms it anyways
    # returning client: confirms the OTP was signed by the same private key
    def confirm(self, otp):
        start, proof = (otp[:8], otp[0x20:0x128])
        with open(self.root_path("public.pem"), "rb") as fp:
            key = serialization.load_pem_public_key(
                fp.read(), crypto_default_backend())
        key.verify(proof, start, *self.signing_params)

    def ssl_context(self, fname):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations(self.root_path(fname))
        return ssl_context

    @property
    def ctx(self):
        return self.ssl_context(self._ssl)

class HandshakeRouter(RouteLobby):
    pass

class HandshakeBP(HandshakeTLS, HandshakeRouter):
    _ssl = "private.pem"

    def __init__(self):
        super().__init__()
        self.bp = flask.Blueprint("wss_handshake", __name__, url_prefix="/wss")
        self.register_lobby(self.bp)
        self.keypair()

    @HandshakeRouter.route("/syn")
    def syn(self):
        return self.otp()

    @HandshakeRouter.route("/establish", methods=["POST"])
    def establish(self):
        try:
            return self.verify(flask.request.data)
        except:
            flask.abort(400)

class ClientTLS(HandshakeTLS):
    _ssl = "public.pem"

    def __init__(self, base_url):
        super.__init__()
        self.url = lambda path: base_url + "/wss" + path
        self.load_public()

    def load_public(self):
        otp = requests.get(self.url("/syn")).content
        if os.path.exists(self.root_path("public.pem")):
            self.confirm(otp)
        else:
            self.decode(requests.post(
                self.url("/establish"), self.sign(otp)).content)
