import os.path, functools, collections

def relpath(*args):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), *args)

project_path = lambda *a: relpath("..", "..", *a)

from flask_caching.backends.memcache import MemcachedCache

# https://github.com/memcached/memcached/wiki/ConfiguringServer#unix-sockets
# remember TLS for all sensitive ISP traffic, see: MUSCULAR

# TODO: why does this seemingly work without the server running?
class ThreadedMemcached(MemcachedCache):
    def import_preferred_memcache_lib(self, servers):
        import libmc
        return libmc.ThreadedClient(servers, hash_fn=libmc.MC_HASH_FNV1_32)

def threaded_client(app, config, args, kwargs):
    return ThreadedMemcached.factory(app, config, args, kwargs)

import json

def dict_names(o):
    if hasattr(o, "_asdict"):
        o = o._asdict()
    if any(isinstance(o, i) for i in (list, tuple)):
        return tuple(dict_names(i) for i in o)
    if isinstance(o, dict):
        return {k: dict_names(v) for k, v in o.items()}
    return o

class RouteLobby:
    def __init__(self):
        self.routes = []

    def route(self, *a, **kw):
        def wrapper(f):
            self.routes.append((a, kw, f))
            return f
        return wrapper

    def register_lobby(self, bp, *fa, **fkw):
        for a, kw, f in self.routes:
            bp.route(*a, **kw)(
                functools.wraps(f)(functools.partial(f, *fa, **fkw)))

    def template_json(self, rule, template_path, prefix="/view", **routeargs):
        def decorator(f):
            def json_wrapper(*a, **kw):
                res = f(*a, **kw)
                if isinstance(res, flask.Response):
                    # TODO: not really implied, sort of a work around
                    if 300 <= res.status_code < 400:
                        flask.abort(401)
                    return res
                return json.dumps(dict_names(res))
            def template(*a, **kw):
                res = f(*a, **kw)
                if isinstance(res, flask.Response):
                    return res
                return flask.render_template(template_path, **res)

            json_wrapper.__name__ = f.__name__ + "_json"
            template.__name__ = f.__name__ + "_template"

            self.route(rule, **routeargs)(json_wrapper)
            self.route(prefix + rule, **routeargs)(template)
            return f
        return decorator

key_paths = (project_path("run"), project_path())
def secret_key(paths = key_paths):
    for path in paths:
        file = os.path.join(path, "secret_key")
        if os.path.exists(file):
            with open(file, "rb") as f:
                return f.read()

    os.makedirs(paths[0], exist_ok=True)
    with open(os.path.join(paths[0], "secret_key"), "wb") as f:
        secret = os.urandom(24)
        f.write(secret)
    return secret

import math

class CompressedUUID:
    compressed = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    base16 = "0123456789abcdef"
    # [i for i, j in enumerate(str(uuid.uuid4())) if j == '-']
    dashes = [8, 13, 18, 23]

class CompressedUUID(CompressedUUID):
    length = math.ceil(math.log(16 ** 32) / math.log(
        len(CompressedUUID.compressed)))

    @staticmethod
    def rebase(value, inbase, outbase):
        output = []
        for remainder in value:
            for digit in range(len(output)):
                remainder = inbase * output[digit] + remainder
                output[digit] = remainder % outbase
                remainder = remainder // outbase
            while remainder:
                output.append(remainder % outbase)
                remainder = remainder // outbase
        return output[::-1]

    @classmethod
    def translate(cls, value, inalphabet, outalphabet):
        rebased = cls.rebase(map(lambda x: inalphabet.index(x), value),
            len(inalphabet), len(outalphabet))
        return "".join(map(lambda x: outalphabet[x], rebased))

    @classmethod
    def fromUUID(cls, strUUID):
        b16str = strUUID.replace('-', '')
        small = cls.translate(b16str, cls.base16, cls.compressed)
        return small.rjust(cls.length, cls.compressed[0])

    @classmethod
    def toUUID(cls, short):
        b16str = cls.translate(short, cls.compressed, cls.base16)
        for i in cls.dashes:
            b16str = b16str[:i] + "-" + b16str[i:]
        return b16str

    @classmethod
    def possible(cls, unknown):
        return len(unknown) == cls.length and all(
            i in cls.compressed for i in unknown)

# ensures that json value matches template given
# templates with one list element can be an arbitrary length
# templates with multiple list elements must have the elements match
# dictionaries are turned into `namedtuple`s sorted alphabetically
# templates with sets are considered enums, and value must be in that set
# other than a nested set, sets can contain all the other kinds of templates
# otherwise, the type of the value must match the type given in template
def data_payload(value, template, parsed=True):
    def oxford_comma(terms):
        return " and ".join(terms) if len(terms) < 3 else \
            ", ".join(terms[:-1]) + ", and " + terms[-1]

    def ensure(payload, template, qualname=""):
        part_name = f"payload" + qualname
        requires = template if type(template) == type else type(template)
        if requires == set:
            assert len(template) > 0
            flag, has = type('flag', (), {})(), type(payload)
            it = ((flag, i) if type(i) == type else (i, flag) for i in template)
            values, types = map(lambda x: set(x).difference({flag}), zip(*it))
            if has in set(map(type, values)).intersection({dict, list}):
                for option in (i for i in values if type(i) == has):
                    try:
                        return ensure(payload, option, qualname)
                    except:
                        pass
            elif has in types or payload in values:
                return payload
            raise Exception(f"{part_name} has invalid value for enum")
        if not isinstance(payload, requires):
            raise Exception(f"{part_name} should be {requires}")
        if requires == dict:
            if template.keys() != payload.keys():
                given, needed = set(payload.keys()), set(template.keys())
                missing = oxford_comma(needed.difference(given))
                extra = oxford_comma(given.difference(needed))
                # one value can not be both missing and extra
                xor = {missing: "is missing ", extra: "should not contain "}
                message = part_name + " " + " and ".join(
                    v + k for k, v in xor.items() if k)
                raise Exception(message)
            ordered_names = tuple(sorted(template.keys()))
            obj = collections.namedtuple(
                part_name.replace(".", "__"), ordered_names)
            return obj(**{
                k: ensure(payload[k], template[k], qualname + f".{k}")
                for k in ordered_names})
        elif requires == list:
            idx = (lambda i: 0) if len(template) == 1 else (lambda i: i)
            return [
                ensure(v, template[idx(i)], qualname + f"_{i}")
                for i, v in enumerate(payload)]
        else:
            return payload

    if parsed:
        payload = value
    else:
        try:
            payload = json.loads(value)
        except json.decoder.JSONDecodeError:
            flask.abort(415, description="invalid JSON")
    try:
        return ensure(payload, template)
    except Exception as e:
        # raise e
        flask.abort(400, description=e.args[0])

