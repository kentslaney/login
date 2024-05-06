import os.path, functools, collections, flask

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
def secret_key(paths = key_paths, key_name="login_secret_session_key"):
    if isinstance(paths, str):
        paths = (paths,)
    for path in paths:
        file = os.path.join(path, key_name)
        if os.path.exists(file):
            with open(file, "rb") as f:
                return f.read()

    os.makedirs(paths[0], exist_ok=True)
    with open(os.path.join(paths[0], key_name), "wb") as f:
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

class OpShell:
    _op_on, _op, _op_args = None, None, ()

    symbols = (
        ("_and", lambda l, r: f"({l} AND {r})"),
        ("_or", lambda l, r: f"({l} OR {r})"),
        ("_xor", lambda l, r: f"({l} XOR {r})"),
        ("_invert", lambda x: f"NOT {x}"),
    )

    @property
    def _shell(self):
        return __class__

    def __init__(self, this=None, op=None, *a):
        self._op_on, self._op, self._op_args = this, op, a
        self._op_symbols = {
            getattr(self.__class__, k): v for k, v in self.symbols}

    @property
    def _on(self):
        return self if self._op_on is None else self._op_on

    def __contains__(self, user):
        return bool(self.generic("__contains__")(user))

    def __getattr__(self, name):
        return self.generic(name)

    def generic(self, f, *a, **kw):
        if self._op is None:
            assert getattr(self._on.__class__, f, None) != getattr(
                self._shell, f, None)
        def wrapper(*a, **kw):
            if self._op is None:
                return getattr(self._on, f)(*a, **kw)
            return self._op(f, *self._op_args, *a, **kw)
        return functools.wraps(f)(wrapper)

    def __pos__(self):
        return abs(self) if self._op is None else self

    def __neg__(self):
        return self if self._op is None else abs(self)

    def __abs__(self):
        return self._shell(self, self._op, *self._op_args)

    def _and(self, f, other, *a, **kw):
        return getattr(self, f)(*a, **kw) and getattr(other, f)(*a, **kw)

    def __and__(self, other):
        return self._shell(self, self._and, other)

    def __iand__(self, other):
        this = +self
        this._op, this._op_args = (-this)._and, (other,)
        return this

    def _or(self, f, other, *a, **kw):
        return getattr(self, f)(*a, **kw) or getattr(other, f)(*a, **kw)

    def __or__(self, other):
        return self._shell(self, self._or, other)

    def __ior__(self, other):
        this = +self
        this._op, this._op_args = (-this)._or, (other,)
        return this

    def _xor(self, f, other, *a, **kw):
        return bool(
            getattr(self, f)(*a, **kw) ^ getattr(other, f)(*a, **kw))

    def __xor__(self, other):
        return self._shell(self, self._xor, other)

    def __ixor__(self, other):
        this = +self
        this._op, this._op_args = (-this)._xor, (other,)
        return this

    def _invert(self, *a, **kw):
        return not getattr(self, f)(*a, **kw)

    def __invert__(self):
        return self._shell(self, self._invert)

    def __repr__(self):
        if self._op is None:
            return super().__repr__() if self._on is self else repr(self._on)
        return self._op_symbols[self._op.__func__](
            repr(self._on), *map(repr, self._op_args))

    def rpn(self):
        if self._op is None:
            return super().__str__() if self._on is self else str(self._on)
        return [
            f"__{self._op.__func__.__name__.replace('_', '')}__",
            *map(lambda x: x.rpn(), [self._on, *self._op_args])]

    def __str__(self):
        return json.dumps(self.rpn())

class FlatInfo(tuple):
    pass

class InfoShell(OpShell):
    @property
    def _shell(self):
        return __class__

    def __init__(self, this=None, op=None, *a):
        # TODO: could be distributive
        assert op.__func__.__name__ == "_add" or (
            this._op is None or this._op.__func__.__name__ != "_add") and (
            not a or a[0]._op is None or
            a[0]._op.__func__.__name__ != "_add")
        self.symbols += ("_add", lambda l, r: f"({l} ADD {r})"),
        super().__init__(this, op, *a)

    def _add(self, f, other, *a, **kw):
        res = (getattr(self, f)(*a, **kw), getattr(other, f)(*a, **kw))
        return FlatInfo(
            j for i in res for j in (i if isinstance(i, FlatInfo) else (i,)))

    def __add__(self, other):
        return self._shell(self, self._add, other)

    def __iadd__(self, other):
        this = +self
        this._op, this._op_args = (-this)._add, (other,)
        return this

class OpShellTest(OpShell):
    def __init__(self, lo, hi):
        self.lo, self.hi = lo, hi

    def __contains__(self, value):
        return self.lo <= value <= self.hi

    def test(self, x):
        return x not in self

    def __repr__(self):
        return f"{self.lo} to {self.hi}"

# a = OpShellTest(2, 3) & OpShellTest(3, 4)
# b = OpShellTest(2, 3) | OpShellTest(3, 4)
# c = OpShellTest(7, 8)
# d = c
# d |= a

def endpoint_next(endpoint, redirect=None):
    return endpoint + "?" + urllib.parse.urlencode(
        {"next": redirect or flask.request.url})

