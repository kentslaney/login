import collections, uuid, json

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from utils import InfoShell

end_locals()

GroupInfo = collections.namedtuple("GroupInfo", ("bind", "db", "owner", "sep"))

# returns stack of access groups going upwards from init
def access_stack(db, init, query, args=(), many=True):
    init = (init if " " in init or "(" in init else (init,)) \
        if type(init) is str else init
    init, select = ((), init) if type(init) is str else \
        (init, f"VALUES{','.join(('(?)',) * len(init))}")
    return db.many[many](
        "WITH RECURSIVE "
          "supersets(n) AS ("
            f"{select} "
            "UNION ALL "
            "SELECT parent_group FROM access_groups, supersets "
            "WHERE access_id=supersets.n"
          f") {query}", init + args, True)

# group can be a root last stack
def ismember(db, user, group, args=()):
    return access_stack(
        db, group, "SELECT guild, access_group FROM user_groups WHERE "
        "access_group IN supersets AND member=? AND active=1 AND "
        "(until IS NULL or until>unixepoch())", args + (user,), False)

class AccessGroup(InfoShell):
    def __init__(self, name, info, stack=None):
        self.info = info
        assert info.sep not in name
        self.name, self.uuid = name, None
        self.stack, self.root = (stack or []) + [self], not bool(stack)
        self.info.bind(self)

    def group(self, name):
        return __class__(name, self.info, self.stack)

    @property
    def qualname(self):
        return self.info.sep.join(i.name for i in self.stack)

    def __repr__(self):
        return self.qualname

    def register(self, app):
        db = self.db(app).begin()
        self.ensure(db)
        db.close()

    def ensure(self, db):
        if self.uuid is not None:
            return
        parent = None if self.root else self.stack[-2].uuid
        access = db.queryone(
            "SELECT parent_group, access_id FROM access_groups "
            "WHERE group_name=?", (self.qualname,), True)
        uniq = str(uuid.uuid4()) if access is None else access.access_id
        if access is None or access.parent_group != parent:
            # update if the access_group structure has changed
            db.execute(
                "INSERT INTO access_groups(group_name, parent_group, access_id)"
                "VALUES (?, ?, ?) ON CONFLICT(group_name) DO UPDATE SET "
                "parent_group=excluded.parent_group",
                (self.qualname, parent, uniq))
            self.uuid = uniq
        else:
            self.uuid = access.access_id

        if self.info.owner is not None and self.root:
            owner = db.queryone(
                "SELECT uuid FROM auths WHERE method=? AND platform_id=?",
                self.info.owner)
            if owner is None:
                owner = str(uuid.uuid4())
                db.execute(
                    "INSERT INTO auths(method, platform_id, uuid) "
                    "VALUES (?, ?, ?)", self.info.owner + (owner,))
                changed=True
            else:
                owner = owner[0]
                changed = db.queryone(
                    "SELECT 1 FROM user_groups LEFT JOIN invitations "
                    "ON via=invite WHERE until IS NULL AND spots IS NULL AND "
                    "user_groups.active=1 AND member=? AND access_group=? AND "
                    "deauthorizes=2", (owner, self.uuid)) is None
            if changed:
                invite = str(uuid.uuid4())
                db.execute(
                    "INSERT INTO invitations"
                    "(invite, accessing, inviter, depletes, deauthorizes) "
                    "VALUES (?, ?, NULL, FALSE, 2)", (invite, self.uuid))
                db.execute(
                    "INSERT INTO user_groups"
                    "(guild, via, member, access_group, spots) "
                    "VALUES (?, ?, ?, ?, NULL)",
                    (str(uuid.uuid4()), invite, owner, self.uuid))
        db.commit()

    def shallow(self, app, user):
        db = self.db(app).begin()
        res = ismember(db, user, [self.uuid])
        db.close()
        return res

    def db(self, app=None):
        return self.info.db() if app is None else self.info.db(app).ctx

    # TODO: strict ordering (see Google Zanzibar) using read/write decorators?
    def vet(self, user, app=None):
        db = self.db(app).begin()
        res = ismember(db, user, tuple(reversed([i.uuid for i in self.stack])))
        db.close()
        return res

    def __contains__(self, user):
        return bool(self.vet(user))

    def __truediv__(self, other):
        assert isinstance(other, str)
        return AccessGroupRef(self.info.db, self.info.sep, None, self, other)

    def add_user(self, user):
        guild = str(uuid.uuid4())
        self.db().execute(
            "INSERT INTO user_groups(guild, member, access_group) "
            "VALUES (?, ?, ?)", (guild, user, self.uuid))
        return guild

class AccessGroupRef(AccessGroup):
    def __init__(
            self, db, sep='/', access_id=None, source=None, *names,
            qualname=None, owner=None):
        self.db, self.sep, self._name = lambda *a, **kw: db(), sep, qualname
        self.info = GroupInfo(None, self.db, owner, sep)
        assert access_id and not names or names or qualname and not source
        self._uuid, self.source, self.names = access_id, source, names
        if self._name is not None:
            prefix = self._name.split(sep)
            if self.names:
                self._name = None
            self.names = tuple(prefix) + self.names

    def __contains__(self, user):
        if self.source is not None and self.names or self._name:
            return bool(ismember(
                self.db(), user,
                "SELECT access_id FROM access_groups WHERE group_name=?",
                (self.qualname,)))
        elif self._stack is None and self._uuid is not None:
            return bool(ismember(self.db(), user, self.uuid))
        else:
            return super().__contains__(user)

    @property
    def qualname(self):
        if self._name is None:
            if self.names:
                self._name = self.sep.join(self.names)
                if self.source is not None:
                    self._name = self.source.qualname + self.sep + self._name
            else:
                self._name = self.db().queryone(
                    "SELECT group_name FROM access_groups WHERE uuid=?",
                    (self.uuid,))
                assert self._name is not None
                self._name = self._name[0]
        return self._name

    @property
    def uuid(self):
        if self._uuid is None:
            self._uuid = self.db().queryone(
                "SELECT access_id FROM access_groups WHERE group_name=?",
                (self.qualname,))
            if self._uuid is not None:
                self._uuid = self._uuid[0]
        return self._uuid

    @uuid.setter
    def uuid(self, value):
        self._uuid = value
        if self._stack is not None:
            self._stack[0] = self.access_ref()

    access_ref = lambda self: type("AccessRef", (), {"uuid": self.uuid})()
    _stack = None
    @property
    def stack(self):
        if self._stack is None:
            if len(self.names) == 1 and self.source is not None:
                self._stack = [self.access_ref()] + self.source.stack
            elif self._uuid is None:
                self._stack = access_stack(
                    self.db(),
                    "SELECT access_id FROM access_groups WHERE group_name=?",
                    "SELECT n AS uuid FROM supersets", (self.qualname,))
                assert len(self._stack) > 0
                self._uuid = self._stack[0].uuid
            else:
                self._stack = access_stack(
                    self.db(), self.uuid, "SELECT n AS uuid FROM supersets")
        return self._stack

    _root = None;
    @property
    def root(self):
        if self._root is None:
            self._root = self.source is None and len(self.names) == 1
        return self._root

    def __truediv__(self, other):
        assert isinstance(other, str)
        if self.source is None or self._stack is not None:
            return __class__(self.db, self.sep, None, self, other)
        return __class__(
            self.db, self.sep, None, self.source, *(self.names + (other,)))

    @classmethod
    def reconstruct(cls, db, rpn, sep='/', owner=None):
        def f(el):
            return cls(db, sep, qualname=el, owner=owner)
        if isinstance(rpn, str):
            if '"' in rpn:
                rpn = json.loads(rpn)
            else:
                return f(rpn)
        assert isinstance(rpn, list)

        def inner(el):
            return [inner(i) if type(i) is list else f(i) for i in el[1:]]
        args = inner(rpn)
        return getattr(args[0], rpn[0])(*args[1:])

    def ensure(self, db=None):
        db, close = db or self.db().begin(), db is None
        if len(self.names) > 1:
            self.source = __class__(
                self.db, self.sep, None, self.source, *self.names[:-1],
                owner=self.info.owner)
            self.names = (self.names[-1],)
        if self.source is not None:
            self.source.ensure(db)
        super().ensure(db)
        if close:
            db.close()

