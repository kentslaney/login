import collections, uuid, json

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from utils import OpShell

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

class AccessGroup(OpShell):
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
        db = self.info.db(app).ctx.begin()
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
                    "SELECT 1 FROM user_groups WHERE via IS NULL AND "
                    "until IS NULL AND spots IS NULL AND active=1 AND "
                    "member=? AND access_group=?", (owner, self.uuid)) is None
            if changed:
                db.execute(
                    "INSERT INTO user_groups(guild, member, access_group) "
                    "VALUES (?, ?, ?)", (str(uuid.uuid4()), owner, self.uuid))
        db.commit().close()

    def shallow(self, app, user):
        db = self.info.db(app).begin()
        res = ismember(db, user, [self.uuid])
        db.close()
        return res

    # TODO: strict ordering (see Google Zanzibar) using read/write decorators?
    def vet(self, app, user):
        db = self.info.db(app).begin()
        res = ismember(db, user, tuple(reversed([i.uuid for i in self.stack])))
        db.close()
        return res

    def __contains__(self, user):
        return bool(self.vet(None, user))

    def __truediv__(self, other):
        return AccessGroupRef(self.info.db, self.info.sep, None, self, other)

class AccessGroupRef(AccessGroup):
    def __init__(
            self, db, sep='/', access_id=None, source=None, *names,
            qualname=None):
        self.db, self.sep, self._name = db, sep, qualname
        self.info = GroupInfo(None, db, None, sep)
        assert access_id and not names or source and names or qualname
        self._uuid, self.source, self.names = access_id, source, names

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
            if self.source is not None:
                self._name = self.source.qualname + self.info.sep + \
                    self.info.sep.join(self.names)
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
            assert self._uuid is not None
            self._uuid = self._uuid[0]
        return self._uuid

    _stack = None
    @property
    def stack(self):
        if self._stack is None:
            if len(self.names) == 1:
                access_id = type("AccessRef", (), {"uuid": self.uuid})()
                self._stack = [access_id] + self.source.stack
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

    def __truediv__(self, other):
        if self.source is None or self._stack is not None:
            return AccessGroupRef(self.db, self.sep, None, self, other)
        return AccessGroupRef(
            self.db, self.sep, None, self.source, *(self.names + [other]))

    @classmethod
    def reconstruct(cls, db, rpn, sep='/'):
        def f(el):
            return cls(db, sep, qualname=el)
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

