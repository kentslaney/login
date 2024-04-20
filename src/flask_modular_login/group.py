import collections

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from utils import OpShell

end_locals()

GroupInfo = collections.namedtuple("GroupInfo", ("bind", "db", "owner", "sep"))

# returns stack of access groups going upwards from init
# if extra is non empty, it also queries those columns
# if querying extra, expects init to be a tuple with those columns after
# if extra is empty, init can also be a string
# if init is a string, the output is flattened
# the last element will have None as the UUID
def access_stack(db, init, query, args=(), many=True):
    return db.many[many](
        "WITH RECURSIVE "
          "supersets(n) AS ("
            "VALUES(?) "
            "UNION ALL "
            "SELECT parent_group FROM access_groups, supersets "
            "WHERE uuid=supersets.n"
          f") {query}", (init,) + args, True)

# group can be a root last stack
# calls db.commit
def ismember(db, user, group):
    return access_stack(
        db, group, "SELECT uuid, access_group FROM user_groups WHERE "
        "access_group IN supersets AND member=? AND active=1 AND "
        "(until IS NULL or until>unixepoch())", (user,), False)

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
            "SELECT parent_group, uuid FROM access_groups WHERE group_name=?",
            (self.qualname,), True)
        uniq = str(uuid.uuid4()) if access is None else access.uuid
        if access is None or access.parent_group != parent:
            # update if the access_group structure has changed
            db.execute(
                "INSERT INTO access_groups(group_name, parent_group, uuid) "
                "VALUES (?, ?, ?) ON CONFLICT(group_name) DO UPDATE SET "
                "parent_group=excluded.parent_group",
                (self.qualname, parent, uniq))
            self.uuid = uniq
        else:
            self.uuid = access.uuid

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
                    "SELECT 1 FROM user_groups WHERE parents_group IS NULL AND "
                    "until IS NULL AND spots IS NULL AND active=1 AND "
                    "member=? AND access_group=?", (owner, self.uuid)) is None
            if changed:
                db.execute(
                    "INSERT INTO "
                    "user_groups(uuid, member, access_group) "
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

