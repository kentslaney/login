import collections

GroupInfo = collections.namedtuple("GroupInfo", ("bind", "db", "owner", "sep"))

# returns stack of access groups going upwards from init
# if extra is non empty, it also queries those columns
# if querying extra, expects init to be a tuple with those columns after
# if extra is empty, init can also be a string
# if init is a string, the output is flattened
# the last element will have None as the UUID
def access_stack(db, init, extra=()):
    parent = (init,) if isinstance(init, str) else init
    assert len(extra) + 1 == len(parent)
    stack, query = [parent], "".join(", " + i for i in extra)
    while parent[0] is not None:
        parent = db.queryone(
            f"SELECT parent_group{query} FROM access_groups WHERE uuid=?",
            (stack[-1][0],))
        stack.append(parent)
    return sum(stack, ()) if isinstance(init, str) else stack

# group can be a root last stack
# calls db.commit
def ismember(db, user, group):
    stack = access_stack(db, group) if isinstance(group, str) else group
    for superset in reversed(stack):
        permission = None if superset is None else db.queryone(
            "SELECT uuid, until FROM user_groups "
            "WHERE member=? AND access_group=? AND "
            "active=1 ORDER BY until DESC NULLS FIRST",
            (user, superset))
        if permission is not None:
            if permission[1] is not None and permission[1] < time.time():
                # deactivate if it's past access expiration
                db.execute(
                    "UPDATE user_groups SET active=0 WHERE uuid=?",
                    (permission[0],))
                db.commit()
            else:
                return (superset, permission[0])

class AccessGroup:
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

    def contains(self, app, user):
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

