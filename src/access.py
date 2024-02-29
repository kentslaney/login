import flask, uuid

access_bp = flask.Blueprint(
    "modular_login_access", __name__, url_prefix="/access")

class AccessRoot:
    def __init__(self, bp):
        self.registered, self.groups = [], []
        bp.record(lambda setup_state: self.register(setup_state.app))

    def register(self, app):
        self.registered.append(app)
        for group in self.groups:
            group.register(app)

    def __call__(self, db):
        return AccessDB(db, self.bind)

    def bind(self, group):
        self.groups.append(group)
        for app in self.registered:
            group.register(app)

AccessRoot = AccessRoot(access_bp)

class AccessDB:
    def __init__(self, db, bind):
        self.bind, self.db, self.groups = bind, db, []

    def create(self, ownership_method, owner_id, name, sep="."):
        res = AccessGroup(
            name, (ownership_method, owner_id), self.db, self.bind, sep)
        self.groups.append(res)
        return res

class AccessGroup:
    def __init__(self, name, owner, db, bind, sep, stack=None):
        self.owner, self.db, self.bind = owner, db, bind
        assert sep not in name
        self.name, self.sep, self.uuid = name, sep, None
        self.stack, self.root = (stack or []) + [self], not bool(stack)
        self.bind(self)

    def group(self, name):
        return __class__(
            name, self.owner, self.db, self.bind, self.sep, self.stack)

    @property
    def qualname(self):
        return self.sep.join(i.name for i in self.stack)

    def register(self, app):
        db = self.db(app).ctx.begin()
        uniq = self.uuid or str(uuid.uuid4())
        parent = None if self.root else self.stack[-1].uuid
        access_id = db.queryone(
            "SELECT uuid FROM access_groups WHERE group_name=?",
            (self.qualname,))
        if access_id is None:
            db.execute(
                "INSERT INTO access_groups(group_name, parent_group, uuid) "
                "VALUES (?, ?, ?) ON CONFLICT(group_name) DO NOTHING",
                (self.qualname, parent, uniq))
        else:
            self.uuid = access_id[0]
            if self.root:
                owner = db.queryone(
                    "SELECT uuid FROM auths WHERE method=? AND platform_id=?",
                    self.owner)
                if owner is None:
                    owner = str(uuid.uuid4())
                    db.execute(
                        "INSERT INTO auths(method, platform_id, uuid) "
                        "VALUES (?, ?, ?)", self.owner + (owner,))
                else:
                    owner = owner[0]
                db.execute(
                    "INSERT INTO "
                    "user_groups(parent_group, member, access_group) "
                    "VALUES (?, ?, ?)", (str(uuid.uuid4()), owner, self.uuid))
        db.commit()

    def contains(self, app, user):
        return self.db(app).queryone(
            "SELECT parent_group FROM user_groups "
            "WHERE member=? AND access_group=?", (user, self.uuid))

    # TODO: strict ordering? (see Google Zanzibar)
    def vet(self, app, user):
        superset = None if self.root else self.stack[-1].vet(app, user)
        if superset is not None:
            return superset
        uniq = self.contains(app, user)
        return uniq and (self, uniq[0])
