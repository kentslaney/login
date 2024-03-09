import flask, uuid, collections, urllib.parse, time

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from login import authorized
from store import RouteLobby

end_locals()

def ismember(db, user, group): # group can be a root last stack
    stack, parent = ([], (group,)) if isinstance(group, str) else (group, None)
    while parent is not None:
        stack.append(parent[0])
        parent = db.queryone(
            "SELECT parent_group FROM access_groups WHERE uuid=?", (stack[-1],))
    for superset in reversed(stack):
        permission = db.queryone(
            "SELECT user_groups.parent_group, limitations.until "
            "FROM user_groups LEFT JOIN limitations "
            "ON user_groups.parent_group=limitations.parent_group "
            "WHERE user_groups.member=? AND user_groups.access_group=? AND "
            "limitations.active=1", (user, superset))
        if permission is not None:
            if permission[1] is not None and permission[1] < time.time():
                db.execute(
                    "UPDATE limitations SET active=0 WHERE parent_group=?",
                    (permission[0],))
                db.commit()
            else:
                return (superset, permission[0])

GroupInfo = collections.namedtuple("GroupInfo", (
    "bind", "db", "owner", "sep"))

class AccessRouter(RouteLobby):
    pass

class AccessRoot(AccessRouter):
    def __init__(self, db, redirect):
        self.registered, self.groups = [], []
        self.redirect, self.db = redirect, db
        self.bp = flask.Blueprint(
            "modular_login_access", __name__, url_prefix="/access")
        self.bp.record(lambda setup_state: self.register(setup_state.app))
        self.register_lobby(self.bp)

    def register(self, app):
        self.registered.append(app)
        for group in self.groups:
            group.register(app)

    def __call__(self, ownership_method, owner_id, name, sep="."):
        return AccessGroup(name, GroupInfo(
            self.bind, self.db, (ownership_method, owner_id), sep))

    def bind(self, group):
        self.groups.append(group)
        for app in self.registered:
            group.register(app)

    @AccessRouter.route("/accept/<invite>")
    def accept(self, invite):
        if not authorized():
            return flask.redirect(
                self.redirect() + "?" + urllib.parse.urlencode(
                    {"next": flask.request.url}))
        user = flask.session["user"]
        db = self.db().begin()
        info = db.queryone(
            "SELECT inviter, access_group, acceptance_expiration, "
            "access_expiration, invitees, plus, depletes, depth, redirect "
            "FROM invitations WHERE uuid=?", (invite,))
        if info is None:
            db.close()
            flask.abort(410)
        remove = lambda x: db.execute(
            "DELETE FROM invitations WHERE uuid=?", (x,))
        now = time.time()
        if info[2] is not None and info[2] < now:
            remove(invite)
            db.commit().close()
            flask.abort(401)
        if info[4] is not None and info[4] == 0:
            db.close()
            flask.abort(404)
        if ismember(db, user, info[1]):
            db.close()
            flask.abort(400)
        else:
            child = info[0]
            while child is not None:
                parent = db.queryone(
                    "SELECT member, parent_group FROM user_groups "
                    "WHERE child_group=?", (child,))
                if parent is None:
                    break
                if parent[0] == user:
                    db.close()
                    flask.abort(412)
                child = parent[1]
        if info[4] is not None:
            lower, count, parent = invite, info[4], info[6]
            while count is not None:
                if count == 0:
                    db.commit()
                    db.close()
                    flask.abort(404)
                else:
                    db.execute(
                        "UPDATE invitations SET invitees=? WHERE uuid=?",
                        (count - 1, lower))
                if parent is None:
                    break
                else:
                    lower = parent
                    count, parent = db.queryone(
                        "SELECT invitees, depletes FROM invitations "
                        "WHERE uuid=?", (parent,))
        db.execute(
            "INSERT INTO user_groups(parent_group, member, access_group) "
            "VALUES (?, ?, ?)", (info[0], user, info[1]))
        until = info[3] and (info[3] if info[3] > 0 else now - info[3])
        depth = info[7] and (info[7] - 1)
        print(
            "INSERT INTO limitations"
            "(member, parent_group, until, spots, depletes, depth) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user, info[0], until, info[5], invite, depth))
        db.execute(
            "INSERT INTO limitations"
            "(member, parent_group, until, spots, depletes, depth) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user, info[0], until, info[5], invite, depth))
        db.commit().close()
        return flask.redirect(info[8])

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
            self.uuid = uniq
            if self.root:
                owner = db.queryone(
                    "SELECT uuid FROM auths WHERE method=? AND platform_id=?",
                    self.info.owner)
                if owner is None:
                    owner = str(uuid.uuid4())
                    db.execute(
                        "INSERT INTO auths(method, platform_id, uuid) "
                        "VALUES (?, ?, ?)", self.info.owner + (owner,))
                else:
                    owner = owner[0]
                db.execute(
                    "INSERT INTO "
                    "user_groups(parent_group, member, access_group) "
                    "VALUES (?, ?, ?)", (str(uuid.uuid4()), owner, self.uuid))
        else:
            self.uuid = access_id[0]
        db.commit().close()

    def contains(self, app, user):
        db = self.info.db(app).begin()
        res = ismember(db, user, [self.uuid])
        db.close()
        return res

    # TODO: strict ordering? (see Google Zanzibar)
    def vet(self, app, user):
        db = self.info.db(app).begin()
        res = ismember(db, user, tuple(reversed([i.uuid for i in self.stack])))
        db.close()
        return res
