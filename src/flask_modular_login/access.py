import flask, uuid, collections, urllib.parse, time

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from login import authorized
from store import RouteLobby

end_locals()

def access_stack(db, init, extra=()):
    stack, parent = [], (init,) if isinstance(init, str) else init
    assert len(extra) + 1 == len(parent)
    query = "".join(", " + i for i in extra)
    while parent is not None:
        stack.append(parent)
        parent = db.queryone(
            f"SELECT parent_group{query} FROM access_groups WHERE uuid=?",
            (stack[-1][0],))
    return list(zip(*stack)) if isinstance(init, str) else stack

def ismember(db, user, group): # group can be a root last stack
    stack = access_stack(db, group) if isinstance(group, str) else group
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

    # TODO: the group doesn't need an owner if all invites are API calls
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
        now = time.time()
        # invite hasn't expired
        if info[2] is not None and info[2] < now:
            db.execute("DELETE FROM invitations WHERE uuid=?", (invite,))
            db.commit().close()
            flask.abort(401)
        # can't accept the same invite twice
        accepted = db.queryone(
            "SELECT EXISTS(SELECT 1 FROM limitations "
            "WHERE member=? AND depletes=? LIMIT 1)",
            (user, invite))
        if accepted[0]:
            db.close()
            flask.abort(400)
        # can't accept your own invite
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
        # lower depletions
        if info[4] is not None:
            lower, count, parent = invite, info[4], info[6]
            while count is not None:
                if count == 0:
                    # none left, don't execute depletions
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
        db.execute(
            "INSERT INTO limitations"
            "(member, parent_group, until, spots, depletes, depth) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user, info[0], until, info[5], invite, depth))
        db.commit().close()
        return flask.redirect(info[8])

    group_query=(
        "SELECT user_groups.access_group, user_groups.child_group, "
        "user_groups.parent_group, until, spots, depletes, depth "
        "FROM limitations LEFT JOIN user_groups "
        "ON limitations.member=user_groups.member "
        "AND limitations.parent_group=user_groups.parent_group "
        "WHERE active=1 AND ")
    info_keys = (
        "access_group", "child_group", "parent_group", "until", "spots",
        "depletes", "depth", "depletion_bound", "subgroups")

    @staticmethod
    def depletion_bound(count, parent, db):
        minimum = count
        while parent is not None:
            count, parent = db.queryone(
                "SELECT invitees, depletes FROM invitations "
                "WHERE uuid=?", (parent,))
            if count is not None:
                minimum = count if minimum is None else min(count, minimum)
        return minimum

    def user_groups(self, user=None, db=None):
        user = user or flask.session["user"]
        db, close = db or self.db().begin(), db is None
        info = db.queryall(self.group_query + "user_groups.member=?", (user,))
        for option in info:
            option.append(self.depletion_bound(option[4], option[5]), db)
            access = db.queryone(
                "SELECT group_name FROM access_groups WHERE uuid=?", (info[0],))
            access = [[info[0], access]]
            subgroups = access
            while access:
                children = []
                for parent, _ in access:
                    children += db.queryall(
                        "SELECT uuid, group_name FROM access_groups "
                        "WHERE parent_group=?", (parent,))
                access = children
                subgroups += access
            option.append(subgroups)
        if close:
            db.close()
        return [dict(zip(self.info_keys, option)) for option in info]

    def group_access(self, group, user=None, db=None):
        user = user or flask.session["user"]
        db, close = db or self.db().begin(), db is None
        group_name = db.queryone(
            "SELECT group_name FROM access_group WHERE uuid=?", (group,))
        stack = access_stack(db, (group, group_name), ("group_name",))
        query = " OR ".join(("user_groups.access_group=?",) * len(stack))
        info = db.queryall(
            self.group_query + "(" + query + ")", stack)
        for option in info:
            option.append(self.depletion_bound(option[2], option[4], db))
            option.append(list(reversed(stack[:stack.index(option[0]) + 1])))
        if close:
            db.close()
        return info

    @AccessRouter.route("/invite")
    @AccessRouter.route("/invite/<group>")
    def invite(self, group=None):
        ...

    # TODO: invitation page
    # TODO: creation API endpoint
    # TODO: access group deauthorization

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
