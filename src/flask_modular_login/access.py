import flask, uuid, collections, urllib.parse, time, json

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
            "SELECT limitations.users_group, limitations.until "
            "FROM user_groups LEFT JOIN limitations "
            "ON user_groups.child_group=limitations.users_group "
            "WHERE user_groups.member=? AND user_groups.access_group=? AND "
            "limitations.active=1", (user, superset))
        if permission is not None:
            if permission[1] is not None and permission[1] < time.time():
                db.execute(
                    "UPDATE limitations SET active=0 WHERE users_group=?",
                    (permission[0],))
                db.commit()
            else:
                return (superset, permission[0])

def descendants(db, queries):
    results = []
    children = queries if type(queries) not is str else db.queryall(
        "SELECT child_group FROM user_groups WHERE member=?", (queries,), True)
    while children:
        children = db.queryall(
            "SELECT parents_group, child_group, member, access_group " +
            "FROM user_groups WHERE parents_group IN (" +
            ", ".join(("?",) * len(children)) +
            ")", filter(None, [child.child_group for child in children]), True)
        results += children
    return results

def isdescendant(db, user, parents_group):
    while parents_group:
        parent = db.queryone(
            "SELECT member, parents_group FROM user_groups WHERE child_group=?",
            (parents_group,), True)
        if parent is None:
            return None
        if parent.member == user:
            return parents_group
        parents_group = parent.parents_group

def json_payload(self, value, template):
    def oxford_comma(terms):
        return " and ".join(terms) if len(terms) < 3 else \
            ", ".join(terms[:-1]) + ", and " + terms[-1]

    def ensure(payload, template, qualname=""):
        part_name = f"payload" + (qualname or "_part_" + {qualname[1:]})
        requires = payload if type(payload) == type else type(template)
        if requires == set:
            if payload not in template:
                flask.abort(flask.Response("invalid enum", code=400))
            return payload
        if not isinstance(template, requires):
            flask.abort(flask.Response(
                f"payload should be {requires}", code=400))
        if requires == dict:
            if template.keys() != payload.keys():
                given, needed = set(payload.keys()), set(template.keys())
                missing = oxford_comma(needed.difference(given))
                extra = oxford_comma(given.difference(needed))
                xor = {missing: "is missing ", extra: "should not contain "}
                message = part_name + " " + " and ".join(
                    v + k for k, v in xor if k)
                flask.abort(flask.Response(message, code=400))
            ordered_names = tuple(sorted(template.keys()))
            obj = collections.namedtuple(part_name, ordered_names)
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

    try:
        payload = json.loads(value)
    except json.decoder.JSONDecodeError:
        flask.abort(flask.Response("invalid JSON", code=400))
    return ensure(payload, template)

GroupInfo = collections.namedtuple("GroupInfo", ("bind", "db", "owner", "sep"))

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

    def __call__(self, name, ownership_method=None, owner_id=None, sep="."):
        assert (ownership_method is None) == (owner_id is None)
        owner = owner_id and (ownership_method, owner_id)
        return AccessGroup(name, GroupInfo(self.bind, self.db, owner, sep))

    def bind(self, group):
        self.groups.append(group)
        for app in self.registered:
            group.register(app)

    def authorize(self):
        # repeated from LoginBuilder
        if not authorized():
            if flask.request.method == "GET":
                return flask.redirect(
                    self.redirect() + "?" + urllib.parse.urlencode(
                        {"next": flask.request.url}))
            flask.abort(401)
        return flask.session["user"]

    @AccessRouter.route("/accept/<invite>")
    def confirm(self):
        ...

    @AccessRouter.route("/add/<invite>")
    def accept(self, invite, db=None, implied=False):
        user = self.authorize()
        db = db or self.db().begin()
        info = db.queryone(
            "SELECT inviter, access_group, acceptance_expiration, access_limit,"
            "access_expiration, invitees, plus, depletes, dos, deauthorizes, "
            "implies, implied, redirect FROM invitations WHERE uuid=?",
            (invite,), True)
        if info is None:
            db.close()
            flask.abort(410)
        if info.implied == 1 and not implied:
            db.close()
            flask.abort(400)
        now = time.time()
        # invite hasn't expired
        if info.access_expiration is not None and info.access_expiration < now:
            db.close()
            self.db().execute("DELETE FROM invitations WHERE uuid=?", (invite,))
            flask.abort(401)
        # can't accept the same invite twice
        accepted = db.queryone(
            "SELECT EXISTS(SELECT 1 FROM limitations "
            "WHERE member=? AND via=? LIMIT 1)", (user, invite))
        if accepted[0]:
            db.close()
            flask.abort(400)
        # can't accept your own invite
        child = info.inviter
        while child is not None:
            parent = db.queryone(
                "SELECT member, parents_group FROM user_groups "
                "WHERE child_group=?", (child,))
            if parent is None:
                break
            if parent[0] == user:
                db.close()
                flask.abort(412)
            child = parent[1]
        # lower depletions
        if info.invitees is not None:
            lower, count, parent = invite, info.invitees, info.depletes
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
                    # FK implies unpackable
                    count, parent = db.queryone(
                        "SELECT invitees, depletes FROM invitations "
                        "WHERE uuid=?", (parent,))
        child_group = str(uuid.uuid4())
        db.execute(
            "INSERT INTO user_groups(parents_group, child_group, member, "
            "access_group) VALUES (?, ?, ?, ?)",
            (info.inviter, child_group, user, info.access_group))
        until = info.access_expiration
        if until is not None and until < 0:
            until = min(now + until, info.access_limit)
        dos = info.dos and (info.dos - 1)
        db.execute(
            "INSERT INTO limitations(users_group, until, spots, via, "
            "depletes, dos, deauthorizes) VALUES (?, ?, ?, ?, ?, ?, ?)", (
                child_group, until, info.plus, invite,
                info.depletes is not None, dos, info.deauthorizes))
        if info.implies is not None:
            return self.accept(info.implies, db, True)
        db.commit().close()
        return flask.redirect(info.redirect)

    # selecting columns needed to know what invites selected can create
    group_query=(
        "SELECT access_group, child_group, parents_group, member, "# user_groups
        "until, spots, via, depletes, dos, deauthorizes "# limitations
        "FROM limitations LEFT JOIN user_groups "
        "ON limitations.users_group=user_groups.child_group "
        "WHERE active=1 AND ")
    access_info = collections.namedtuple("AccessInfo", (
        "access_group", "child_group", "parents_group", "member", "until",
        "spots", "depletes", "dos", "deauthorizes", "depletion_bound",
        "implied_groups"))

    @staticmethod
    def depletion_bound(count, parent, depletes, db):
        if not depletes:
            return count
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
        results, info = [], db.queryall(
            self.group_query + "user_groups.member=?", (user,), True)
        access_names = {} if len(info) == 0 else dict(db.queryall(
            "SELECT uuid, group_name FROM access_groups WHERE uuid IN (" +
            ", ".join(("?",) * len(info)) + ")",
            [option.access_group for option in info]))
        for option in info:
            access = [[option.access_group, access_names[option.access_group]]]
            subgroups = access
            while access:
                children = []
                for parent, _ in access:
                    children += db.queryall(
                        "SELECT uuid, group_name FROM access_groups "
                        "WHERE parent_group=?", (parent,))
                access = children
                subgroups += access
            results += option + (self.depletion_bound(
                option.spots, option.via, option.depletes, db), subgroups)
        if close:
            db.close()
        return [self.access_info(*option) for option in results]

    def group_access(self, groups, db=None):
        db, close = db or self.db().begin(), db is None
        group_names = db.queryall(
            "SELECT uuid, group_name FROM access_group WHERE uuid IN (" +
            ", ".join(("?",) * len(groups)) + ")", groups)
        if len(group_name) != len(groups):
            db.close()
            flask.abort(400)
        stack = {}
        for group in group_names:
            stack[group[0]] = access_stack(db, group, ("group_name",)))
        uniq = set(sum(list(zip(*stack.values()))[0], []))
        info = db.queryall(
            self.group_query + "user_groups.access_group IN (" + ", ".join(
                ("?",) * len(uniq)) + ")", tuple(uniq), True)
        results = [self.access_info(
            *option, self.depletion_bound(
                option.spots, option.via, option.depletes, db),
            stack[option.access_group]) for option in info]
        if close:
            db.close()
        return results

    @AccessRouter.route("/invite")
    @AccessRouter.route("/invite/<group>")
    def invite(self, group=None):
        ...

    creation_args = {
        "redirect": str,
        "confirm": bool,
        "invitations": [{
            "access_group": str,
            "acceptance_expiration": int,
            "access_expiration": int,
            "invitees": int,
            "plus": int,
            "via": str,
            "depletes": bool,
            "dos": int,
            "deauthorizes": {0, 1, 2},
        }]}

    @AccessRouter.route("/allow", methods=["POST"])
    def create(self):
        user = self.authorize()
        payload = json_payload(flask.request.body, self.creation_args)
        db = self.db().begin()
        if len(payload.invitations) == 0:
            db.close()
            flask.abort(flask.Response("no invites", code=400))
        if not payload.redirect:
            db.close()
            flask.abort(flask.Response("bad redirect", code=400))
        values, first = [], (i == 0 for i in range(len(payload.invitations)))
        current_uuid, next_uuid = uuid.uuid4(), None
        for invite, last in reversed(zip(payload.invitations, first)):
            # user accepted via
            # via has access to group (limitations.active = 1)
            limits = db.queryone(
                "SELECT until, spots, depletes, dos, deauthorizes "
                "FROM limitations LEFT JOIN user_groups "
                "ON limitations.users_group=user_groups.child_group "
                "WHERE via=? AND user_groups.member=? AND active=1",
                (invite.via, user), True)
            if limits is None:
                db.close()
                flask.abort(flask.Response("invalid source", code=401))
            # acceptance expiration and access expiration are before until
            #     (negative values for access expiration are after acceptance)
            #     (limited by access_limit)
            if invite.acceptance_expiration > limits.until or \
                    invite.access_expiration > limits.until:
                db.close()
                flask.abort(flask.Response("invalid timing", code=400))
            # invitees is less than or equal to depletion bound
            if invite.invitees > self.depletion_bound(
                    limits.spots, invite.via, limits.depletes, db):
                db.close()
                flask.abort(flask.Response("too many invitees", code=400))
            # plus < spots
            if invite.plus >= limits.spots:
                db.close()
                flask.abort(flask.Response("too many plus ones", code=400))
            # 0 < dos < limits.dos
            if not 0 < invite.dos < limits.dos:
                db.close()
               flask.abort(flask.Response(
                   "invalid degrees of separation", code=400))
            # invite deauthorizes <= limitations.deauthorizes
            if invite.deauthorizes > limits.deauthorizes:
                db.close()
                flask.abort(flask.Response("can't deauthorize", code=401))
            # depletes <= limits.depletes
            if invite.depletes is None and limits.deplets is not None:
                db.close()
                flask.abort(flask.Response("must deplete", code=401))
            redirect = next_uuid and payload.redirect
            current_uuid, next_uuid = uuid.uuid4(), current_uuid
            implied = (-1 if payload.confirm else 0) if last else 1
            values.append(invite.limits + (
                limits.until, implied, redirect, current_uuid, next_uuid))
        try:
            db.executemany(
                "INSERT INTO invitations(" +
                ", ".join(payload.invitations[0]._fields) +
                ", access_limit, implied, redirect, uuid, implies) VALUES (" +
                ", ".join(("?",) * (len(payload.invitations[0]) + 5)) +
                ")", values)
            return current_uuid
        finally:
            try:
                db.commit()
            finally:
                db.close()

    removal_args = [{
            "invitation": str,
            "member": str,
        }]

    @AccessRouter.route("/revoke", methods=["POST"])
    def revoke(self):
        user = self.authorize()
        payload = json_payload(flask.request.body, self.removal_args)
        db = self.db().begin()
        access_groups = dict(db.queryall(
            "SELECT uuid, access_group FROM invitations WHERE uuid IN (" +
            ", ".join(("?",) * len(payload)) + ")",
            [revoking.invitation for revoking in payload]))
        for revoking in payload:
            access_group = access_groups.get(revoking.invitation)
            if access_group is None:
                flask.abort(400)
            stack = access_stack(db, access_group[0])
            privledges = db.queryone(
                "SELECT MAX(SELECT deauthorizes FROM limitations " +
                "LEFT JOIN user_groups " +
                "ON limitations.users_group=user_groups.child_group " +
                "WHERE user_groups.member=? AND user_groups.access_group IN (" +
                ", ".join(("?",) * len(stack)) + "))", stack)
            if privledges is None or privledges[0] == 0:
                db.close()
                flask.abort(401)
            if privledges[1] == 1:
                users_group = db.queryone(
                    "SELECT users_group FROM limitations WHERE member=? AND "
                    "via=?", (revoking.member, revoking.invitation))
                if users_group is None
                    db.close()
                    flask.abort(401)
                parents_group = isdescendant(db, user, users_group[0])
                while parents_group:
                    access = db.queryone(
                        "SELECT deauthorizes FROM limitations "
                        "WHERE users_group=?", (parents_group,))
                    if access is not None and access[0] == 1:
                        break
                    parents_group = isdescendant(db, user, parents_group)
                if not parents_group:
                    db.close()
                    flask.abort(401)
        db.executemany(
            "UPDATE limitations SET active=0 FROM user_groups "
            "WHERE users_group=child_group AND via=? AND member=?",
            [(revoking.invitation, revoking.member) for revoking in payload])
        db.execute().close()

    deauth_info = collections.namedtuple("Deauthable", (
        "member", "invite", "access_group", "group_name"))

    # returns member, access_group, group_name, invite
    def deauthable(self, user, db=None):
        db = db or self.db().begin()
        groups = self.user_groups(user, db)
        permissions = [[], [], []]
        for group in groups:
            permissions[group.deauthorizes].append(group)
        # permissions[1] access_group, group_name (descendants all in implied)
        # member, access_group, child_group
        childrens_groups = descendants(db, [
            group.child_group for group in permissions[1]])
        # users_group, invite
        childrens_invites = [] if len(childrens_groups) == 0 else db.queryall(
            "SELECT users_group, via FROM limitations WHERE active=1 AND "
            "users_group IN (" + ", ".join(("?",) * len(childrens_groups)) +
            ")", [group.child_group for group in childrens_groups], True)
        # permissions[2] access_group, group_name
        implied = set() if len(permissions[2]) == 0 else set(sum((
            list(zip(*group["implied_groups"]))[0] # group uuids not names
            for group in permissions[2]), []))
        # member, invite, access_group
        subgroupers = [] if len(implied) == 0 else db.queryall(
            "SELECT member, via, access_group FROM user_groups LEFT JOIN "
            "limitations ON user_groups.child_group=limitations.users_group "
            "WHERE access_group IN (" + ", ".join(("?",) * len(implied)) + ")",
            list(implied))
        # python joins because of recursive queries
        childrens_invites = dict(childrens_invites)
        child_names = [(
            group.member, childrens_invites[group.child_group],
            group.access_group) for group in childrens_groups]
        match = [dict(share.implied_groups) for share in permissions[1:]]
        results = [[self.deauth_info(
            share.member, share.via, share.access_group,
            share.implied_groups[0][1]) for share in permissions[0]]]
        for group_names, user_groups in zip(match, (child_names, subgroupers)):
            results.append(self.deauth_info(
                *share, group_names[share[2]]) for share in user_groups)
        return results

    @AccessRouter.route("/remove")
    def remove(self):
        ...

    # TODO: create invitation page
    # TODO: confirm acceptence page (for implies == -1)
    # TODO: deauthorization page
    # TODO: module interface based access

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
            if self.root and self.info.owner is not None:
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
                    "user_groups(child_group, member, access_group) "
                    "VALUES (?, ?, ?)", (str(uuid.uuid4()), owner, self.uuid))
        else:
            self.uuid = access_id[0]
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

