import flask, uuid, collections, urllib.parse, time, json, datetime

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from login import authorized
from store import RouteLobby

end_locals()

lenUUID = len(str(uuid.uuid4()))

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

# queries is either a str reprsenting a user UUID or a list of `users_group`s
def descendants(db, queries):
    results = []
    children = queries if type(queries) is not str else sum(db.queryall(
        "SELECT uuid FROM user_groups WHERE member=?", (queries,)), ())
    children = tuple(filter(None, children))
    while children:
        children = db.queryall(
            "SELECT parents_group, uuid, member, access_group " +
            "FROM user_groups WHERE parents_group IN (" +
            ", ".join(("?",) * len(children)) + ")", children, True)
        results += children
        children = tuple(filter(None, (child.uuid for child in children)))
    return results

# checks if a group descends from user, returns None if not
# otherwise, returns the child and parent group of the user_group for user
def isdescendant(db, user, parents_group):
    while parents_group:
        parent = db.queryone(
            "SELECT member, parents_group FROM user_groups WHERE uuid=?",
            (parents_group,), True)
        if parent is None:
            return None
        if parent.member == user:
            return parents_group, parent.parents_group
        parents_group = parent.parents_group

# ensures that json value matches template given
# templates with one list element can be an arbitrary length
# templates with multiple list elements must have the elements match
# dictionaries are turned into `namedtuple`s sorted alphabetically
# templates with sets are considered enums, and value must be in that set
# other than a nested set, sets can contain all the other kinds of templates
# otherwise, the type of the value must match the type given in template
def json_payload(value, template):
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

    try:
        payload = json.loads(value)
    except json.decoder.JSONDecodeError:
        flask.abort(400, description="invalid JSON")
    try:
        return ensure(payload, template)
    except Exception as e:
        # raise e
        flask.abort(400, description=e.args[0])

GroupInfo = collections.namedtuple("GroupInfo", ("bind", "db", "owner", "sep"))

access_lobby = RouteLobby()

class AccessRoot:
    def __init__(self, db, redirect):
        self.registered, self.groups = [], []
        self.redirect, self.db = redirect, db
        self.bp = flask.Blueprint(
            "modular_login_access", __name__, url_prefix="/access")
        self.bp.record(lambda setup_state: self.register(setup_state.app))
        access_lobby.register_lobby(self.bp, self)

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
        if not authorized():
            flask.abort(401)
        return flask.session["user"]

    @access_lobby.route("/accept/<invite>")
    def confirm(self, invite):
        return flask.render_template("confirm.html", invite=invite)

    @access_lobby.route("/add/<invite>")
    def accept(self, invite, db=None, implied=False):
        user = self.authorize()
        db = db or self.db().begin()
        info = db.queryone(
            "SELECT inviter, acceptance_expiration, access_limit,"
            "access_expiration, invitees, plus, depletes, dos, deauthorizes, "
            "implies, implied, redirect FROM invitations WHERE active=1 AND "
            "uuid=?", (invite,), True)
        if info is None:
            db.close()
            flask.abort(410)
        if info.implied == 1 and not implied:
            db.close()
            flask.abort(400)
        now = time.time()
        # invite hasn't expired
        if info.acceptance_expiration is not None and \
                info.acceptance_expiration < now or \
                info.access_expiration is not None and \
                info.access_expiration < now or \
                info.access_limit is not None and \
                info.access_limit < now:
            db.close()
            self.db().execute(
                "UPDATE invitations SET active=0 WHERE uuid=?", (invite,))
            flask.abort(401)
        # can't accept the same invite twice
        user_group = db.queryone(
            "SELECT parents_group, member, access_group, spots "
            "FROM user_groups WHERE uuid=?", (info.inviter,), True)
        if user_group.member == user:
            db.close()
            return f"invite working, {user_group.spots} left"
        # can't accept your own invite
        child = info.inviter
        while child is not None:
            parent = db.queryone(
                "SELECT member, parents_group FROM user_groups "
                "WHERE uuid=?", (child,), True)
            if parent is None:
                break
            if parent.member == user:
                db.close()
                flask.abort(412)
            child = parent.parents_group
        # lower depletions; invites' invitees is not None if depletes
        lower, depletes = info.inviter, info.depletes
        if depletes:
            count, parent = user_group.spots, user_groups.parent_group
            while count is not None and parent is not None:
                if count == 0:
                    # none left, don't execute depletions
                    db.close()
                    flask.abort(404)
                else:
                    db.execute(
                        "UPDATE invitations SET invitees=? WHERE uuid=?",
                        (count - 1, lower))
                lower = parent
                depletes = db.queryone(
                    "SELECT depletes FROM invitations WHERE inviter=?",
                    (parent,))[0]
                if not depletes:
                    break
                # FK implies unpackable
                count, parent = db.queryone(
                    "SELECT spots, parents_group FROM user_groups "
                    "WHERE uuid=?", (parent,))
        creating = str(uuid.uuid4())
        until = info.access_expiration
        if until is not None and until < 0:
            until = min(now + until, info.access_limit)
        db.execute(
            "INSERT INTO user_groups(uuid, parents_group, member, "
            "access_group, until, spots) VALUES (?, ?, ?, ?, ?, ?)", (
                creating, info.inviter, user, user_group.access_group, until,
                info.invitees - 1))
        dos = info.dos and (info.dos - 1)
        if info.implies is not None:
            return self.accept(info.implies, db, True)
        db.commit().close()
        return flask.redirect(info.redirect)

    @staticmethod
    # selecting columns needed to know what invites selected can create
    def group_query(db, member=None, access_groups=()):
        assert member or access_group
        member_query = ((), ()) if not member else (("member=?",), (member,))
        access_groups_query = ((), ()) if not access_groups else ((
            "user_groups.access_group IN (" +
            ", ".join(("?",) * len(access_groups)) + ")",), access_groups)
        groups = db.queryall(
            "SELECT access_group, user_groups.uuid, parents_group, member, " +
            "until, spots, depletes, dos, " +
            #"CASE WHEN deauthorizes IS NULL THEN 2 ELSE deauthorizes END AS " +
            "deauthorizes FROM user_groups " +
            "LEFT JOIN invitations ON inviter=parents_group WHERE " +
            "(invitations.active IS NULL OR invitations.active=1) AND " +
            "(until IS NULL or until>unixepoch()) AND " +
            " AND ".join(member_query[0] + access_groups_query[0]),
            member_query[1] + access_groups_query[1], True)
        return [
            group._replace(deauthorizes=2) if group.deauthorizes is None else
            group for group in groups]

    access_info = collections.namedtuple("AccessInfo", (
        "access_group", "child_group", "parents_group", "member", "until",
        "spots", "depletes", "dos", "deauthorizes", "depletion_bound",
        "implied_groups"))

    @staticmethod
    def depletion_bound(db, initial, depletes=True, count=None):
        minimum, parent = count, initial
        while parent is not None and depletes:
            depletes = db.queryone(
                "SELECT depletes FROM invitations WHERE inviter=?", (parent,))
            # FK implies unpackable
            parent, count = db.queryone(
                "SELECT parents_group, spots FROM user_groups "
                "WHERE uuid=?", (parent,))
            if count is not None:
                minimum = count if minimum is None else min(count, minimum)
        return minimum

    # returns access_info for all groups user is in
    def user_groups(self, user=None, groups=None, db=None):
        user = user or flask.session["user"]
        db, close = db or self.db().begin(), db is None
        info = self.group_query(db, user, () if groups is None else groups)
        access_names = {} if len(info) == 0 else dict(db.queryall(
            "SELECT uuid, group_name FROM access_groups WHERE uuid IN (" +
            ", ".join(("?",) * len(info)) + ")",
            [option.access_group for option in info]))
        results = []
        for option in info:
            access = [[option.access_group, access_names[option.access_group]]]
            subgroups = access
            while access:
                access = db.queryall(
                    "SELECT uuid, group_name FROM access_groups " +
                    "WHERE parent_group IN (" +
                    ", ".join(("?",) * len(access)) + ")",
                    [i[0] for i in access])
                subgroups += access
            results.append(option + (
                self.depletion_bound(
                    db, option.parents_group, option.depletes, option.spots),
                subgroups))
        if close:
            db.close()
        return [self.access_info(*option) for option in results]

    # returns all members of a given list of groups
    # shouldn't necessarily be viewable
    def group_access(self, groups, db=None):
        db, close = db or self.db().begin(), db is None
        group_names = db.queryall(
            "SELECT uuid, group_name FROM access_group WHERE uuid IN (" +
            ", ".join(("?",) * len(groups)) + ")", groups)
        if len(group_names) != len(groups):
            db.close()
            flask.abort(400)
        stack = {}
        for group in group_names:
            stack[group[0]] = access_stack(db, group, ("group_name",))
        uniq = set(sum([i[0] for i in stack.values()], []))
        info = self.group_query(db, access_groups=uniq)
        results = [self.access_info(
            *option, self.depletion_bound(
                db, option.parents_group, option.depletes, option.spots),
            stack[option.access_group]) for option in info]
        if close:
            db.close()
        return results

    @access_lobby.template_json(
        "/invite/<group>", "invite.html", methods=["GET", "POST"])
    def single_group_invite(self, group):
        return self.invite(group)

    @access_lobby.template_json("/invite", "invite.html")
    @access_lobby.route("/view/invite", methods=["POST"])
    def invite(self, group=None):
        user = self.authorize()
        if flask.request.method == "GET":
            memberships = self.user_groups(user, group and (group,))
            invitable = [
                i for i in memberships if
                (i.depletion_bound is None or i.depletion_bound > 0) and
                (i.dos is None or i.dos > 1)]
            return {"groups": invitable}
        else:
            return self.parse_invite(flask.request.form)

    creation_args = {
        "redirect": str,
        "confirm": bool,
        "invitations": [{
            "access_group": str,
            "acceptance_expiration": {None, int},
            "access_expiration": {None, int},
            "invitees": {None, int},
            "plus": {None, int},
            "inviter": str,
            "depletes": bool,
            "dos": {None, int},
            "deauthorizes": {0, 1, 2},
        }]}

    @access_lobby.route("/allow", methods=["POST"])
    def allow(self):
        return self.create(flask.request.body)

    def parse_invite(self, form):
        if not form.get("redirect"):
            flask.abort(400, description="missing redirect")
        payload = {
            "redirect": form.get("redirect"), "confirm": "confirm" in form,
            "invitations": []}
        try:
            tz = datetime.timezone(
                -datetime.timedelta(minutes=int(form.get("tz", 0))))
        except ValueError:
            flask.abort(400, description="invalid tz")
        payload["invitations"] = [
            {"access_group": i, **{
                k[:-lenUUID - 1]: form[k] for k in form.keys()
                if k.endswith(i) and k != i}}
            for i in form.keys() if len(i) == lenUUID and i[-22] == "4"]
        if len(payload["invitations"]) == 0:
            flask.abort(400, description="no invite groups")
        for group in payload["invitations"]:
            for dated in ("access_expiration", "acceptance_expiration"):
                value = group.get(dated)
                if value:
                    group[dated] = int(datetime.datetime.fromisoformat(
                        value).replace(tzinfo=tz).timestamp())
                else:
                    group[dated] = None
            relative = group.pop("access-num", None)
            if group.pop(
                    "expiration-type", "").startswith("relative") and relative:
                group["access_expiration"] = -int(float(relative) * 86400)
            group['depletes'] = 'depletes' in group
            for num in ("invitees", "plus", "dos", "deauthorizes"):
                try:
                    group[num] = None if group.get(num) in (None, '') \
                        else json.loads(group[num])
                except ValueError:
                    flask.abort(400, description=f"invalid {num}")
        return self.create(json.dumps(payload))

    def create(self, payload):
        inserting = (
            "acceptance_expiration", "access_expiration", "invitees", "plus",
            "inviter", "depletes", "dos", "deauthorizes")
        payload = json_payload(payload, self.creation_args)
        user = self.authorize()
        db = self.db().begin()
        if len(payload.invitations) == 0:
            db.close()
            flask.abort(400, description="no invites")
        if not payload.redirect:
            db.close()
            flask.abort(400, description="bad redirect")
        values, first = [], (i == 0 for i in range(len(payload.invitations)))
        initial_uuid = current_uuid = str(uuid.uuid4())
        next_uuid = None
        now = time.time()
        for invite, last in reversed(tuple(zip(payload.invitations, first))):
            # user accepted via
            # user has access to group through via (limitations.active = 1)
            stack = tuple(filter(None, access_stack(db, invite.access_group)))
            users_group = db.queryone(
                "SELECT parents_group, until, spots FROM user_groups WHERE " +
                "uuid=? AND member=? AND active=1 AND " +
                "(until IS NULL or until>unixepoch()) AND access_group IN (" +
                ", ".join(("?",) * len(stack)) + ")",
                (invite.inviter, user) + stack, True)
            if users_group is None:
                db.close()
                flask.abort(401, description="invalid source")
            if users_group.parents_group is None:
                limits = collections.namedtuple("limits", (
                    "depletes", "dos", "deauthorizes"))(False, None, 2)
            else:
                limits = db.queryone(
                    "SELECT depletes, dos, deauthorizes FROM invitations"
                    "WHERE inviter=?", (users_group.parents_group,), True)
            # acceptance expiration and access expiration are before until
            #     (negative values for access expiration are after acceptance)
            #     (limited by access_limit)
            # TODO: redundant logic in /add
            if users_group.until is not None and (
                    invite.acceptance_expiration is None or
                    invite.acceptance_expiration > users_group.until or
                    invite.access_expiration is None or
                    invite.access_expiration > users_group.until):
                db.close()
                flask.abort(400, description="unauthorized timing")
            if invite.acceptance_expiration is not None and \
                    invite.acceptance_expiration < now or \
                    invite.access_expiration is not None and \
                    0 < invite.access_expiration < now:
                db.close()
                flask.abort(400, description="invalid timing")
            if invite.acceptance_expiration is not None and \
                    invite.access_expiration is not None and \
                    0 < invite.access_expiration and \
                    invite.access_expiration < invite.acceptance_expiration:
                db.close()
                flask.abort(400, description="invalid timing")
            # invitees is less than or equal to depletion bound
            bound = self.depletion_bound(
                db, users_group.parents_group, limits.depletes,
                users_group.spots)
            if bound is not None and (
                    invite.invitees is None or invite.invitees > bound):
                db.close()
                flask.abort(400, description="too many invitees")
            # plus < spots
            if users_group.spots is not None and (
                    invite.plus is None or invite.plus >= users_group.spots):
                db.close()
                flask.abort(400, description="too many plus ones")
            # 0 < dos < limits.dos
            if limits.dos is not None if invite.dos is None else (
                    0 > invite.dos and (
                        limits.dos is None or invite.dos >= limits.dos)):
                db.close()
                flask.abort(400, description="invalid degrees of separation")
            # invite deauthorizes <= limitations.deauthorizes
            if invite.deauthorizes > limits.deauthorizes:
                db.close()
                flask.abort(401, description="can't deauthorize")
            # depletes >= limits.depletes
            if not invite.depletes and limits.depletes:
                db.close()
                flask.abort(401, description="must deplete")
            redirect = payload.redirect if last else None
            implied = (-1 if payload.confirm else 0) if next_uuid is None else 1
            current_uuid, next_uuid = str(uuid.uuid4()), current_uuid
            # TODO: seems silly to have an access limit == until if not depletes
            #       but it also seems silly to tie depletes to access_limit
            values.append(tuple(getattr(invite, i) for i in inserting) + (
                users_group.until, implied, redirect, current_uuid,
                None if last else next_uuid))
        db.executemany(
            "INSERT INTO invitations(" + ", ".join(inserting) +
            ", access_limit, implied, redirect, uuid, implies) VALUES (" +
            ", ".join(("?",) * (len(inserting) + 5)) +
            ")", values)
        db.commit().close()
        return current_uuid

    removal_args = [str]

    @access_lobby.route("/revoke", methods=["POST"])
    def revoke(self):
        user = self.authorize()
        payload = json_payload(flask.request.body, self.removal_args)
        db = self.db().begin()
        access_groups = dict(db.queryall(
            "SELECT uuid, access_group FROM user_groups WHERE uuid IN (" +
            ", ".join(("?",) * len(payload)) + ")",
            [revoking for revoking in payload]))
        for revoking in payload:
            access_group = access_groups.get(revoking)
            # also ensures privledges query is not empty
            if access_group is None:
                flask.abort(400)
            stack = filter(None, access_stack(db, access_group))
            privledges = db.queryone(
                "SELECT deauthorizes FROM invitations " +
                "RIGHT JOIN user_groups ON parents_group=inviter " +
                "WHERE user_groups.active=1 AND member=? AND "
                "(until IS NULL or until>unixepoch()) AND " +
                "access_group IN (" + ", ".join(("?",) * len(stack)) +
                ") ORDER BY deauthorizes DESC NULLS FIRST LIMIT 1",
                [user] + stack)
            if privledges is None or privledges[0] == 0:
                db.close()
                flask.abort(401)
            if privledges[0] == 1:
                # walk stack to check if user has any ancestor groups from
                # user_group with privledges to deauthorize
                # though under the current setup, there should only be one
                # instance of user along any path from root
                child, parent = isdescendant(db, user, revoking)
                while parent:
                    access = db.queryone(
                        "SELECT deauthorizes FROM invitations "
                        "WHERE inviter=?", (parent,))
                    if access is not None and access[0] == 1:
                        break
                    child, parent = isdescendant(db, user, parent)
                if not child:
                    db.close()
                    flask.abort(401)
            # no need to check privledges for deauthorizes in (2, None)
        db.executemany("UPDATE user_groups SET active=0 WHERE uuid=?", payload)
        db.execute().close()

    deauth_info = collections.namedtuple("Deauthable", (
        "member", "user_group", "invite", "access_group"))

    # returns member, user_group, access_group, group_name
    # TODO: check for active, add user auth info (name specifically)
    def deauthable(self, user, db=None):
        db = db or self.db().begin()
        groups = self.user_groups(user, db=db)
        permissions = [[], [], []]
        for group in groups:
            permissions[group.deauthorizes].append(group)
        # permissions[1] access_group, group_name (descendants all in implied)
        # member, access_group, uuid
        childrens_groups = descendants(db, [
            group.child_group for group in permissions[1]])
        # permissions[2] access_group, group_name
        implied = set() if len(permissions[2]) == 0 else set(
            i[0] for group in permissions[2] for i in group.implied_groups)
        # member, uuid, access_group
        subgroupers = [] if len(implied) == 0 else db.queryall(
            "SELECT member, uuid, access_group FROM user_groups "
            "WHERE access_group IN (" +
            ", ".join(("?",) * len(implied)) + ")", list(implied))
        # python joins because of recursive queries
        child_names = [
            (group.member, group.child_group, group.access_group)
            for group in childrens_groups]
        match = [
            [dict(share.implied_groups) for share in level]
            for level in permissions[1:]]
        results = [[self.deauth_info(
            share.member, share.child_group, share.access_group,
            share.implied_groups[0][1]) for share in permissions[0]]]
        for group_names, user_groups in zip(match, (child_names, subgroupers)):
            results.append([
                self.deauth_info(*share, names[share[2]])
                for share, names in zip(user_groups, group_names)])
        return results

    @access_lobby.template_json("/remove", "remove.html")
    def remove(self):
        user = self.authorize()
        return {"removable": self.deauthable(user)}

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

