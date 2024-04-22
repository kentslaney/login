import flask, uuid, collections, urllib.parse, time, json, datetime, qrcode, io

import sys, os.path; end_locals, start_locals = lambda: sys.path.pop(0), (
    lambda x: x() or x)(lambda: sys.path.insert(0, os.path.dirname(__file__)))

from login import authorized
from utils import RouteLobby, CompressedUUID, data_payload
from group import AccessGroup, GroupInfo, access_stack

end_locals()

lenUUID = len(str(uuid.uuid4()))

# queries is either a str reprsenting a user UUID or a list of `users_group`s
def descendants(db, queries, selection=None, many=True):
    if len(queries) == 0:
        return [] if many else None
    selection = selection or ["via", "guild", "member", "access_group"]
    initial, args = ("VALUES" + ",".join("(?)" * len(queries)), queries) \
            if type(queries) is not str else \
            ("SELECT guild FROM user_groups WHERE member=?", (queries,))
    # TODO: profile join vs subquery
    return db.many[many](
        "WITH RECURSIVE "
          "descendants(n) AS ("
            f"{initial} UNION ALL SELECT guild FROM "
            "user_groups RIGHT JOIN invitations ON via=invite, descendants "
            "WHERE inviter=descendants.n"
          ") "
        f"SELECT {','.join(selection)} FROM user_groups "
        "WHERE guild IN descendants", args, True)

# checks if a group descends from user, returns None if not
# otherwise, returns the child and parent group of the user_group for user
def ancestors(db, initial, selection, args=(), many=True):
    return db.many[many](
        "WITH RECURSIVE "
          "ancestors(n) AS ("
            "VALUES(?) "
            "UNION ALL "
            "SELECT inviter FROM "
            "user_groups RIGHT JOIN invitations ON via=invite, ancestors "
            "WHERE guild=ancestors.n"
          f") {selection}", (initial,) + args, True)

access_lobby = RouteLobby()

class AccessRoot:
    def __init__(self, db, redirect):
        self.registered, self.groups = [], []
        self.redirect, self.db = redirect, db
        self.bp = flask.Blueprint(
            "modular_login_access", __name__, url_prefix="/access")
        self.qual = "modular_login.modular_login_access"
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

    def bounce(self):
        if not authorized():
            return flask.redirect(flask.url_for(
                "modular_login.login", next=flask.request.url))
        return None

    def confirm(self, invite, url, **kw):
        if CompressedUUID.possible(invite):
            invite = CompressedUUID.toUUID(invite)
        implied = self.db().queryone(
            "SELECT implied FROM invitations WHERE invite=?", (invite,))
        if implied is None or implied[0] == 1:
            flask.abort(404)
        if implied[0] == 0:
            return flask.redirect(url)
        return flask.render_template(
            "confirm.html", invite=invite, url=url, **kw)

    @access_lobby.route("/accept/<invite>")
    def accept(self, invite):
        auth = self.bounce()
        if auth is not None:
            return auth
        return self.confirm(
            invite, flask.url_for(f"{self.qual}.add", invite=invite))

    @access_lobby.route("/add/<invite>")
    def add(self, invite):
        auth = self.bounce()
        if auth is not None:
            return auth
        res = self.validate(invite)
        if not isinstance(res, str):
            return res
        return flask.redirect(res)

    @access_lobby.route("/qr")
    def qr_handoff(self):
        auth = self.bounce()
        if auth is not None:
            return auth
        url = self.db().queryone(
            "SELECT redirect FROM invitations RIGHT JOIN user_groups "
            "ON via=invite WHERE redirect IS NOT NULL AND member=? "
            "ORDER BY user_groups.rowid DESC LIMIT 1", (flask.session["user"],))
        if url is None:
            flask.abort(404)
        return flask.redirect(url[0])

    @access_lobby.route("/qr/accept/<invite>")
    def qr_landing(self, invite):
        auth = self.bounce()
        if auth is not None:
            return auth
        return self.confirm(invite, qr=True, url=flask.url_for(
            f"{self.qual}.qr_add", invite=invite))

    @access_lobby.route("/qr/add/<invite>")
    def qr_add(self, invite):
        auth = self.bounce()
        if auth is not None:
            return auth
        res = self.validate(invite)
        if not isinstance(res, str):
            return res
        # TODO: add way to specify shortlink
        return flask.render_template("qr.html", url=res, handoff=flask.url_for(
            f"{self.qual}.qr_handoff", _external=True))

    @access_lobby.route("/qr/img/<invite>")
    def qr_img(self, invite):
        value = flask.url_for(
            f"{self.qual}.qr_landing", invite=invite, _external=True)
        output = io.BytesIO()
        qrcode.make(value).save(output)
        return flask.Response(output.getvalue(), mimetype='image/png')

    def preview(self, invite, info):
        short = CompressedUUID.fromUUID(invite)
        return flask.Response(flask.render_template(
            "preview.html", spots=info.invitees, url=flask.url_for(
                f"{self.qual}.accept", invite=short, _external=True),
            qr=flask.url_for(f"{self.qual}.qr_img", invite=short),
            next=flask.url_for(
                f"{self.qual}.qr_landing", invite=short, _external=True)))

    def validate(self, invite, db=None, implied=False):
        if CompressedUUID.possible(invite):
            invite = CompressedUUID.toUUID(invite)
        user = self.authorize()
        db = db or self.db().begin()
        info = db.queryone(
            "SELECT accessing, inviter, acceptance_expiration, access_limit,"
            "access_expiration, invitees, plus, depletes, dos, deauthorizes, "
            "implies, implied, redirect FROM invitations WHERE active=1 AND "
            "invite=?", (invite,), True)
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
                "UPDATE invitations SET active=0 WHERE invite=?", (invite,))
            flask.abort(401)
        # can't accept the same invite twice
        user_group = db.queryone(
            "SELECT via, member, spots FROM user_groups WHERE guild=?",
            (info.inviter,), True)
        if user_group.member == user:
            db.close()
            return self.preview(invite, info)
        # no user_group loops
        # lower depletions; invites' invitees is not None if depletes
        chain = ancestors(
            db, info.inviter, "SELECT guild, member, spots, invite, invitees, "
            "depletes FROM user_groups RIGHT JOIN invitations on inviter=guild "
            "WHERE guild IN ancestors")
        if any(i.member == user for i in chain):
            db.close()
            flask.abort(412)
        invite_update, user_update = [], []
        for i, level in enumerate(chain):
            if level.spots == 0 or level.invitees == 0:
                db.close()
                flask.abort(404)
            if level.spots is not None:
                user_update.append((level.spots - 1, level.guild))
            if level.invitees is not None:
                invite_update.append((level.invitees - 1, level.invite))
            if not level.depletes:
                break
        db.executemany(
            "UPDATE user_groups SET spots=? WHERE guild=?", user_update)
        db.executemany(
            "UPDATE invitations SET invitees=? WHERE invite=?", invite_update)
        creating = str(uuid.uuid4())
        until = info.access_expiration
        if until is not None and until < 0:
            until = min(now + until, info.access_limit)
        db.execute(
            "INSERT INTO user_groups(guild, via, member, "
            "access_group, until, spots) VALUES (?, ?, ?, ?, ?, ?)", (
                creating, invite, user, info.accessing, until,
                info.plus))
        dos = info.dos and (info.dos - 1)
        if info.implies is not None:
            return self.validate(info.implies, db, True)
        db.commit().close()
        return info.redirect

    @staticmethod
    # selecting columns needed to know what invites selected can create
    def group_query(db, member=None, access_groups=()):
        assert member or access_group
        member_query = ((), ()) if not member else (("member=?",), (member,))
        access_groups_query = ((), ()) if not access_groups else ((
            "user_groups.access_group IN (" +
            ", ".join(("?",) * len(access_groups)) + ")",), access_groups)
        return db.queryall(
            "SELECT access_group, guild, via, member, " +
            "until, spots, depletes, dos, " +
            "CASE WHEN deauthorizes IS NULL THEN 2 ELSE deauthorizes END AS " +
            "deauthorizes FROM user_groups " +
            "LEFT JOIN invitations ON invite=via WHERE " +
            "user_groups.active=1 AND " +
            "(until IS NULL or until>unixepoch()) AND " +
            " AND ".join(member_query[0] + access_groups_query[0]),
            member_query[1] + access_groups_query[1], True)

    access_info = collections.namedtuple("AccessInfo", (
        "access_group", "guild", "via", "member", "until",
        "spots", "depletes", "dos", "deauthorizes", "depletion_bound",
        "implied_groups"))

    @staticmethod
    def depletion_bound(db, initial):
        opt = lambda *a: None if all(i is None for i in a) else min(*(
            i for i in a if i is not None))
        minimum, chain = None, ancestors(
            db, initial, "SELECT spots, invitees, depletes "
            "FROM user_groups RIGHT JOIN invitations on via=invite "
            "WHERE guild IN ancestors")
        for level in chain:
            minimum = opt(minimum, level.spots)
            if level.depletes:
                minimum = opt(minimum, level.invitees)
            else:
                break
        return minimum

    # returns access_info for all groups user is in
    def user_groups(self, user=None, groups=None, db=None):
        user = user or flask.session["user"]
        db, close = db or self.db().begin(), db is None
        info = self.group_query(db, user, () if groups is None else groups)
        results = []
        for option in info:
            subgroups = db.queryall(
                "WITH RECURSIVE "
                  "subsets(n) AS ("
                    "VALUES(?) "
                    "UNION ALL "
                    "SELECT access_id FROM access_groups, subsets "
                    "WHERE parent_group=subsets.n"
                  ") "
                "SELECT access_id, group_name FROM access_groups "
                "WHERE access_id IN subsets", (option.access_group,))
            results.append(option + (
                self.depletion_bound(db, option.guild), subgroups))
        if close:
            db.close()
        return [self.access_info(*option) for option in results]

    # returns all members of a given list of groups
    # shouldn't necessarily be viewable
    def group_access(self, groups, db=None):
        db, close = db or self.db().begin(), db is None
        stack = {}
        for group in groups:
            stack[group] = access_stack(
                db, group, "SELECT uuid, group_name FROM access_groups WHERE "
                "uuid IN supersets")
        uniq = set(sum([i[0] for i in stack.values()], []))
        info = self.group_query(db, access_groups=uniq)
        results = [self.access_info(
            *option, self.depletion_bound(db, option.guild),
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
        "invitees": {None, int},
        "redirect": str,
        "confirm": bool,
        "invitations": [{
            "accessing": str,
            "acceptance_expiration": {None, int},
            "access_expiration": {None, int},
            "plus": {None, int},
            "inviter": str,
            "depletes": bool,
            "dos": {None, int},
            "deauthorizes": {0, 1, 2},
        }]}

    @access_lobby.route("/allow", methods=["POST"])
    def allow(self):
        return json.dumps(self.create(flask.request.json))

    def parse_invite(self, form):
        if not form.get("redirect"):
            flask.abort(400, description="missing redirect")
        payload = {
            "redirect": form.get("redirect"), "confirm": "confirm" in form,
            "invitees": form.get("invitees"), "invitations": []}
        try:
            tz = datetime.timezone(
                -datetime.timedelta(minutes=int(form.get("tz", 0))))
        except ValueError:
            flask.abort(400, description="invalid tz")
        if form["invitees"] is not None:
            try:
                payload["invitees"] = int(payload["invitees"])
            except ValueError:
                flask.abort(400, description="invalid invitees")
        payload["invitations"] = [
            {"accessing": i, **{
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
            for num in ("plus", "dos", "deauthorizes"):
                try:
                    group[num] = None if group.get(num) in (None, '') \
                        else json.loads(group[num])
                except ValueError:
                    flask.abort(400, description=f"invalid {num}")
        return flask.redirect(flask.url_for(
            f"{self.qual}.add",
            invite=self.create(payload)["long"]))

    def create(self, payload):
        inserting = (
            "accessing", "acceptance_expiration", "access_expiration", "plus",
            "inviter", "depletes", "dos", "deauthorizes")
        payload = data_payload(payload, self.creation_args, True)
        user = self.authorize()
        db = self.db().begin()
        if len(payload.invitations) == 0:
            db.close()
            flask.abort(400, description="no invites")
        if not payload.redirect:
            db.close()
            flask.abort(400, description="bad redirect")
        values, first = [], (i == 0 for i in range(len(payload.invitations)))
        current_uuid, next_uuid = None, None
        now = time.time()
        for invite, last in reversed(tuple(zip(payload.invitations, first))):
            # user accepted via
            # user has access to group through via (limitations.active = 1)
            users_group = access_stack(db, invite.accessing,
                "SELECT via, until, spots FROM user_groups WHERE "
                "guild=? AND member=? AND active=1 AND "
                "(until IS NULL or until>unixepoch()) AND "
                "access_group IN supersets", (invite.inviter, user), False)
            if users_group is None:
                db.close()
                flask.abort(401, description="invalid source")
            if users_group.via is None:
                limits = collections.namedtuple("limits", (
                    "depletes", "dos", "deauthorizes", "plus"))(
                        False, None, 2, None)
            else:
                limits = db.queryone(
                    "SELECT depletes, dos, deauthorizes, plus FROM invitations "
                    "WHERE invite=?", (users_group.via,), True)
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
            bound = self.depletion_bound(db, invite.inviter)
            if bound is not None and (
                    payload.invitees is None or payload.invitees > bound):
                db.close()
                flask.abort(400, description="too many invitees")
            if users_group.spots is not None and (
                    invite.plus is None or invite.plus > users_group.spots):
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
            current_uuid, next_uuid = str(uuid.uuid4()), current_uuid
            implied = (-1 if payload.confirm else 0) if last else 1
            redirect = payload.redirect if next_uuid is None else None
            # TODO: what about "try for 3 days" spreadable invites
            values.append(tuple(getattr(invite, i) for i in inserting) + (
                payload.invitees, users_group.until, implied, redirect,
                current_uuid, next_uuid))
        db.executemany(
            "INSERT INTO invitations(" + ", ".join(inserting) +
            ", invitees, access_limit, implied, redirect, invite, implies) " +
            "VALUES (" + ", ".join(("?",) * (len(inserting) + 6)) + ")", values)
        db.commit().close()
        return {
            "long": current_uuid,
            "short": CompressedUUID.fromUUID(current_uuid)}

    removal_args = [str] # user_group UUIDs

    @access_lobby.route("/revoke", methods=["POST"])
    def revoke(self):
        self.kick(flask.request.json)
        return flask.request.data

    def kick(self, payload):
        user = self.authorize()
        payload = data_payload(payload, self.removal_args, True)
        db = self.db().begin()
        access_groups = dict(db.queryall(
            "SELECT guild, access_group FROM user_groups WHERE guild IN (" +
            ", ".join(("?",) * len(payload)) + ")",
            [revoking for revoking in payload]))
        for revoking in payload:
            access_group = access_groups.get(revoking)
            # also ensures privledges query is not empty
            if access_group is None:
                flask.abort(400)
            privledges = access_stack(
                db, access_group, "SELECT MAX"
                "(CASE WHEN deauthorizes IS NULL THEN 2 ELSE deauthorizes END) "
                "AS deauthorizes FROM invitations "
                "RIGHT JOIN user_groups ON via=invite "
                "WHERE user_groups.active=1 AND member=? AND "
                "(until IS NULL or until>unixepoch()) AND "
                "access_group IN supersets", (user,), False).deauthorizes
            if privledges == 0:
                db.close()
                flask.abort(401)
            if privledges == 1:
                # walk stack to check if user has any ancestor groups from
                # user_group with privledges to deauthorize
                # though under the current setup, there should only be one
                # instance of user along any path from root
                if not ancestors(
                        db, revoking, "SELECT guild FROM "
                        "user_groups RIGHT JOIN invitations ON "
                        "via=invite WHERE deauthorizes=1 AND "
                        "member=? AND guild IN ancestors", (user,)):
                    db.close()
                    flask.abort(401)
            # no need to check privledges for deauthorizes in (2, None)
        db.executemany(
            "UPDATE user_groups SET active=0 WHERE guild=?",
            [(guild,) for guild in payload])
        db.commit().close()

    deauth_info = collections.namedtuple("Deauthable", (
        "member", "display_name", "user_group", "access_group", "group_name"))

    # returns member, user_group, access_group, group_name
    def deauthable(self, user, db=None):
        db = db or self.db().begin()
        groups = self.user_groups(user, db=db)
        permissions = [[], [], []]
        for group in groups:
            permissions[group.deauthorizes].append(group)
        # permissions[1] access_group, group_name (descendants all in implied)
        # member, access_group, uuid
        childrens_groups = descendants(db, [
            group.guild for group in permissions[1]])
        # permissions[2] access_group, group_name
        implied = set() if len(permissions[2]) == 0 else set(
            i[0] for group in permissions[2] for i in group.implied_groups)
        # member, uuid, access_group
        subgroupers = [] if len(implied) == 0 else db.queryall(
            "SELECT member, guild, access_group FROM user_groups " +
            "WHERE user_groups.active=1 AND access_group IN (" +
            ", ".join(("?",) * len(implied)) + ")", list(implied), True)
        members = set(
            share.member for share in
            subgroupers + childrens_groups + permissions[0])
        display_names = dict(db.queryall(
            "SELECT uuid, display_name FROM auths WHERE uuid IN (" +
            ", ".join(("?",) * len(members)) + ")", tuple(members)))
        # python joins because of recursive queries
        match = [
            dict(sum([share.implied_groups for share in level], []))
            for level in permissions[1:]]
        results = [[
            self.deauth_info(
                share.member, display_names[share.member], share.guild,
                share.access_group, share.implied_groups[0][1])
            for share in permissions[0]]]
        for group_names, user_group in zip(match, (
                childrens_groups, subgroupers)):
            results.append([
                self.deauth_info(
                    share.member, display_names[share.member], share.guild,
                    share.access_group, group_names[share.access_group])
                for share in user_group])
        return results

    @access_lobby.template_json("/remove", "remove.html")
    @access_lobby.route("/view/remove", methods=["POST"])
    def remove(self):
        if flask.request.method == "GET":
            user = self.authorize()
            return {"removable": self.deauthable(user)}
        else:
            removing = list(flask.request.form.keys())
            self.kick(removing)
            return json.dumps(removing)

