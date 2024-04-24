CREATE TABLE auths (
    method TEXT,
    platform_id TEXT,
    display_name TEXT,
    picture TEXT,
    token TEXT,
    uuid TEXT
);
CREATE UNIQUE INDEX platform ON auths(method, platform_id);
CREATE UNIQUE INDEX authid ON auths(uuid);
CREATE TABLE active (
    uuid TEXT,
    refresh TEXT,
    ip TEXT, -- TODO: keep history?
    authtime FLOAT,
    refresh_time FLOAT,
    FOREIGN KEY(uuid) REFERENCES auths(uuid) ON DELETE CASCADE
);
CREATE UNIQUE INDEX persistent ON active(refresh);
CREATE TABLE revoked (
    revoked_time FLOAT,
    refresh TEXT,
    authtime FLOAT,
    refresh_time FLOAT
);
CREATE UNIQUE INDEX removed ON revoked(refresh);
CREATE TABLE ignore (
    ref INT,
    revoked_time FLOAT,
    refresh TEXT,
    refresh_time FLOAT
);

-- TODO: check rowid order to ensure no loops
CREATE TABLE access_groups (
    access_id TEXT NOT NULL,
    group_name TEXT,
    parent_group TEXT,
    PRIMARY KEY(access_id),
    FOREIGN KEY(parent_group) REFERENCES access_groups(access_id)
);
CREATE UNIQUE INDEX access_names ON access_groups(group_name);
CREATE TABLE user_groups (
    guild TEXT NOT NULL,
    via TEXT,
    member TEXT NOT NULL,
    access_group TEXT NOT NULL,
    until INT,
    spots INT,
    active BOOLEAN DEFAULT 1,
    PRIMARY KEY(guild),
    FOREIGN KEY(member) REFERENCES auths(uuid),
    FOREIGN KEY(access_group) REFERENCES access_groups(access_id),
    FOREIGN KEY(via) REFERENCES invitations(invite)
);
CREATE INDEX membership ON user_groups(member, access_group);
CREATE TABLE invitations (
    invite TEXT,
    accessing TEXT NOT NULL,
    inviter TEXT,
    acceptance_expiration INT,
    access_expiration INT,
    access_limit INT,
    invitees INT DEFAULT 0,
    plus INT,
    depletes BOOL,
    dos INT, /* degrees of separation */
    deauthorizes INT NOT NULL DEFAULT 0, /* 0, 1, 2 */
    implies TEXT,
    implied INT DEFAULT 0, /* -1, 0, 1 */
    redirect TEXT,
    active BOOLEAN DEFAULT 1,
    PRIMARY KEY(invite),
    FOREIGN KEY(accessing) REFERENCES access_groups(access_id),
    FOREIGN KEY(inviter) REFERENCES user_groups(guild),
    FOREIGN KEY(implies) REFERENCES invitations(invite),
    CHECK((implies IS NULL) <> (redirect IS NULL)),
    CHECK(deauthorizes >= 0 AND deauthorizes <= 2),
    CHECK(implied >= -1 AND implied <= 1),
    CHECK(dos >= 0)
);

