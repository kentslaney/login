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
	access_token TEXT,
	refresh TEXT,
	ip TEXT, -- TODO: keep history?
	authtime FLOAT,
	refresh_time FLOAT,
	FOREIGN KEY(uuid) REFERENCES auths(uuid) ON DELETE CASCADE
);
CREATE UNIQUE INDEX activities ON active(access_token);
CREATE UNIQUE INDEX persistent ON active(refresh);
CREATE TABLE revoked (
	revoked_time FLOAT,
	access_token TEXT,
	authtime FLOAT,
	refresh_time FLOAT
);
CREATE UNIQUE INDEX removed ON revoked(access_token);
CREATE TABLE ignore (
	ref INT,
	revoked_time FLOAT,
	access_token TEXT,
	refresh_time FLOAT
);

-- TODO: check rowid order to ensure no loops
CREATE TABLE access_groups (
	uuid TEXT NOT NULL,
	group_name TEXT,
	parent_group TEXT,
	PRIMARY KEY(uuid),
	FOREIGN KEY(parent_group) REFERENCES access_groups(uuid)
);
CREATE UNIQUE INDEX access_names ON access_groups(group_name);
CREATE TABLE user_groups (
	uuid TEXT NOT NULL,
	parents_group TEXT,
	member TEXT NOT NULL,
	access_group TEXT NOT NULL,
	until INT,
	spots INT,
	active BOOLEAN DEFAULT 1,
    PRIMARY KEY(uuid),
	FOREIGN KEY(member) REFERENCES auths(uuid),
	FOREIGN KEY(access_group) REFERENCES access_groups(uuid),
	FOREIGN KEY(parents_group) REFERENCES user_groups(uuid)
);
CREATE INDEX membership ON user_groups(member, access_group);
CREATE TABLE invitations (
	uuid TEXT,
	inviter TEXT, -- joins on either uuid or parents_group
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
	PRIMARY KEY(uuid),
	FOREIGN KEY(inviter) REFERENCES user_groups(uuid),
	FOREIGN KEY(implies) REFERENCES invitations(uuid),
	CHECK((implies IS NULL) <> (redirect IS NULL)),
	CHECK(deauthorizes >= 0 AND deauthorizes <= 2),
	CHECK(implied >= -1 AND implied <= 1),
	CHECK(dos >= 0)
);

