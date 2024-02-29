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
	token TEXT,
	ip TEXT,
	authtime FLOAT,
	FOREIGN KEY(uuid) REFERENCES auths(uuid) ON DELETE CASCADE
);
CREATE UNIQUE INDEX activities ON active(token);

CREATE TABLE access_groups (
	uuid TEXT,
	group_name TEXT,
	parent_group TEXT,
	PRIMARY KEY(uuid),
	FOREIGN KEY(parent_group) REFERENCES access_groups(uuid)
);
CREATE UNIQUE INDEX group_names ON access_groups(group_name);
CREATE TABLE user_groups (
	parent_group TEXT,
	child_group TEXT,
	member TEXT,
	access_group TEXT,
	FOREIGN KEY(member) REFERENCES auths(uuid),
	FOREIGN KEY(access_group) REFERENCES access_groups(uuid)
);
CREATE UNIQUE INDEX shares ON user_groups(child_group);
CREATE UNIQUE INDEX invited ON user_groups(parent_group, member);
CREATE INDEX membership ON user_groups(member, access_group);
CREATE TABLE invitations (
	uuid TEXT,
	inviter TEXT,
	access_group TEXT,
	acceptance_expiration INT,
	access_expiration INT,
	invitees INT,
	plus INT,
	depletes TEXT,
	depth INT,
	redirect TEXT,
	PRIMARY KEY(uuid),
	FOREIGN KEY(depletes) REFERENCES invitations(uuid),
	FOREIGN KEY(inviter) REFERENCES shares,
	FOREIGN KEY(access_group) REFERENCES access_groups(uuid)
);
CREATE TABLE limitations (
	member TEXT,
	parent_group TEXT,
	active BOOLEAN DEFAULT 1,
	until INT,
	spots INT,
	depletes TEXT,
	depth INT,
	FOREIGN KEY(parent_group, member) REFERENCES invited,
	FOREIGN KEY(depletes) REFERENCES invitations(uuid)
);
