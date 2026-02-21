CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);

CREATE TABLE sessions (
    sid BYTEA PRIMARY KEY,
    csrf_secret BYTEA NOT NULL,
    uid BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at BIGINT NOT NULL,
    last_seen BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX sessions_uid_idx ON sessions(uid);
CREATE INDEX sessions_expires_at_idx ON sessions(expires_at);

CREATE TABLE oauth_identities (
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (provider, provider_user_id)
);

CREATE INDEX oauth_identities_user_id_idx ON oauth_identities(user_id);
