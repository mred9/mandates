-- Profiles and credentials live in separate tables. SQLite has no roles and
-- no cross-file foreign keys, so here both share one file: SQLite is for dev
-- and tests; the access-control split is enforced in PostgreSQL/CockroachDB.
-- PII columns hold AES-GCM ciphertext; phone_bidx is an HMAC blind index.
CREATE TABLE IF NOT EXISTS user_profiles (
    id          TEXT PRIMARY KEY,
    wrapped_dek BLOB NOT NULL,
    name_ct     BLOB NOT NULL,
    phone_ct    BLOB NOT NULL,
    address_ct  BLOB NOT NULL,
    phone_bidx  BLOB NOT NULL,
    created_at  TIMESTAMP NOT NULL
);
-- (phone_bidx, id) serves the search query and its keyset paging in one index.
CREATE INDEX IF NOT EXISTS user_profiles_phone_bidx ON user_profiles (phone_bidx, id);

CREATE TABLE IF NOT EXISTS user_credentials (
    id                    TEXT PRIMARY KEY,
    user_id               TEXT NOT NULL REFERENCES user_profiles (id) ON DELETE CASCADE,
    username              TEXT NOT NULL,
    method                TEXT NOT NULL CHECK (method IN ('password', 'passkey', 'totp')),
    password_hash         TEXT,
    passkey_credential_id BLOB,
    passkey_public_key    BLOB,
    totp_wrapped_dek      BLOB,
    totp_secret_ct        BLOB,
    created_at            TIMESTAMP NOT NULL,
    -- Exactly the payload for the method, enforced below the application too.
    CHECK (
        (method = 'password' AND password_hash IS NOT NULL
            AND passkey_credential_id IS NULL AND passkey_public_key IS NULL AND totp_secret_ct IS NULL AND totp_wrapped_dek IS NULL)
     OR (method = 'passkey' AND passkey_credential_id IS NOT NULL AND passkey_public_key IS NOT NULL
            AND password_hash IS NULL AND totp_secret_ct IS NULL AND totp_wrapped_dek IS NULL)
     OR (method = 'totp' AND totp_secret_ct IS NOT NULL AND totp_wrapped_dek IS NOT NULL
            AND password_hash IS NULL AND passkey_credential_id IS NULL AND passkey_public_key IS NULL)
    )
);
-- One password per username; a user may hold several passkeys.
CREATE UNIQUE INDEX IF NOT EXISTS user_credentials_password_username ON user_credentials (username) WHERE method = 'password';
CREATE UNIQUE INDEX IF NOT EXISTS user_credentials_passkey_id ON user_credentials (passkey_credential_id) WHERE method = 'passkey';
CREATE INDEX IF NOT EXISTS user_credentials_username ON user_credentials (username, method);
CREATE INDEX IF NOT EXISTS user_credentials_user ON user_credentials (user_id);
