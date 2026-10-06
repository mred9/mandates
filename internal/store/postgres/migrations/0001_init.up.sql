-- Profiles and credentials live in separate tables so they can be governed
-- separately (different database roles and grants).
-- PII columns hold AES-GCM ciphertext; phone_bidx is an HMAC blind index.
CREATE TABLE IF NOT EXISTS user_profiles (
    id          UUID PRIMARY KEY,
    wrapped_dek BYTEA NOT NULL,
    name_ct     BYTEA NOT NULL,
    phone_ct    BYTEA NOT NULL,
    address_ct  BYTEA NOT NULL,
    phone_bidx  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL
);
-- (phone_bidx, id) serves the search query and its keyset paging in one index.
CREATE INDEX IF NOT EXISTS user_profiles_phone_bidx ON user_profiles (phone_bidx, id);

CREATE TABLE IF NOT EXISTS user_credentials (
    id                    UUID PRIMARY KEY,
    user_id               UUID NOT NULL REFERENCES user_profiles (id) ON DELETE CASCADE,
    username              TEXT NOT NULL,
    method                TEXT NOT NULL CHECK (method IN ('password', 'passkey', 'totp')),
    password_hash         TEXT,
    passkey_credential_id BYTEA,
    passkey_public_key    BYTEA,
    totp_wrapped_dek      BYTEA,
    totp_secret_ct        BYTEA,
    created_at            TIMESTAMPTZ NOT NULL,
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
