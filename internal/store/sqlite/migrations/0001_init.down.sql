-- Rollback for 0001. Destroys all profile and credential data; run by hand only.
DROP TABLE IF EXISTS user_credentials;
DROP TABLE IF EXISTS user_profiles;
