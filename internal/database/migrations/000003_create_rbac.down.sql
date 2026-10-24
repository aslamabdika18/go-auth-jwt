ALTER TABLE users
DROP CONSTRAINT IF EXISTS fk_users_role;

DROP INDEX IF EXISTS uq_users_one_superadmin;

DROP INDEX IF EXISTS idx_users_role_id;

ALTER TABLE users
DROP COLUMN IF EXISTS is_superadmin;

ALTER TABLE users
DROP COLUMN IF EXISTS role_id;

DROP TABLE IF EXISTS role_permissions;

DROP TABLE IF EXISTS permissions;

DROP TABLE IF EXISTS roles;