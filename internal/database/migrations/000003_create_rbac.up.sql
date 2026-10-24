CREATE TABLE roles (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    is_superadmin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE permissions (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,

    PRIMARY KEY (role_id, permission_id),

    CONSTRAINT fk_role_permissions_role
        FOREIGN KEY (role_id)
        REFERENCES roles(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_role_permissions_permission
        FOREIGN KEY (permission_id)
        REFERENCES permissions(id)
        ON DELETE RESTRICT
);

CREATE INDEX idx_role_permissions_permission_id
ON role_permissions(permission_id);

ALTER TABLE users
ADD COLUMN role_id INTEGER;

ALTER TABLE users
ADD COLUMN is_superadmin BOOLEAN NOT NULL DEFAULT FALSE;

INSERT INTO roles (
    name,
    description,
    is_superadmin
)
VALUES
    (
        'user',
        'Default user role',
        FALSE
    ),
    (
        'superadmin',
        'System superadmin role',
        TRUE
    );

UPDATE users
SET role_id = (
    SELECT id
    FROM roles
    WHERE name = 'user'
);

ALTER TABLE users
ALTER COLUMN role_id SET NOT NULL;

ALTER TABLE users
ADD CONSTRAINT fk_users_role
    FOREIGN KEY (role_id)
    REFERENCES roles(id)
    ON DELETE RESTRICT;

CREATE INDEX idx_users_role_id
ON users(role_id);

CREATE UNIQUE INDEX uq_users_one_superadmin
ON users(is_superadmin)
WHERE is_superadmin = TRUE;