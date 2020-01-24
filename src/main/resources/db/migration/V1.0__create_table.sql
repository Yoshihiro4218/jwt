CREATE TABLE IF NOT EXISTS user
(
    id         int(11) auto_increment,
    name       VARCHAR(128) NOT NULL,
    password   VARCHAR(256) NOT NULL,
    email      VARCHAR(256) NOT NULL,
    admin_flag BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at      DATETIME      NOT NULL,
    updated_at      DATETIME      NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY (name),
    UNIQUE KEY (email)
);