CREATE TABLE user (
    id INT UNSIGNED AUTO_INCREMENT,
    name VARCHAR(256) NOT NULL,
    hashed_password VARCHAR(4000) NOT NULL ,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (`id`)
);
