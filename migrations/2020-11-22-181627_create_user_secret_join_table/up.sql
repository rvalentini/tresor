CREATE TABLE user_secret (
    user_id VARCHAR NOT NULL,
    secret_id INTEGER NOT NULL,
    secret_id_client_side VARCHAR NOT NULL, --TODO change name to secret_client_side_id to have consistent naming with secrets table
    PRIMARY KEY (user_id, secret_id),
    constraint fk_secret_id
        foreign key (secret_id)
        REFERENCES secrets (id)
        ON DELETE CASCADE
);
CREATE INDEX user_id_idx ON user_secret (user_id);
CREATE INDEX secret_id_idx ON user_secret (secret_id);
CREATE INDEX secret_id_client_side_idx ON user_secret (secret_id_client_side);
