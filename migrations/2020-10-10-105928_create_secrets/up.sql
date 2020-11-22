CREATE TABLE secrets (
    id SERIAL PRIMARY KEY,
    client_side_id VARCHAR UNIQUE NOT NULL,
    name VARCHAR NOT NULL,
    content VARCHAR NOT NULL,
    url VARCHAR
);
CREATE INDEX client_side_id_idx ON secrets (client_side_id);
