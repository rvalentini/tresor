CREATE TABLE secrets (
    id SERIAL PRIMARY KEY,
    client_id INTEGER UNIQUE NOT NULL,
    name VARCHAR NOT NULL,
    content VARCHAR NOT NULL,
    url VARCHAR
);
CREATE INDEX client_id_idx ON secrets (client_id);