CREATE TABLE secrets (
    id SERIAL PRIMARY KEY,
    name VARCHAR NOT NULL,
    content VARCHAR NOT NULL,
    url VARCHAR
)