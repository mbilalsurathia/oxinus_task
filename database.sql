CREATE DATABASE Account;
CREATE USER oxinus WITH ENCRYPTED PASSWORD '12345';
ALTER ROLE oxinus SET client_encoding TO 'utf8';
ALTER ROLE oxinus SET default_transaction_isolation TO 'read committed';
ALTER ROLE oxinus SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE Account TO oxinus;
