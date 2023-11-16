const { Pool } = require('pg');

const pool = new Pool({
  user: 'oxinus',
  host: '127.0.0.1',
  database: 'account',
  password: '12345',
  port: 5432,
});

module.exports = pool;
