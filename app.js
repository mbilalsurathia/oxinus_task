const express = require('express');
const bodyParser = require('body-parser');
const pool = require('./db');
const validator = require('email-validator');
const app = express();
const port = 3000;
const crypto = require('crypto');
const admin = require('firebase-admin')
const credentials = require('./serviceAccountKey.json');
const { use } = require('passport');
const pgp = require('pg-promise')();
const db = pgp('postgres://oxinus:12345@localhost:5432/account');
// encryption key
const key = 'mysecretkey';
// encryption algorithm
const algorithm = 'aes-256-cbc';
// create a cipher object
const cipher = crypto.createCipher(algorithm, key);


admin.initializeApp({
  credential: admin.credential.cert(credentials)
})


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));



creatingDataBase()
creatingTable()
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});


// Your CRUD routes go here
// Create a new account
app.post('/accounts', async (req, res) => {
  const { firstName, email, lastName, phone, password, birthday, role } = req.body;
  const isValid = validator.validate(email);

  if (!isValid) {
    return res.status(400).json({ error: 'Email is not valid' });
  }
  const emailCheck = await pool.query('SELECT * FROM accounts WHERE email = $1', [email]);
  if (emailCheck.rowCount > 0) {
    return res.status(400).json({ error: 'Email already exists' });
  }
  const phoneCheck = await pool.query('SELECT * FROM accounts WHERE phone = $1', [email]);
  if (phoneCheck.rowCount > 0) {
    return res.status(400).json({ error: 'Phone already exists' });
  }
  // encrypt the plain text
  let encryptedpassword = cipher.update(password, 'utf8', 'hex');
  encryptedpassword += cipher.final('hex');
  let result = await pool.query('INSERT INTO accounts (first_name, email,last_name,phone,password,birthday) VALUES ($1, $2,$3,$4,$5,$6) RETURNING *', [firstName, email, lastName, phone, encryptedpassword, birthday]);

  const { uid } = await admin.auth().createUser({ firstName, encryptedpassword, email })
  await admin.auth().setCustomUserClaims(uid, { role })

  res.json(result.rows[0]);
});

// Get all accounts
// using authentication and authorization --> because only admin role can access the list of accounts
app.get('/accounts', isAuthenticated, isAuthorized, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    // Get the total count of accounts
    const totalCountQuery = 'SELECT COUNT(*) FROM accounts';
    const totalCountResult = await pool.query(totalCountQuery);
    const totalCount = parseInt(totalCountResult.rows[0].count);

    // Get paginated accounts
    const accountsQuery = 'SELECT * FROM accounts ORDER BY id LIMIT $1 OFFSET $2';
    const accountsResult = await pool.query(accountsQuery, [limit, offset]);
    const accounts = accountsResult.rows;

    const results = {
      totalCount,
      page,
      limit,
      accounts,
    };

    // Calculate next and previous page links
    if (offset + limit < totalCount) {
      results.next = {
        page: page + 1,
        limit,
      };
    }
    if (offset > 0) {
      results.previous = {
        page: page - 1,
        limit,
      };
    }
    //returning result
    res.json(results);
  } catch (error) {
    return res.status(403).json({ error: 'Forbidden.' });
  }
});

// Get a specific account by ID
app.get('/accounts/:id', isAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM accounts WHERE id = $1', [id]);
    if (result.rowCount == 0) {
      return res.status(404).json({ error: 'Account Not found' });
    }

    let verified = await verifyUser(result.rows[0].email, req)
    if (!verified) {
      return res.status(401).json({ error: 'Unauthorized.' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    return res.status(403).json({ error: 'Forbidden.' });
  }
});

// Update a account by ID
app.put('/accounts/:id', isAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    const { firstName, lastName, birthday } = req.body;
    const result = await pool.query('UPDATE accounts SET first_name = $1, last_name =$2,birthday =$3,last_modified =$4 WHERE id = $5 RETURNING *', [firstName, lastName, birthday, new Date(), id]);

    let verified = await verifyUser(result.rows[0].email, req)
    if (!verified) {
      return res.status(401).json({ error: 'Unauthorized.' });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    return res.status(403).json({ error: 'Forbidden.' });
  }

});

// Delete a account by ID
app.delete('/accounts/:id', isAuthenticated, isAuthorized, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM accounts WHERE id = $1 RETURNING *', [id]);
    res.json(result.rows[0]);
  } catch (error) {
    return res.status(403).json({ error: 'Forbidden.' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    // create a cipher object
    const cipher = crypto.createCipher(algorithm, key);

    // encrypt the plain text
    let encryptedpassword = cipher.update(password, 'utf8', 'hex');
    encryptedpassword += cipher.final('hex');
    const result = await pool.query('SELECT * FROM accounts WHERE email = $1 and password = $2', [email, encryptedpassword]);
    const user = await admin.auth().getUserByEmail(email);
    return res.json({ "access_token": user.uid });
  } catch (error) {
    return res.status(401).json({ error: 'Email not found' });
  }
});

//authorisation by role
async function isAuthorized(req, res, next) {
  const { role } = res.locals
  if (role == 'admin')
    return next();
  return res.status(403).send({ message: "Unauthorized role is not admin" });
}
// authenticate the token by user id 
async function isAuthenticated(req, res, next) {
  const { authorization } = req.headers

  if (!authorization)
    return res.status(401).send({ message: 'Unauthorized' });
  if (!authorization.startsWith('Bearer'))
    return res.status(401).send({ message: 'Unauthorized' });
  const split = authorization.split('Bearer ')
  if (split.length !== 2)
    return res.status(401).send({ message: 'Unauthorized' });

  const uId = split[1]
  try {
    const user = await admin.auth().getUser(uId);
    res.locals = { ...res.locals, uid: user.uid, role: user.customClaims.role, email: user.email }
    return next();
  }
  catch (err) {
    console.error(`${err.code} -  ${err.message}`)
    return res.status(401).send({ message: 'Unauthorized' });
  }
}

async function verifyUser(email, req) {
  const { authorization } = req.headers
  if (!authorization)
    return res.status(401).send({ message: 'Unauthorized' });
  if (!authorization.startsWith('Bearer'))
    return res.status(401).send({ message: 'Unauthorized' });
  const split = authorization.split('Bearer ')
  if (split.length !== 2)
    return res.status(401).send({ message: 'Unauthorized' });

  const uId = split[1]

  const user = await admin.auth().getUserByEmail(email);
  if (user.uid == uId) {
    return true
  }
  return false
}

function creatingDataBase() {
  try {
    // Specify the name of the database you want to create
    const newDatabaseName = 'account';

    // Define the SQL script to create the new database
    const createDatabaseScript = `
    CREATE DATABASE ${newDatabaseName};
    `;

    // Execute the SQL script to create the new database
    db.none(createDatabaseScript)
      .then(() => {
        console.log(`Database '${newDatabaseName}' created successfully`);
        pgp.end(); // Close the database connection
      })
      .catch(error => {
        console.log("Database already created")
        pgp.end(); // Close the database connection in case of an error
      });
  } catch (error) {
    console.log("Database already created")
  }
}

function creatingTable() {

  // Define the SQL script to create the 'accounts' table
  const createTableScript = `
  CREATE TABLE IF NOT EXISTS accounts (
  id serial PRIMARY KEY,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  phone VARCHAR(16) UNIQUE NOT NULL,
  password VARCHAR(50) NOT NULL,
  birthday date NOT NULL,
  created_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`;

  // Execute the SQL script
  db.none(createTableScript)
    .then(() => {
      console.log('Database schema created successfully');
      pgp.end(); // Close the database connection
    })
    .catch(error => {
      console.error('Error creating database schema:', error);
      pgp.end(); // Close the database connection in case of an error
    });

}
