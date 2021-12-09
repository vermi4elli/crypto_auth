require('dotenv').config()
const fs = require('fs')
const { Pool } = require('pg')
const path = require('path');

const fastify = require('fastify')({
  logger: true,
  http2: true,
  https: {
    key: fs.readFileSync(process.env.KEY),
    cert: fs.readFileSync(process.env.CERT),
    ca: [fs.readFileSync(process.env.CA)]
  }
})

const pool = new Pool({
  connectionString: `postgresql://${process.env.PG_USER}:${process.env.PG_PASS}@${process.env.PG_HOST}:${process.env.PG_PORT}/${process.env.PG_DB}`,
  ssl: false
})

fastify
  .register(require('fastify-static'), {
    root: path.join(__dirname),
    default: '/'
  })
  .register(require('fastify-cors'), {
    origin: '*',
    methods: 'GET,POST',
    allowedHeaders:
      'Content-Type,Access-Control-Allow-Headers,Authorization,X-Requested-With'
  })
  .register(require('fastify-formbody'))

fastify
  .get('/', async (request, reply) => {
    reply.status(200).sendFile('index.html');
  })
  .post('/login', async (request, reply) => {
    const _sodium = require('libsodium-wrappers');
    (async () => {
      await _sodium.ready;
      const sodium = _sodium;

      const username = request.body.username
      const password = request.body.password

      if (password.length > 60) {
        reply.status(400).send({ status: 'password is too long, 60 chars max' })
        return;
      }

      pool
        .query(`select * from crypto_lab_5 where username=${username};`)
        .then(res => {
          console.log(res)

          if (res.rows.length == 0)
            reply.status(403).send({ status: `failed to log in user ${username}: not found` })

          const hashed_password = res.rows[0].password
          const passwords_match = sodium.crypto_pwhash_str_verify(hashed_password, password)
          if (passwords_match)
            reply.status(200).send({ status: `successfully logged in user ${username}` })
          else
            reply.status(403).send({ status: 'log in failed: incorrect password' })
        })
        .catch(err => {
          console.log(err)
          reply.status(403).send({ status: `failed to log in user ${username}` })
        })
        .finally(
          pool.end()
        )
    })();
  })
  .post('/register', async (request, reply) => {
    const _sodium = require('libsodium-wrappers');
    (async () => {
      await _sodium.ready;
      const sodium = _sodium;

      const username = request.body.username
      const password = request.body.password

      if (password.length > 60) {
        reply.status(400).send({ status: 'password is too long, 60 chars max' })
        return;
      }

      const hashed_password = sodium.crypto_pwhash_str(password, sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)

      pool
        .query(`insert into crypto_lab_5 values (\'${username}\',\'${hashed_password}\');`)
        .then(res => {
          console.log(res)
          reply.status(200).send({ status: `successfully registered user ${username}` })
        })
        .catch(err => {
          console.log(err)
          reply.status(401).send({ status: `failed to register user ${username}` })
        })
        .finally(
          pool.end()
        )
    })();
  })

const start = async () => {
  try {
    await fastify.listen(process.env.PORT || 5000)
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}
start()