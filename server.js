require('dotenv').config()
const fs = require('fs')
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

fastify
  .register(require('fastify-static'), {
    root: path.join(__dirname),
    default: '/'
  })
  .register(require('fastify-cors'), {
    origin: '*',
    methods: 'GET,POST',
    allowedHeaders:
      'Content-Type,Access-Control-Allow-Headers,Authorization,X-Requested-With,application/x-www-form-urlencoded'
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

      const hashed_password = sodium.crypto_pwhash_str(password, sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)
      
      const passwords_match = sodium.crypto_pwhash_str_verify(hashed_password, password)
      if (passwords_match)
        reply.status(200).send({ status: 'successfully logged in' })
      else
        reply.status(403).send({ status: 'log in failed: incorrect password' })
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

      reply.status(200).send({ status: 'successfully registered' })
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