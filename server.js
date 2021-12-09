require('dotenv').config()
const fs = require('fs')
const { Pool } = require('pg')
const path = require('path')
const commonPasswordsMap = FillCommonPasswordsMap()

function FillCommonPasswordsMap()
{
  const result = new Map()

  const commonPass = fs.readFileSync(process.env.COMMON_PASSWORDS, "utf8")
  const commonPassArr = commonPass.split('\n')
  commonPassArr.forEach(pass => {
    result.set(pass, 1)    
  });

  return result;
}

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
      'Content-Type,Access-Control-Allow-Headers,Authorization,X-Requested-With'
  })
  .register(require('fastify-formbody'))

fastify
  .get('/', async (request, reply) => {
    reply.status(200).sendFile('index.html');
  })
  .post('/login', async (request, reply) => {
    const pool = new Pool({
      connectionString: `postgresql://${process.env.PG_USER}:${process.env.PG_PASS}@${process.env.PG_HOST}:${process.env.PG_PORT}/${process.env.PG_DB}`,
      ssl: false
    })

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
        .query(`select * from crypto_lab_5 where username='${username}';`)
        .then(res => {
          if (res.rows.length == 0)
            reply.status(403).send({ status: `failed to log in user ${username}: not found` })

          const hashed_password = decrypt_after_extracting_nonce(
            sodium,
            res.rows[0].password,
            sodium.from_hex(process.env.SECRET_KEY)
          )
          
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
    const pool = new Pool({
      connectionString: `postgresql://${process.env.PG_USER}:${process.env.PG_PASS}@${process.env.PG_HOST}:${process.env.PG_PORT}/${process.env.PG_DB}`,
      ssl: false
    })

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
      else if (commonPasswordsMap.has(password)) {
        reply.status(400).send({ status: 'password is too simple, add some complexity to it' })
        return;
      }

      const ciphered_password = encrypt_and_prepend_nonce(
        sodium,
        sodium.crypto_pwhash_str(password, sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE),
        sodium.from_hex(process.env.SECRET_KEY)
      )

      pool
        .query(`insert into crypto_lab_5 values (\'${username}\',\'${ciphered_password}\');`)
        .then(res => {
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

function encrypt_and_prepend_nonce(sodium, message, key) {
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
  const cipher = sodium.crypto_secretbox_easy(message, nonce, key)
  return sodium.to_base64(new Uint8Array([...nonce, ...cipher]))
}

function decrypt_after_extracting_nonce(sodium, nonce_and_ciphertext_base64, key) {
  const nonce_and_ciphertext = sodium.from_base64(nonce_and_ciphertext_base64)

  if (nonce_and_ciphertext.length < sodium.crypto_secretbox_NONCEBYTES + sodium.crypto_secretbox_MACBYTES) {
    throw "Short message"
  }

  const nonce = nonce_and_ciphertext.slice(0, sodium.crypto_secretbox_NONCEBYTES)
  const ciphertext = nonce_and_ciphertext.slice(sodium.crypto_secretbox_NONCEBYTES)

  return sodium.to_string(sodium.crypto_secretbox_open_easy(ciphertext, nonce, key))
}