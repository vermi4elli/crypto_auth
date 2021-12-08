const fs = require('fs')
const path = require('path')
const fastifyCors = require('fastify-cors')

const fastify = require('fastify')({
    logger: true,
    // https: {
    //     key: fs.readFileSync('./tls/cert.key'),
    //     cert: fs.readFileSync('./tls/cert.pem')
    // }
})

fastify.register(require('fastify-static'), {
  root: path.join(__dirname),
  default: '/'
}).register(fastifyCors, {
  origin: '*',
  methods: 'GET,POST,PUT,DELETE,OPTIONS',
  allowedHeaders:
    'Content-Type,Access-Control-Allow-Headers,Authorization,X-Requested-With,application/x-www-form-urlencoded'
}).get('/', async (request, reply) => {
  reply.status(200).sendFile('index.html');
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
