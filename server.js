let fs = require('fs')

const fastify = require('fastify')({
    logger: true,
    https: {
        key: fs.readFileSync('./tls/cert.key'),
        cert: fs.readFileSync('./tls/cert.pem')
    }
})

fastify.get('/', async (request, reply) => {
  return { hello: 'world' }
})

const start = async () => {
  try {
    await fastify.listen(process.env.PORT || 8080)
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}
start()
