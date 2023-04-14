const jwt = require('jsonwebtoken')

const tokenGenerator = (username, jwtSecret) => {
  const jwtClaims = {
    sub: username,
    iss: 'localhost:3000',
    aud: 'localhost:3000',
    exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
    role: 'user' // just to show a private JWT field
  }

  // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
  const token = jwt.sign(jwtClaims, jwtSecret)

  return token
}

module.exports = tokenGenerator