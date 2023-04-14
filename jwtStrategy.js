const JwtStrategy = require('passport-jwt').Strategy

const jwtStrategy = (jwtSecret) => new JwtStrategy(
  {
    jwtFromRequest: function (req) {
      let token = null;
      if (req && req.cookies) {
        token = req.cookies['jwt'];
      }
      return token;
    },
    secretOrKey: jwtSecret,
    session: false
  },
  function (jwtPayload, done) {
    const user = {
      username: jwtPayload.sub,
      description: 'the only user that deserves to contact the fortune teller'
    }
    return done(null, user)
  }
)

module.exports = jwtStrategy