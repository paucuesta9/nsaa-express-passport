const OpenIDStrategy = require('passport-auth0-openidconnect').Strategy

const oidcStrategy = new OpenIDStrategy({
  domain: 'dev-iemdct2flusap3ii.us.auth0.com',
  clientID: 'R08q72ozSAXEl7fPYi5xOjlM7gwZ73Ro',
  clientSecret: '3qUPAI4l2Kh0wqkxAhT-6Puztq8lY0BxMnUYM6D-7uOeZaEkH0MuG2EeKJYsEj2W',
  callbackURL: "http://localhost:3000/auth/oidc/callback",
},
  function (issuer, audience, profile, cb) {
    //not interested in passport profile normalization, 
    //just the Auth0's original profile that is inside the _json field
    const user = {
      username: 'walrus',
      description: 'the only user that deserves to contact the fortune teller'
    }
    return cb(null, user)

  }
)

module.exports = oidcStrategy