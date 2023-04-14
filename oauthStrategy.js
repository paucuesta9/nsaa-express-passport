const OAuth2Strategy = require('passport-oauth2').Strategy

const oauthStrategy = (GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET) => new OAuth2Strategy({
  authorizationURL: 'https://github.com/login/oauth/authorize',
  tokenURL: 'https://github.com/login/oauth/access_token',
  clientID: GITHUB_CLIENT_ID,
  clientSecret: GITHUB_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/github/callback",
  session: false
},
  async function (accessToken, refreshToken, profile, done) {
    const user = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `token ${accessToken}`
      }
    }).then(res => res.json())

    const userApp = {
      username: user.login,
      description: 'the only user that deserves to contact the fortune teller'
    }
    return done(null, userApp)

  }
)

module.exports = oauthStrategy