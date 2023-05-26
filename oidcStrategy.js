const OpenIDConnectStrategy = require('openid-client').Strategy
const Issuer = require('openid-client').Issuer

const OIDC_CLIENT_ID = '324648735522-88q778jv388ogeg85q4a8ho1ai4hp3tf.apps.googleusercontent.com'
const OIDC_CLIENT_SECRET = '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'
const OIDC_PROVIDER = 'https://accounts.google.com'
const OIDC_CALLBACK_URL = 'http://localhost:3000/auth/oidc/callback'

const main = async () => {
  const oidcIssuer = await Issuer.discover(OIDC_PROVIDER)

  const oidcClient = new oidcIssuer.Client({
    client_id: OIDC_CLIENT_ID,
    client_secret: OIDC_CLIENT_SECRET,
    redirect_uris: [OIDC_CALLBACK_URL],
    response_types: ['code'] // code is use for Authorization Code Grant; token for Implicit Grant
  })

  const oidcStrategy = new OpenIDConnectStrategy({
    client: oidcClient,
    usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
  }, (tokenSet, userInfo, done) => {
    console.log(tokenSet, userInfo)
    if (tokenSet === undefined || userInfo === undefined) {
      return done('no tokenSet or userInfo')
    }
    return done(null, userInfo)
  })

  return oidcStrategy
}

module.exports = main