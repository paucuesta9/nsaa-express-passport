const { default: axios } = require('axios')
const dotenv = require('dotenv')
dotenv.config()

const oauthManualStrategy = async (req, _, next) => {
  const code = req.query.code
  if (code === undefined) {
    const err = new Error('no code provided')
    err.status = 400
    throw err
  }

  const tokenResponse = await axios.post(process.env.OAUTH2_TOKEN_URL, {
    client_id: process.env.GITHUB_MANUAL_CLIENT_ID,
    client_secret: process.env.GITHUB_MANUAL_CLIENT_SECRET,
    code
  })

  const params = new URLSearchParams(tokenResponse.data)
  const accessToken = params.get('access_token')
  const scope = params.get('scope')

  if (scope !== 'user:email') {
    const err = new Error('user did not consent to release email')
    err.status = 401 // Unauthorized
    throw err
  }

  const userDataResponse = await fetch(process.env.USER_API, {
    headers: {
      Authorization: `token ${accessToken}`
    }
  })

  const userData = await userDataResponse.json()

  const userApp = {
    username: userData.email,
    description: 'the only user that deserves to contact the fortune teller'
  }

  req.user = userApp
  next()
}

module.exports = oauthManualStrategy