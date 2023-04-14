const LocalStrategy = require('passport-local').Strategy
const fs = require('fs')
const Client = require('node-radius-client');
const {
  dictionaries: {
    rfc2865: {
      file,
      attributes,
    },
  },
} = require('node-radius-utils');

const radiusStrategy = new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  async function (username, password, done) {
    const client = new Client({
      host: '127.0.0.1',
      dictionaries: [
        file,
      ],
    });

    try {
      const result = await client.accessRequest({
        secret: 'testing123',
        attributes: [
          [attributes.USER_NAME, username],
          [attributes.USER_PASSWORD, password],
        ],
      })

      console.log(result)
      const user = {
        username: username,
        description: 'the only user that deserves to contact the fortune teller'
      }
      return done(null, user)
    } catch (error) {
      console.log(error)
      return done(null, false)
    }
  }
)

module.exports = radiusStrategy