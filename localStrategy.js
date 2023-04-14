const LocalStrategy = require('passport-local').Strategy
const fs = require('fs')
const scryptMcf = require('scrypt-mcf')

// scryptMcf.hash('walrus', { scryptParams: { logN: 20 } }).then(hash => console.log(hash))

const localStrategy = new LocalStrategy(
  {
    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
  },
  async function (username, password, done) {
    const users = fs.readFileSync('users.txt', 'utf8').split('\r\n').map(line => line.split(':'))
    const account = users.find(user => user[0] === username)
    if (!account) {
      return done(null, false) // in passport returning false as the user object means that the authentication process failed.
    }
    const passwordMatch = await scryptMcf.verify(password, account[1])
    if (passwordMatch) {
      const user = {
        username: account[0],
        description: 'the only user that deserves to contact the fortune teller'
      }
      return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
    }
    return done(null, false)  // in passport returning false as the user object means that the authentication process failed. 
  }
)

const localStrategySlow = new LocalStrategy(
  {
    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
  },
  async function (username, password, done) {
    const users = fs.readFileSync('users_slow.txt', 'utf8').split('\r\n').map(line => line.split(':'))
    const account = users.find(user => user[0] === username)
    if (!account) {
      return done(null, false) // in passport returning false as the user object means that the authentication process failed.
    }
    const passwordMatch = await scryptMcf.verify(password, account[1])
    if (passwordMatch) {
      const user = {
        username: account[0],
        description: 'the only user that deserves to contact the fortune teller'
      }
      return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
    }
    return done(null, false)  // in passport returning false as the user object means that the authentication process failed. 
  }
)


module.exports = {
  localStrategy,
  localStrategySlow
}