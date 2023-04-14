const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits
const fortune = require('fortune-teller')
const app = express()
const port = 3000
const JwtStrategy = require('passport-jwt').Strategy
const cookieParser = require('cookie-parser')
const scryptMcf = require('scrypt-mcf')
const hash = require('scrypt-mcf').hash
const verify = require('scrypt-mcf')
const argon2 = require('argon2')
const db = require("./database.js")
const Strategy = require('passport-auth0-openidconnect').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy
const session = require('express-session');
const { Issuer, generators } = require('openid-client');
const Client = require('node-radius-client');
const {
  dictionaries: {
    rfc2865: {
      file,
      attributes,
    },
  },
} = require('node-radius-utils');
app.use(cookieParser())

app.use(session({
  secret: 'bla bla bla',
  resave: false,
  saveUninitialized: true
}))

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});

const client = new Client({
  host: '127.0.0.1',
  dictionaries: [
    file,
  ],
});


//----bd-----
//// Server port
var HTTP_PORT = 8000
// Start server
app.listen(HTTP_PORT, () => {
  console.log("Server running on port %PORT%".replace("%PORT%", HTTP_PORT))
});


//users
app.get("/api/users", (req, res, next) => {
  var sql = "select * from user"
  var params = []
  db.all(sql, params, (err, rows) => {
    if (err) {
      res.status(400).json({ "error": err.message });
      return;
    }
    res.json({
      "message": "success",
      "data": rows
    })
  });
});



passport.use('local-radius', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  async function (username, password, done) {
    client.accessRequest({
      secret: 'testing123',
      attributes: [
        [attributes.USER_NAME, username],
        [attributes.USER_PASSWORD, password],
      ],
    }).then((result) => {

      const user = {
        username: username,
        description: 'the only user that deserves to contact the fortune teller'
      }
      return done(null, user);
    }).catch((error) => {

      return done(null, false);
    });
  }
))

app.post('/radius', passport.authenticate('local-radius', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => {
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    //res.json(token)
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 604800000
    })

    // And let us log a link to the jwt.io debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    res.redirect('/')
  }
)

passport.use('oauth0', new Strategy({
  domain: 'dev-2subf668ijulu7ai.us.auth0.com',
  clientID: 'WoUiPXVMU04yUzHShm2Zp0ZrtUONOm7u',
  clientSecret: '6-jmi6-I9jyKbIPSqZFP10WkpeOXRzKDer5ArnbOIaxB88cqummje8xW0SfOX_PK',
  callbackURL: 'http://localhost:3000/openid/callback'
},
  function (issuer, audience, profile, done) {
    console.log(profile);
    const name = profile.displayName;
    const sql = "SELECT * FROM user WHERE name = ?";
    const params = [name];
    db.get(sql, params, function (err, row) {
      if (err) {
        return done(err);
      }
      if (row) { // user already exists in the database
        const user = {
          username: row.name,
          description: 'the only user that deserves to contact the fortune teller'
        }
        return done(null, user);
      } else { // user does not exist in the database
        const sql = "INSERT INTO user ( name) VALUES (?)";
        const params = [name];
        db.run(sql, params, function (err) {
          if (err) {
            return done(err);
          }
          const user = {
            username: name,
            description: 'the only user that deserves to contact the fortune teller'
          }
          console.log(user)
          return done(null, user);
        });
      }
    });

  }));
app.get('/openid/callback',
  passport.authenticate('oauth0', { failureRedirect: '/login', session: false }),

  function (req, res) {
    console.log(req.user.username)
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('jwt', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 604800000
    })
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    res.redirect('/');
  });
app.get('/openid', passport.authenticate('oauth0', { scope: ['profile'] }));


app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login', session: false }),

  function (req, res) {
    console.log(req.user.username)
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    const token = jwt.sign(jwtClaims, jwtSecret)

    res.cookie('jwt', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 604800000
    })
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    res.redirect('/');
  });

passport.use(new GoogleStrategy({
  clientID: '224634110517-ijfc4c1m8s22c4j86e9269en17a7n2ip.apps.googleusercontent.com',
  clientSecret: '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',
  callbackURL: '/auth/google/callback'
},
  function (accessToken, refreshToken, profile, done) {

    const name = profile.displayName;
    const sql = "SELECT * FROM user WHERE name = ?";
    const params = [name];
    db.get(sql, params, function (err, row) {
      if (err) {
        return done(err);
      }
      if (row) { // user already exists in the database
        const user = {
          username: row.name,
          description: 'the only user that deserves to contact the fortune teller'
        }
        return done(null, user);
      } else { // user does not exist in the database
        const sql = "INSERT INTO user ( name) VALUES (?)";
        const params = [name];
        db.run(sql, params, function (err) {
          if (err) {
            return done(err);
          }
          const user = {
            username: name,
            description: 'the only user that deserves to contact the fortune teller'
          }
          return done(null, user);
        });
      }
    });
  }));

var cookieExtractor = function (req) {
  var token = null;
  if (req && req.cookies) {
    token = req.cookies['jwt'];
  }
  return token;
};

passport.use('jwt', new JwtStrategy({
  jwtFromRequest: cookieExtractor,
  secretOrKey: jwtSecret,
  session: false
},
  function (jwtPayload, done) {



    db.get('SELECT * FROM user WHERE name = ?', jwtPayload.sub, (err, row) => {
      if (err) {

        return done(err);
      }
      if (!row) {

        return done(null, false);
      }
      const user = {
        username: row.name,
        description: 'the only user that deserves to contact the fortune teller'
      };

      return done(null, user);
    });


  }
)
)

passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  async function (username, password, done) {
    try {

      const sql = "SELECT * FROM user WHERE name = ?"
      const params = [username]
      db.get(sql, params, async function (err, row) {
        if (err) {
          return done(err)
        }
        if (!row) {

          return done(null, false)
        }
        const hash = row.password
        const match = await argon2.verify(hash, password)
        if (!match) {
          console.log("not matched");
          return done(null, false)
        }
        console.log("matched");
        const user = {
          username: row.name,
          description: 'the only user that deserves to contact the fortune teller'
        }
        return done(null, user)
      })
    } catch (err) {
      return done(err)
    }
  }
))

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.
app.use(passport.session())
app.get('/', passport.authenticate('jwt', { failureRedirect: '/login', session: false }), (req, res) => {
  res.send(fortune.fortune())
})

app.get('/logout', (req, res) => {
  res.clearCookie('jwt')
  res.redirect('/login')
})


app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.post('/login',
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => {
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    //res.json(token)
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 604800000
    })

    // And let us log a link to the jwt.io debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    res.redirect('/')
  }
)

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
