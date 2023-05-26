const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits 
const sessionSecret = require('crypto').randomBytes(32).toString('base64url')
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const session = require('express-session')
const { localStrategy, localStrategySlow } = require('./localStrategy')
const radiusStrategy = require('./radiusStrategy')
const jwtStrategy = require('./jwtStrategy')
const oauthStrategy = require('./oauthStrategy')
const oidcStrategy = require('./oidcStrategy')

const tokenGenerator = require('./tokenGenerator')
require('./passportConfig')

const GITHUB_CLIENT_ID = '612cf222d352280edd93'
const GITHUB_CLIENT_SECRET = 'ffbfb6639f2005ffce9e1a44d6535bbfc570f325'

  ; (async () => {

    passport.use('username-password', localStrategy)

    passport.use('username-password-slow', localStrategySlow)

    passport.use('radius-local', radiusStrategy)

    passport.use('jwt', jwtStrategy(jwtSecret))

    passport.use('oauth2', oauthStrategy(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET));

    passport.use('oidc', await oidcStrategy());

    const app = express()
    const port = 3000

    app.use(logger('dev'))
    app.use(session({
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false
    }))

    app.use(express.urlencoded({ extended: true }))
    app.use(passport.initialize())
    app.use(passport.session())
    app.use(cookieParser())

    app.use(function (err, _, res, _) {
      console.error(err.stack)
      res.status(500).send('Something broke!')
    })

    app.get('/', passport.authenticate('jwt', { failureRedirect: '/login', session: false }), (_, res) => {
      res.send(fortune.fortune())
    })

    app.get('/login',
      (_, res) => {
        res.sendFile('login.html', { root: __dirname })
      }
    )

    app.get('/logout', (_, res) => {
      res.clearCookie('jwt')
      res.redirect('/login')
    })

    app.post('/login',
      passport.authenticate('username-password', { failureRedirect: '/login', session: false }), (req, res) => {
        const token = tokenGenerator(req.user.username, jwtSecret)

        res.cookie('jwt', token, { httpOnly: true, secure: true })
        res.redirect('/')
      }
    )

    app.post('/login/slow',
      passport.authenticate('username-password-slow', { failureRedirect: '/login', session: false }), (req, res) => {
        const token = tokenGenerator(req.user.username, jwtSecret)

        res.cookie('jwt', token, { httpOnly: true, secure: true })
        res.redirect('/')
      }
    )

    app.post('/auth/radius/login',
      passport.authenticate('radius-local', { failureRedirect: '/login', session: false }),
      (req, res) => {

        const token = tokenGenerator(req.user.username, jwtSecret)

        res.cookie('jwt', token, { httpOnly: true, secure: true })

        res.redirect('/')
      }
    )

    app.get('/auth/github', passport.authenticate('oauth2', { session: false, scope: ['read:user'] }));

    app.get('/auth/github/callback',
      passport.authenticate('oauth2', { failureRedirect: '/login', session: false }),
      function (req, res) {
        const token = tokenGenerator(req.user.username, jwtSecret)

        res.cookie('jwt', token, { httpOnly: true, secure: true })
        res.redirect('/')
      });

    app.get('/user', passport.authenticate('jwt', { failureRedirect: '/login', session: false }), (req, res) => {
      const user = {
        name: req.user.username,
        description: 'it is what it is'
      }
      res.json(user)
    })

    app.get('/auth/oidc', passport.authenticate('oidc', { scope: 'openid email', session: false }));

    app.get('/auth/oidc/callback',
      passport.authenticate('oidc', { failureRedirect: '/login', failureMessage: true }),
      function (req, res) {
        const token = tokenGenerator(req.user.username, jwtSecret)

        res.cookie('jwt', token, { httpOnly: true, secure: true })
        res.redirect('/')
      });

    app.listen(port, () => {
      console.log(`Example app listening at http://localhost:${port}`)
    })

  })();