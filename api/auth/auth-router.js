// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express');
const userModel = require('../users/users-model');
const bcrypt = require('bcryptjs');
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require('./auth-middleware');

const router = express.Router()

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/api/auth/register', checkUsernameFree(), checkPasswordLength(), async(req, res, next) => {
    const { username, password } = req.body;
    const hashPass = await bcrypt.hash(password, 14)
    const addUser = await userModel.add({ username, hashPass })
    if (addUser) {
        res.status(200).json(addUser);
    } else {
        next()
    }
})


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.post('api/auth/login', checkUsernameExists(), async(req, res, next) => {
    const { username } = req.body;
    if (username) {
        res.status(200).json({ message: `Welcome ${username}` })
    } else {
        next();
    }
})


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

router.get('/logout', (req, res, next) => {
    if (!req.session || !req.session.user) {
        res.status(200).json({ message: 'no session' })
    } else {
        req.session.destroy((err) => {
            if (err) {
                next(err)
            } else {
                res.status(200).json({ message: 'logged out' })
            }
        })
    }
})


// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router;