// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require('express').Router();
const bcrypt = require('bcryptjs');
const db = require('../../data/db-config');
const users = require('../users/users-model');
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require('../auth/auth-middleware');


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
router.post('/register', checkUsernameFree, checkPasswordLength, (req, res, next) => {
  const user = req.body;
  const hash = bcrypt.hashSync(user.password, 12)
  user.password = hash;

  users.add(user)
    .then(newUser => {
      req.user = newUser;
      res.status(201).json({
        user_id: newUser.user_id,
        username: newUser.username
      });
    })
    .catch(next);
});

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
router.post('/login', checkUsernameExists, (req, res, next) => {
  if(bcrypt.compareSync(req.body.password, req.user.password) == true) {
    req.session.user = req.user;
    res.json({ message: `Welcome ${req.body.username}` });
  } else {
    next({ status: 401, message: 'Invalid credentials'});
  }
});

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
  console.log(req.session.user);
  if (req.session.user) {
    req.session.destroy(err => {
      if (err != null) {
          next({ message: 'error while logging out' });
      } else {
          res.status(200).json({ message: 'logged out' });
      }
    });
  } else {
    res.status(200).json({ message: 'no session' });
  }
});
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
